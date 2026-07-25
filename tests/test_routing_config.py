import importlib
import json
import multiprocessing
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


_SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "remem-memory"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS))
remem_routing = importlib.import_module("remem_routing")


def target(connection_id: str, namespace: str):
    return remem_routing.RouteTarget(connection_id, namespace)


def routing_config(
    *,
    connections=None,
    global_routes=None,
    client_routes=None,
    mcp_connections=None,
    revision=0,
):
    primary = remem_routing.Connection("primary", "Primary", "default", True)
    return remem_routing.RoutingConfig(
        schema_version=1,
        revision=revision,
        connections=tuple(connections or (primary,)),
        global_routes=remem_routing.RouteLayer(global_routes or {}),
        client_routes={
            client: remem_routing.RouteLayer(routes)
            for client, routes in (client_routes or {}).items()
        },
        mcp_connections=mcp_connections or {},
        legacy_namespace_migration_completed=False,
        migration_write_blocked=False,
        deprecations=(),
    )


def _concurrent_noop_update(data_dir: str) -> None:
    remem_routing.update_routing(lambda config: config, Path(data_dir))


class RoutingResolutionTests(unittest.TestCase):
    def test_built_in_routes_resolve_when_no_custom_route_exists(self):
        config = routing_config()

        self.assertEqual(
            (target("primary", "@readable"),),
            remem_routing.resolve_routes(
                config, behavior="recall", client="codex"
            ),
        )
        self.assertEqual(
            (target("primary", "@default"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="claude"
            ),
        )

    def test_client_route_override_beats_global_route(self):
        config = routing_config(
            global_routes={"memory": (target("primary", "global"),)},
            client_routes={"claude": {"memory": (target("primary", "claude"),)}},
        )

        self.assertEqual(
            (target("primary", "claude"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="claude"
            ),
        )
        self.assertEqual(
            (target("primary", "global"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="codex"
            ),
        )

    def test_client_off_override_beats_global_route(self):
        config = routing_config(
            global_routes={"memory": (target("primary", "default"),)},
            client_routes={"claude": {"memory": ()}},
        )

        self.assertEqual(
            (),
            remem_routing.resolve_routes(
                config, behavior="memory", client="claude"
            ),
        )

    def test_mcp_connection_is_selected_independently_of_automatic_routes(self):
        connection_id = "conn_0123456789abcdef0123456789abcdef"
        named = remem_routing.Connection(
            connection_id,
            "Read-only workspace",
            "connection:0123456789abcdef0123456789abcdef",
            True,
        )
        config = routing_config(
            connections=(
                remem_routing.Connection("primary", "Primary", "default", True),
                named,
            ),
            global_routes={"memory": (target("primary", "default"),)},
            mcp_connections={"claude": connection_id},
        )

        self.assertEqual(
            named,
            remem_routing.resolve_mcp_connection(config, client="claude"),
        )
        self.assertEqual(
            (target("primary", "default"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="claude"
            ),
        )


class RoutingValidationTests(unittest.TestCase):
    def test_store_rejects_a_label_that_matches_another_connection_id(self):
        first_id = "conn_0123456789abcdef0123456789abcdef"
        second_id = "conn_fedcba9876543210fedcba9876543210"
        config = routing_config(
            connections=(
                remem_routing.Connection(
                    "primary",
                    "Primary",
                    "default",
                    True,
                ),
                remem_routing.Connection(
                    first_id,
                    second_id,
                    "connection:0123456789abcdef0123456789abcdef",
                    False,
                ),
                remem_routing.Connection(
                    second_id,
                    "Other",
                    "connection:fedcba9876543210fedcba9876543210",
                    False,
                ),
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                remem_routing.store_routing(config, Path(directory))

    def test_parse_target_requires_one_valid_connection_and_namespace(self):
        self.assertEqual(
            target("primary", "project-a"),
            remem_routing.parse_target("primary/project-a", direction="write"),
        )
        for value in ("", "/default", "primary/", "PRIMARY/default"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    remem_routing.parse_target(value, direction="write")

    def test_parse_target_rejects_selectors_in_the_wrong_direction(self):
        with self.assertRaises(ValueError):
            remem_routing.parse_target("primary/@default", direction="read")
        with self.assertRaises(ValueError):
            remem_routing.parse_target("primary/@readable", direction="write")

    def test_parse_and_store_reject_untrimmed_namespace_intent(self):
        for namespace in (" private", "private ", " private "):
            with self.subTest(namespace=namespace, boundary="parse"):
                with self.assertRaises(ValueError):
                    remem_routing.parse_target(
                        f"primary/{namespace}",
                        direction="write",
                    )
            with self.subTest(namespace=namespace, boundary="store"):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(ValueError):
                        remem_routing.store_routing(
                            routing_config(
                                global_routes={
                                    "memory": (target("primary", namespace),)
                                }
                            ),
                            Path(directory),
                        )

    def test_health_records_reject_untrimmed_namespace_intent(self):
        for namespace in (" private", "private ", " private "):
            with self.subTest(namespace=namespace):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(ValueError):
                        remem_routing.record_route_health(
                            remem_routing.RouteHealthRecord(
                                "codex",
                                "memory",
                                "primary",
                                namespace,
                                "ok",
                                "ok",
                                "2026-07-24T12:34:56Z",
                            ),
                            Path(directory),
                        )

    def test_legacy_routing_rejects_untrimmed_namespace_intent(self):
        for namespace in (" private", "private ", " private ", "   "):
            with self.subTest(namespace=namespace, boundary="environment"):
                with self.assertRaises(ValueError):
                    remem_routing.discover_legacy_routing(
                        {"REMEM_MEMORY_PERSONAL_NAMESPACE": namespace}
                    )
            with self.subTest(namespace=namespace, boundary="staged"):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(ValueError):
                        remem_routing.stage_legacy_routing(
                            remem_routing.LegacyDiscovery(
                                1,
                                {"memory": (namespace,)},
                            ),
                            Path(directory),
                        )

    def test_store_rejects_fan_out_write_routes(self):
        config = routing_config(
            global_routes={
                "memory": (
                    target("primary", "one"),
                    target("primary", "two"),
                )
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                remem_routing.store_routing(config, Path(directory))

    def test_store_rejects_mutable_primary_connection(self):
        config = routing_config(
            connections=(
                remem_routing.Connection("primary", "Renamed", "default", True),
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                remem_routing.store_routing(config, Path(directory))


class RoutingStorageTests(unittest.TestCase):
    def test_read_only_inspection_never_creates_or_repairs_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            missing = parent / "missing"
            parent_before = parent.stat()

            with self.assertRaises(FileNotFoundError):
                remem_routing.inspect_routing(missing)

            parent_after = parent.stat()
            self.assertFalse(missing.exists())
            self.assertEqual(parent_before.st_ino, parent_after.st_ino)
            self.assertEqual(parent_before.st_mtime_ns, parent_after.st_mtime_ns)

            data_dir = parent / "existing"
            remem_routing.store_routing(routing_config(), data_dir)
            route_path = data_dir / "routes.json"
            data_dir.chmod(0o750)
            route_path.chmod(0o640)
            directory_before = data_dir.stat()
            file_before = route_path.stat()

            with self.assertRaises(ValueError):
                remem_routing.inspect_routing(data_dir)

            directory_after = data_dir.stat()
            file_after = route_path.stat()
            self.assertEqual(
                (
                    directory_before.st_ino,
                    directory_before.st_mtime_ns,
                    stat.S_IMODE(directory_before.st_mode),
                    file_before.st_ino,
                    file_before.st_mtime_ns,
                    stat.S_IMODE(file_before.st_mode),
                ),
                (
                    directory_after.st_ino,
                    directory_after.st_mtime_ns,
                    stat.S_IMODE(directory_after.st_mode),
                    file_after.st_ino,
                    file_after.st_mtime_ns,
                    stat.S_IMODE(file_after.st_mode),
                ),
            )

    def test_default_reset_is_one_revision_and_crash_atomic(self):
        connection_id = "conn_0123456789abcdef0123456789abcdef"
        named = remem_routing.Connection(
            connection_id,
            "Work",
            "connection:0123456789abcdef0123456789abcdef",
            True,
        )
        original = replace(
            routing_config(
                connections=(
                    remem_routing.Connection(
                        "primary",
                        "Primary",
                        "default",
                        True,
                    ),
                    named,
                ),
                global_routes={
                    "recall": (target("primary", "global"),),
                    "memory": (target("primary", "personal"),),
                    "sessions": (target("primary", "engineering"),),
                },
                client_routes={
                    "codex": {"recall": ()},
                    "claude": {"memory": ()},
                },
                mcp_connections={"codex": connection_id},
                revision=7,
            ),
            legacy_namespace_migration_completed=True,
            migration_write_blocked=True,
            deprecations=("REMEM_DEFAULT_NAMESPACE is deprecated",),
        )
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(original, data_dir)

            reset = remem_routing.reset_routing_to_defaults(data_dir)

            self.assertEqual(8, reset.revision)
            self.assertEqual({}, dict(reset.global_routes.routes))
            self.assertEqual({}, dict(reset.client_routes))
            self.assertFalse(reset.migration_write_blocked)
            self.assertEqual(original.connections, reset.connections)
            self.assertEqual(original.mcp_connections, reset.mcp_connections)
            self.assertTrue(reset.legacy_namespace_migration_completed)
            self.assertEqual(original.deprecations, reset.deprecations)

            remem_routing.store_routing(original, data_dir)
            with mock.patch.object(
                remem_routing,
                "_atomic_write",
                side_effect=ValueError("simulated crash"),
            ):
                with self.assertRaises(ValueError):
                    remem_routing.reset_routing_to_defaults(data_dir)

            self.assertEqual(original, remem_routing.load_routing(data_dir))

    def test_loaded_configuration_mappings_cannot_be_mutated_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(
                routing_config(
                    global_routes={"memory": (target("primary", "default"),)},
                    client_routes={"claude": {"sessions": ()}},
                    mcp_connections={"claude": "primary"},
                ),
                data_dir,
            )
            loaded = remem_routing.load_routing(data_dir)

            with self.assertRaises(TypeError):
                loaded.global_routes.routes["memory"] = ()
            with self.assertRaises(TypeError):
                loaded.client_routes["codex"] = remem_routing.RouteLayer({})
            with self.assertRaises(TypeError):
                loaded.mcp_connections["codex"] = "primary"
            self.assertEqual(0, remem_routing.load_routing(data_dir).revision)

    def test_store_writes_deterministic_private_json(self):
        config = routing_config(
            global_routes={"recall": (target("primary", "project-a"),)},
        )

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "state"
            remem_routing.store_routing(config, data_dir)
            first = (data_dir / "routes.json").read_bytes()
            remem_routing.store_routing(config, data_dir)
            second = (data_dir / "routes.json").read_bytes()

            self.assertEqual(first, second)
            self.assertEqual(config, remem_routing.load_routing(data_dir))
            self.assertEqual(0o700, stat.S_IMODE(data_dir.stat().st_mode))
            self.assertEqual(
                0o600,
                stat.S_IMODE((data_dir / "routes.json").stat().st_mode),
            )
            self.assertEqual(
                [
                    "client_routes",
                    "connections",
                    "deprecations",
                    "global_routes",
                    "legacy_namespace_migration_completed",
                    "mcp_connections",
                    "migration_write_blocked",
                    "revision",
                    "schema_version",
                ],
                list(json.loads(first).keys()),
            )

    def test_update_increments_revision_and_persists_mutated_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(routing_config(), data_dir)

            updated = remem_routing.update_routing(
                lambda config: replace(
                    config,
                    global_routes=remem_routing.RouteLayer(
                        {"sessions": (target("primary", "session-log"),)}
                    ),
                ),
                data_dir,
            )

            self.assertEqual(1, updated.revision)
            self.assertEqual(updated, remem_routing.load_routing(data_dir))

    def test_concurrent_updates_preserve_every_revision_increment(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(routing_config(), data_dir)
            workers = [
                multiprocessing.Process(
                    target=_concurrent_noop_update,
                    args=(str(data_dir),),
                )
                for _ in range(4)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
                self.assertEqual(0, worker.exitcode)

            self.assertEqual(4, remem_routing.load_routing(data_dir).revision)

    def test_load_rejects_oversized_and_partially_written_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            route_path = data_dir / "routes.json"
            route_path.write_bytes(b"{" + (b" " * 65536))
            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

            route_path.write_text('{"schema_version":', encoding="utf-8")
            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

    def test_load_rejects_duplicate_configuration_object_names(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(routing_config(), data_dir)
            encoded = (data_dir / "routes.json").read_text(encoding="utf-8")
            duplicate = '{"schema_version":1,"schema_version":1,' + encoded[1:]
            (data_dir / "routes.json").write_text(duplicate, encoding="utf-8")

            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

    def test_load_rejects_schema_mismatch_and_unknown_route_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            config = routing_config()
            remem_routing.store_routing(config, data_dir)
            route_path = data_dir / "routes.json"
            encoded = json.loads(route_path.read_text(encoding="utf-8"))
            encoded["schema_version"] = 2
            route_path.write_text(json.dumps(encoded), encoding="utf-8")
            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

            remem_routing.store_routing(config, data_dir)
            encoded = json.loads(route_path.read_text(encoding="utf-8"))
            encoded["global_routes"] = {
                "memory": [
                    {
                        "connection_id": "conn_0123456789abcdef0123456789abcdef",
                        "namespace": "default",
                    }
                ]
            }
            route_path.write_text(json.dumps(encoded), encoding="utf-8")
            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

    def test_load_refuses_a_routing_file_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "state"
            target_path = Path(directory) / "outside.json"
            target_path.write_text("{}", encoding="utf-8")
            data_dir.mkdir(mode=0o700)
            (data_dir / "routes.json").symlink_to(target_path)

            with self.assertRaises(ValueError):
                remem_routing.load_routing(data_dir)

    def test_atomic_store_never_chmods_a_path_swapped_for_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "state"
            outside = Path(directory) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            outside.chmod(0o644)
            real_replace = remem_routing.os.replace

            def replace_then_swap(source, destination):
                real_replace(source, destination)
                Path(destination).unlink()
                Path(destination).symlink_to(outside)

            with mock.patch.object(
                remem_routing.os,
                "replace",
                side_effect=replace_then_swap,
            ):
                remem_routing.store_routing(routing_config(), data_dir)

            self.assertEqual(0o644, stat.S_IMODE(outside.stat().st_mode))
            self.assertTrue((data_dir / "routes.json").is_symlink())


class RouteHealthStorageTests(unittest.TestCase):
    def test_health_storage_accepts_request_error_and_rejects_unknown_status(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            request_error = remem_routing.RouteHealthRecord(
                client="codex",
                behavior="recall",
                connection_id="primary",
                namespace="@readable",
                status="request_error",
                detail_code="request_invalid",
                observed_at="2026-07-24T12:34:56Z",
            )

            remem_routing.record_route_health(request_error, data_dir)

            self.assertEqual(
                remem_routing.load_route_health(data_dir),
                (request_error,),
            )
            with self.assertRaises(ValueError):
                remem_routing.record_route_health(
                    replace(request_error, status="requestish"),
                    data_dir,
                )

    def test_health_records_are_bounded_non_secret_and_do_not_change_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_routing.store_routing(routing_config(revision=7), data_dir)
            record = remem_routing.RouteHealthRecord(
                client="codex",
                behavior="memory",
                connection_id="primary",
                namespace="@default",
                status="auth_error",
                detail_code="auth_denied",
                observed_at="2026-07-24T12:34:56Z",
            )
            for _ in range(65):
                remem_routing.record_route_health(record, data_dir)

            records = remem_routing.load_route_health(data_dir)
            payload = (data_dir / "route-health.json").read_text(encoding="utf-8")
            self.assertEqual(64, len(records))
            self.assertLessEqual(len(payload.encode("utf-8")), 32768)
            self.assertNotIn("default\",\"configured", payload)
            self.assertEqual(7, remem_routing.load_routing(data_dir).revision)
            self.assertEqual(
                0o600,
                stat.S_IMODE((data_dir / "route-health.json").stat().st_mode),
            )

    def test_health_storage_rejects_free_form_detail_and_invalid_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            unsafe = remem_routing.RouteHealthRecord(
                client="codex",
                behavior="recall",
                connection_id="primary",
                namespace="@readable",
                status="ok",
                detail_code="contains space",
                observed_at="not-a-timestamp",
            )
            with self.assertRaises(ValueError):
                remem_routing.record_route_health(unsafe, data_dir)

    def test_health_load_rejects_duplicate_object_names(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            health_path = data_dir / "route-health.json"
            health_path.write_text(
                """[{"client":"codex","client":"claude","behavior":"recall","connection_id":"primary","namespace":"@readable","status":"ok","detail_code":"ok","observed_at":"2026-07-24T12:34:56Z"}]""",
                encoding="utf-8",
            )
            health_path.chmod(0o600)

            with self.assertRaises(ValueError):
                remem_routing.load_route_health(data_dir)


class RoutingLimitsTests(unittest.TestCase):
    def test_store_rejects_more_than_sixteen_connections(self):
        connections = [
            remem_routing.Connection("primary", "Primary", "default", True)
        ]
        for index in range(16):
            token = f"{index:032x}"
            connections.append(
                remem_routing.Connection(
                    f"conn_{token}",
                    f"Connection {index}",
                    f"connection:{token}",
                    True,
                )
            )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                remem_routing.store_routing(
                    routing_config(connections=connections), Path(directory)
                )

    def test_store_rejects_more_than_sixteen_recall_targets(self):
        config = routing_config(
            global_routes={
                "recall": tuple(
                    target("primary", f"namespace-{index}")
                    for index in range(17)
                )
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                remem_routing.store_routing(config, Path(directory))

    def test_store_rejects_out_of_range_labels_and_control_namespaces(self):
        named_id = "conn_0123456789abcdef0123456789abcdef"
        cases = (
            routing_config(
                connections=(
                    remem_routing.Connection("primary", "Primary", "default", True),
                    remem_routing.Connection(
                        named_id,
                        "",
                        "connection:0123456789abcdef0123456789abcdef",
                        True,
                    ),
                )
            ),
            routing_config(
                connections=(
                    remem_routing.Connection("primary", "Primary", "default", True),
                    remem_routing.Connection(
                        named_id,
                        "x" * 65,
                        "connection:0123456789abcdef0123456789abcdef",
                        True,
                    ),
                )
            ),
            routing_config(
                global_routes={"memory": (target("primary", "x" * 101),)}
            ),
            routing_config(
                global_routes={"memory": (target("primary", "bad\u0085name"),)}
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for config in cases:
                with self.subTest(config=config):
                    with self.assertRaises(ValueError):
                        remem_routing.store_routing(config, Path(directory))

    def test_store_rejects_unknown_clients_behaviors_and_bad_connection_pairing(self):
        named_id = "conn_0123456789abcdef0123456789abcdef"
        cases = (
            routing_config(global_routes={"unknown": ()}),
            routing_config(client_routes={"unknown": {"memory": ()}}),
            routing_config(
                connections=(
                    remem_routing.Connection("primary", "Primary", "default", True),
                    remem_routing.Connection(
                        named_id,
                        "Named",
                        "connection:ffffffffffffffffffffffffffffffff",
                        True,
                    ),
                )
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for config in cases:
                with self.subTest(config=config):
                    with self.assertRaises(ValueError):
                        remem_routing.store_routing(config, Path(directory))


class DefaultRoutesTests(unittest.TestCase):
    def test_use_default_preserves_connections_and_mcp_selection(self):
        config = routing_config(
            global_routes={"memory": (target("primary", "default"),)},
            client_routes={"claude": {"memory": ()}},
            mcp_connections={"claude": "primary"},
        )

        reset = remem_routing.use_default_routes(config)

        self.assertEqual({}, reset.global_routes.routes)
        self.assertEqual({}, reset.client_routes)
        self.assertEqual(config.connections, reset.connections)
        self.assertEqual(config.mcp_connections, reset.mcp_connections)


class LegacyNamespaceMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary_directory.name) / "routing"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_clean_initialization_records_completed_migration(self):
        config, outcome = remem_routing.initialize_routing(self.data_dir, {})

        self.assertTrue(config.legacy_namespace_migration_completed)
        self.assertFalse(config.migration_write_blocked)
        self.assertEqual({}, config.global_routes.routes)
        self.assertTrue(outcome.initialized)
        self.assertEqual(1, outcome.distinct_credentials)

    def test_personal_namespace_is_imported_as_global_memory_route(self):
        config, _ = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "personal"},
        )

        self.assertEqual(
            (target("primary", "personal"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="codex"
            ),
        )
        self.assertNotIn("sessions", config.global_routes.routes)

    def test_engineering_namespace_is_imported_as_global_sessions_route(self):
        config, _ = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_ENGINEERING_NAMESPACE": "engineering"},
        )

        self.assertEqual(
            (target("primary", "engineering"),),
            remem_routing.resolve_routes(
                config, behavior="sessions", client="claude"
            ),
        )
        self.assertNotIn("memory", config.global_routes.routes)

    def test_both_legacy_namespaces_are_independent_global_routes(self):
        config, _ = remem_routing.initialize_routing(
            self.data_dir,
            {
                "REMEM_MEMORY_PERSONAL_NAMESPACE": "personal",
                "REMEM_MEMORY_ENGINEERING_NAMESPACE": "engineering",
            },
        )

        self.assertEqual(
            (target("primary", "personal"),),
            remem_routing.resolve_routes(
                config, behavior="memory", client="codex"
            ),
        )
        self.assertEqual(
            (target("primary", "engineering"),),
            remem_routing.resolve_routes(
                config, behavior="sessions", client="codex"
            ),
        )

    def test_default_namespace_is_deprecated_without_becoming_a_route(self):
        config, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_DEFAULT_NAMESPACE": "must-not-be-imported"},
        )

        self.assertEqual({}, config.global_routes.routes)
        self.assertEqual(
            ("REMEM_DEFAULT_NAMESPACE is deprecated",),
            config.deprecations,
        )
        self.assertEqual(config.deprecations, outcome.deprecations)

    def test_legacy_environment_is_imported_only_once(self):
        first, _ = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "default"},
        )
        second, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "changed"},
        )

        self.assertEqual(
            "default",
            remem_routing.resolve_routes(
                second, behavior="memory", client="codex"
            )[0].namespace,
        )
        self.assertTrue(first.legacy_namespace_migration_completed)
        self.assertFalse(outcome.initialized)

    def test_existing_unmigrated_configuration_is_migrated_once(self):
        original = routing_config(
            global_routes={"recall": (target("primary", "shared"),)},
            client_routes={"claude": {"memory": ()}},
            mcp_connections={"claude": "primary"},
        )
        remem_routing.store_routing(original, self.data_dir)

        migrated, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {
                "REMEM_MEMORY_PERSONAL_NAMESPACE": "personal",
                "REMEM_MEMORY_ENGINEERING_NAMESPACE": "engineering",
            },
        )
        repeated, repeated_outcome = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "changed"},
        )

        self.assertTrue(migrated.legacy_namespace_migration_completed)
        self.assertFalse(outcome.initialized)
        self.assertEqual(
            (target("primary", "shared"),),
            migrated.global_routes.routes["recall"],
        )
        self.assertEqual(original.client_routes, migrated.client_routes)
        self.assertEqual(original.mcp_connections, migrated.mcp_connections)
        self.assertEqual(
            (target("primary", "personal"),),
            migrated.global_routes.routes["memory"],
        )
        self.assertEqual(
            (target("primary", "engineering"),),
            migrated.global_routes.routes["sessions"],
        )
        self.assertEqual(migrated, remem_routing.load_routing(self.data_dir))
        self.assertEqual(migrated, repeated)
        self.assertFalse(repeated_outcome.initialized)

    def test_existing_completed_configuration_is_an_immediate_no_op(self):
        completed = replace(
            routing_config(
                global_routes={"memory": (target("primary", "saved"),)}
            ),
            legacy_namespace_migration_completed=True,
        )
        remem_routing.store_routing(completed, self.data_dir)

        loaded, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "changed"},
        )

        self.assertEqual(completed, loaded)
        self.assertFalse(outcome.initialized)

    def test_use_default_does_not_allow_legacy_environment_to_reapply(self):
        original, _ = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "personal"},
        )
        remem_routing.store_routing(
            remem_routing.use_default_routes(original), self.data_dir
        )

        reloaded, _ = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "changed"},
        )

        self.assertTrue(reloaded.legacy_namespace_migration_completed)
        self.assertEqual({}, reloaded.global_routes.routes)
        self.assertEqual(
            (target("primary", "@default"),),
            remem_routing.resolve_routes(
                reloaded, behavior="memory", client="codex"
            ),
        )

    def test_ambiguous_credentials_block_automatic_writes(self):
        config, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {"REMEM_MEMORY_PERSONAL_NAMESPACE": "personal"},
            remem_routing.LegacyDiscovery(2, {}),
        )

        self.assertTrue(config.migration_write_blocked)
        self.assertTrue(outcome.credential_ambiguous)
        self.assertEqual(
            (),
            remem_routing.resolve_routes(
                config, behavior="memory", client="codex"
            ),
        )
        self.assertEqual(
            (),
            remem_routing.resolve_routes(
                config, behavior="sessions", client="codex"
            ),
        )

    def test_interrupted_installer_stage_blocks_runtime_and_later_installer(self):
        environment = {"CODEX_HOME": str(self.data_dir.parent / "codex")}
        remem_routing.stage_legacy_routing(
            remem_routing.LegacyDiscovery(
                2,
                {"memory": ("legacy-memory",)},
            ),
            self.data_dir,
        )

        runtime = remem_routing.load_or_initialize_routing(
            self.data_dir,
            environment,
            credential_loader=lambda: self.fail(
                "staged discovery must be used without reading credentials"
            ),
        )
        later, _ = remem_routing.initialize_routing(
            self.data_dir,
            environment,
            remem_routing.LegacyDiscovery(1, {}),
        )

        self.assertTrue(runtime.migration_write_blocked)
        self.assertTrue(later.migration_write_blocked)
        self.assertEqual(
            (),
            remem_routing.resolve_routes(
                later,
                behavior="memory",
                client="codex",
            ),
        )

    def test_skipped_installer_discovers_distinct_local_credentials_once(self):
        codex_home = self.data_dir.parent / "codex"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text(
            (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = "vlt_legacy-local"\n'
            ),
            encoding="utf-8",
        )
        environment = {"CODEX_HOME": str(codex_home)}

        runtime = remem_routing.load_or_initialize_routing(
            self.data_dir,
            environment,
            credential_loader=lambda: "vlt_canonical-local",
        )
        later, _ = remem_routing.initialize_routing(
            self.data_dir,
            environment,
            remem_routing.LegacyDiscovery(1, {}),
        )

        self.assertTrue(runtime.migration_write_blocked)
        self.assertTrue(later.migration_write_blocked)
        self.assertNotIn(
            "vlt_",
            (self.data_dir / "routes.json").read_text(encoding="utf-8"),
        )

    def test_runtime_without_credential_loader_never_guesses_legacy_identity(self):
        codex_home = self.data_dir.parent / "codex"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text(
            (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = "vlt_legacy-local"\n'
            ),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            remem_routing.load_or_initialize_routing(
                self.data_dir,
                {"CODEX_HOME": str(codex_home)},
            )

        self.assertFalse((self.data_dir / "routes.json").exists())
        self.assertFalse(
            (self.data_dir / "routing-migration-stage.json").exists()
        )

    def test_completed_migration_can_only_be_strengthened_by_late_discovery(self):
        completed, _ = remem_routing.initialize_routing(self.data_dir, {})

        strengthened, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(2, {}),
        )
        repeated, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(1, {}),
        )

        self.assertFalse(completed.migration_write_blocked)
        self.assertTrue(strengthened.migration_write_blocked)
        self.assertEqual(completed.revision + 1, strengthened.revision)
        self.assertTrue(repeated.migration_write_blocked)
        self.assertEqual(strengthened.revision, repeated.revision)

    def test_migration_stage_is_private_credential_free_and_idempotent(self):
        first = remem_routing.stage_legacy_routing(
            remem_routing.LegacyDiscovery(
                1,
                {"memory": ("one",)},
            ),
            self.data_dir,
        )
        merged = remem_routing.stage_legacy_routing(
            remem_routing.LegacyDiscovery(
                2,
                {"memory": ("one", "two")},
            ),
            self.data_dir,
        )
        stage = self.data_dir / "routing-migration-stage.json"
        encoded = stage.read_text(encoding="utf-8")

        self.assertEqual(first.distinct_credentials, 1)
        self.assertEqual(merged.distinct_credentials, 2)
        self.assertEqual(
            dict(merged.destination_candidates),
            {"memory": ("one", "two")},
        )
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
        self.assertEqual(
            set(json.loads(encoded)),
            {
                "schema_version",
                "distinct_credentials",
                "destination_candidates",
            },
        )
        self.assertNotIn("credential", encoded.lower().replace(
            "distinct_credentials", ""
        ))
        self.assertNotIn("fingerprint", encoded.lower())

        config = remem_routing.load_or_initialize_routing(
            self.data_dir,
            {},
            credential_loader=lambda: self.fail(
                "staged discovery must avoid credential reads"
            ),
        )
        self.assertTrue(config.migration_write_blocked)
        self.assertFalse(stage.exists())

    def test_migration_stage_rejects_oversize_duplicates_and_symlinks(self):
        stage_name = "routing-migration-stage.json"
        invalid_payloads = (
            b"x" * 4_097,
            (
                b'{"schema_version":1,"schema_version":1,'
                b'"distinct_credentials":1,"destination_candidates":{}}'
            ),
        )
        for payload in invalid_payloads:
            with self.subTest(size=len(payload)):
                self.data_dir.mkdir(parents=True, exist_ok=True)
                stage = self.data_dir / stage_name
                stage.write_bytes(payload)
                stage.chmod(0o600)
                with self.assertRaises(ValueError):
                    remem_routing.load_or_initialize_routing(
                        self.data_dir,
                        {},
                    )
                stage.unlink()

        target = self.data_dir.parent / "redirected-stage.json"
        target.write_text("preserve", encoding="utf-8")
        target.chmod(0o600)
        (self.data_dir / stage_name).symlink_to(target)
        with self.assertRaises(ValueError):
            remem_routing.stage_legacy_routing(
                remem_routing.LegacyDiscovery(2, {}),
                self.data_dir,
            )
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve")

    def test_migration_stage_update_is_crash_atomic(self):
        remem_routing.stage_legacy_routing(
            remem_routing.LegacyDiscovery(1, {}),
            self.data_dir,
        )
        stage = self.data_dir / "routing-migration-stage.json"
        before = stage.read_bytes()

        with mock.patch.object(
            remem_routing.os,
            "replace",
            side_effect=OSError("interrupted"),
        ):
            with self.assertRaises(ValueError):
                remem_routing.stage_legacy_routing(
                    remem_routing.LegacyDiscovery(2, {}),
                    self.data_dir,
                )

        self.assertEqual(stage.read_bytes(), before)
        self.assertEqual(
            [
                path.name
                for path in self.data_dir.iterdir()
                if path.name.endswith(".tmp")
            ],
            [],
        )

    def test_destination_conflicts_are_per_behavior_and_block_writes(self):
        config, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(
                1,
                {"memory": ("one", "two"), "sessions": ("sessions",)},
            ),
        )

        self.assertTrue(config.migration_write_blocked)
        self.assertTrue(outcome.destination_ambiguous)
        self.assertEqual(
            (),
            remem_routing.resolve_routes(
                config, behavior="memory", client="claude"
            ),
        )

    def test_client_only_edit_does_not_unblock_imported_ambiguous_routes(self):
        blocked, _ = remem_routing.initialize_routing(
            self.data_dir,
            {
                "REMEM_MEMORY_PERSONAL_NAMESPACE": "personal",
                "REMEM_MEMORY_ENGINEERING_NAMESPACE": "engineering",
            },
            remem_routing.LegacyDiscovery(
                2,
                {
                    "memory": ("personal",),
                    "sessions": ("engineering",),
                },
            ),
        )
        self.assertTrue(blocked.migration_write_blocked)

        updated = remem_routing.update_routing(
            lambda config: replace(
                config,
                client_routes={"codex": remem_routing.RouteLayer({"memory": ()})},
            ),
            self.data_dir,
        )
        self.assertTrue(updated.migration_write_blocked)

    def test_partial_global_edit_does_not_unblock_ambiguity(self):
        blocked, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(2, {}),
        )

        updated = remem_routing.update_routing(
            lambda config: replace(
                config,
                global_routes=remem_routing.RouteLayer(
                    {"memory": (target("primary", "memory"),)}
                ),
            ),
            self.data_dir,
        )

        self.assertTrue(blocked.migration_write_blocked)
        self.assertTrue(updated.migration_write_blocked)

    def test_generic_update_cannot_directly_clear_ambiguity_block(self):
        blocked, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(2, {}),
        )

        updated = remem_routing.update_routing(
            lambda config: replace(config, migration_write_blocked=False),
            self.data_dir,
        )

        self.assertTrue(blocked.migration_write_blocked)
        self.assertTrue(updated.migration_write_blocked)

    def test_explicit_complete_global_write_update_unblocks_ambiguity(self):
        blocked, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(2, {}),
        )

        complete = remem_routing.update_routing(
            lambda config: replace(
                config,
                global_routes=remem_routing.RouteLayer(
                    {
                        "memory": (target("primary", "memory"),),
                        "sessions": (),
                    }
                ),
            ),
            self.data_dir,
            resolve_migration_write_block=True,
        )
        self.assertTrue(blocked.migration_write_blocked)
        self.assertFalse(complete.migration_write_blocked)

    def test_use_default_unblocks_ambiguity(self):
        blocked, _ = remem_routing.initialize_routing(
            self.data_dir,
            {},
            remem_routing.LegacyDiscovery(2, {}),
        )

        reset = remem_routing.use_default_routes(blocked)
        self.assertFalse(reset.migration_write_blocked)

    def test_migration_output_and_storage_are_secret_free(self):
        secret = "vlt_migration-secret-canary"
        config, outcome = remem_routing.initialize_routing(
            self.data_dir,
            {
                "REMEM_API_KEY": secret,
                "REMEM_MEMORY_PERSONAL_NAMESPACE": "personal",
            },
        )

        persisted = (self.data_dir / "routes.json").read_text(encoding="utf-8")
        self.assertNotIn(secret, persisted)
        self.assertNotIn(secret, repr(outcome))
        self.assertNotIn(secret, repr(config))


if __name__ == "__main__":
    unittest.main()
