import importlib
import json
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


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


class RouteHealthStorageTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
