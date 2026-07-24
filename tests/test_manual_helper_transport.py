from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts import remem_checkpoint, remem_memory, remem_recall


_ROOT = Path(__file__).resolve().parents[1]
_API_PATH = (
    _ROOT
    / "plugins"
    / "remem-memory"
    / "scripts"
    / "remem_api.py"
)


def _load_api():
    spec = importlib.util.spec_from_file_location(
        "manual_helper_remem_api_tests",
        _API_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_API = _load_api()


class _Response:
    def __init__(self, payload):
        self._encoded = json.dumps(payload).encode("utf-8")

    def read(self, amount=None):
        return self._encoded[:amount]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _ForbiddenHTTPX:
    class Client:
        def __init__(self, *args, **kwargs):
            raise AssertionError("manual helpers must not use httpx")


class ManualHelperTransportTests(unittest.TestCase):
    @staticmethod
    def _routing_config():
        secondary_id = "conn_" + ("a" * 32)
        return remem_memory.remem_routing.RoutingConfig(
            schema_version=1,
            revision=7,
            connections=(
                remem_memory.remem_routing.Connection(
                    "primary",
                    "Primary",
                    "default",
                    True,
                ),
                remem_memory.remem_routing.Connection(
                    secondary_id,
                    "Secondary",
                    "connection:" + ("a" * 32),
                    True,
                ),
            ),
            global_routes=remem_memory.remem_routing.RouteLayer(
                {
                    "recall": (
                        remem_memory.remem_routing.RouteTarget(
                            "primary",
                            "default",
                        ),
                        remem_memory.remem_routing.RouteTarget(
                            secondary_id,
                            "history",
                        ),
                    ),
                    "sessions": (
                        remem_memory.remem_routing.RouteTarget(
                            "primary",
                            "@default",
                        ),
                    ),
                }
            ),
            client_routes={
                "claude": remem_memory.remem_routing.RouteLayer(
                    {"sessions": ()}
                )
            },
            mcp_connections={},
            legacy_namespace_migration_completed=True,
            migration_write_blocked=False,
            deprecations=(),
        )

    @staticmethod
    def _descriptor_pipe(payload: bytes) -> tuple[dict[str, str], int]:
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, payload)
        os.close(write_descriptor)
        return {
            "REMEM_MEMORY_ROUTE_FD": str(read_descriptor),
        }, read_descriptor

    def test_route_descriptor_is_exact_bounded_and_consumed_once(self) -> None:
        descriptor = {
            "schema_version": 1,
            "client": "claude",
            "behavior": "sessions",
            "route_revision": 7,
            "connection_id": "conn_" + ("a" * 32),
            "read_namespaces": None,
            "write_namespace": "private",
        }
        environment, read_descriptor = self._descriptor_pipe(
            json.dumps(descriptor).encode("utf-8")
        )

        parsed = remem_checkpoint._consume_route_descriptor(
            environment,
            expected_client="claude",
            expected_behavior="sessions",
        )

        self.assertEqual(parsed, descriptor)
        self.assertNotIn("REMEM_MEMORY_ROUTE_FD", environment)
        with self.assertRaises(OSError):
            os.read(read_descriptor, 1)
        with self.assertRaises(ValueError):
            remem_checkpoint._consume_route_descriptor(
                environment,
                expected_client="claude",
                expected_behavior="sessions",
            )

    def test_route_descriptor_rejects_oversized_duplicate_and_secret_fields(
        self,
    ) -> None:
        valid = {
            "schema_version": 1,
            "client": "codex",
            "behavior": "recall",
            "route_revision": 0,
            "connection_id": "primary",
            "read_namespaces": None,
            "write_namespace": None,
        }
        duplicate = (
            '{"schema_version":1,"schema_version":1,'
            '"client":"codex","behavior":"recall","route_revision":0,'
            '"connection_id":"primary","read_namespaces":null,'
            '"write_namespace":null}'
        ).encode("utf-8")
        secret_bearing = dict(valid, api_key="vlt_secret-canary")
        for raw in (
            b"{" + (b"x" * 4096) + b"}",
            duplicate,
            json.dumps(
                dict(valid, schema_version=True)
            ).encode("utf-8"),
            json.dumps(secret_bearing).encode("utf-8"),
        ):
            with self.subTest(size=len(raw)):
                environment, read_descriptor = self._descriptor_pipe(raw)
                with self.assertRaises(ValueError):
                    remem_checkpoint._consume_route_descriptor(
                        environment,
                        expected_client="codex",
                        expected_behavior="recall",
                    )
                with self.assertRaises(OSError):
                    os.read(read_descriptor, 1)

    def test_canonical_write_routing_honors_client_off_and_explicit_to(
        self,
    ) -> None:
        config = self._routing_config()
        canaries = {
            "primary": "vlt_primary-canary",
            "conn_" + ("a" * 32): "vlt_secondary-canary",
        }
        observed = []

        def run_helper(arguments, **kwargs):
            environment = kwargs["env"]
            route_fd = int(environment["REMEM_MEMORY_ROUTE_FD"])
            key_fd = int(environment["REMEM_API_KEY_FD"])
            observed.append(
                (
                    list(arguments),
                    json.loads(os.read(route_fd, 4096).decode("utf-8")),
                    os.read(key_fd, 4096).decode("utf-8"),
                    tuple(kwargs["pass_fds"]),
                )
            )
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_DATA_DIR": directory},
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory,
                    "_load_or_initialize_routing",
                    return_value=config,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        side_effect=lambda connection, **_kwargs: canaries[
                            connection.id
                        ],
                    ):
                        with mock.patch.object(
                            remem_memory.subprocess,
                            "run",
                            side_effect=run_helper,
                        ) as run:
                            stderr = io.StringIO()
                            with contextlib.redirect_stderr(stderr):
                                off_result = remem_memory.run_command(
                                    "checkpoint",
                                    [
                                        "--client",
                                        "claude",
                                        "--ingest",
                                        "--project",
                                        "remem",
                                        "--session-id",
                                        "s1",
                                    ],
                                )
                            explicit_result = remem_memory.run_command(
                                "checkpoint",
                                [
                                    "--client",
                                    "claude",
                                    "--to",
                                    "Secondary/private",
                                    "--ingest",
                                    "--project",
                                    "remem",
                                    "--session-id",
                                    "s1",
                                ],
                            )

        self.assertEqual(off_result, 1)
        self.assertEqual(
            stderr.getvalue(),
            "error: sessions route is off\n",
        )
        self.assertEqual(explicit_result, 0)
        run.assert_called_once()
        _arguments, descriptor, credential, pass_fds = observed[0]
        self.assertEqual(
            descriptor,
            {
                "schema_version": 1,
                "client": "claude",
                "behavior": "sessions",
                "route_revision": 7,
                "connection_id": "conn_" + ("a" * 32),
                "read_namespaces": None,
                "write_namespace": "private",
            },
        )
        self.assertEqual(credential, "vlt_secondary-canary")
        self.assertEqual(len(pass_fds), 2)
        self.assertNotIn("vlt_primary-canary", repr(observed))

    def test_multi_connection_recall_uses_isolated_children_and_global_merge(
        self,
    ) -> None:
        config = self._routing_config()
        credentials = {
            "primary": "vlt_primary-canary",
            "conn_" + ("a" * 32): "vlt_secondary-canary",
        }
        observed = []
        responses = {
            "primary": {
                "results": [
                    {
                        "document_id": "shared",
                        "title": "Lower duplicate",
                        "content": "same",
                        "score": 0.7,
                        "namespace": "default",
                    },
                    {
                        "document_id": "p2",
                        "title": "Primary two",
                        "content": "p2",
                        "score": 0.6,
                        "namespace": "default",
                    },
                ]
            },
            "conn_" + ("a" * 32): {
                "results": [
                    {
                        "document_id": "shared",
                        "title": "Higher duplicate",
                        "content": "same",
                        "score": 0.9,
                        "namespace": "history",
                    },
                    {
                        "document_id": "s2",
                        "title": "Secondary two",
                        "content": "s2",
                        "score": 0.8,
                        "namespace": "history",
                    },
                    {
                        "document_id": "s3",
                        "title": "Secondary three",
                        "content": "s3",
                        "score": 0.5,
                        "namespace": "history",
                    },
                    {
                        "document_id": "s4",
                        "title": "Secondary four",
                        "content": "s4",
                        "score": 0.4,
                        "namespace": "history",
                    },
                ]
            },
        }

        def run_helper(arguments, **kwargs):
            environment = kwargs["environment"]
            descriptor = json.loads(
                os.read(
                    int(environment["REMEM_MEMORY_ROUTE_FD"]),
                    4096,
                ).decode("utf-8")
            )
            credential = os.read(
                int(environment["REMEM_API_KEY_FD"]),
                4096,
            ).decode("utf-8")
            observed.append((descriptor, credential))
            rendered = json.dumps(
                {
                    "payload": {
                        "query": "history",
                        "mode": "fast",
                        "max_results": 10,
                    },
                    "response": responses[descriptor["connection_id"]],
                }
            )
            return mock.Mock(
                returncode=0,
                stdout=rendered,
                stderr="",
            )

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_DATA_DIR": directory},
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory,
                    "_load_or_initialize_routing",
                    return_value=config,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        side_effect=lambda connection, **_kwargs: credentials[
                            connection.id
                        ],
                    ):
                        with mock.patch.object(
                            remem_memory,
                            "_run_bounded_capture",
                            side_effect=run_helper,
                        ) as run:
                            with contextlib.redirect_stdout(stdout):
                                result = remem_memory.run_command(
                                    "recall",
                                    [
                                        "--query",
                                        "history",
                                        "--from",
                                        "primary/default",
                                        "--from",
                                        "Secondary/history",
                                        "--no-log",
                                    ],
                                )

        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            observed,
            [
                (
                    {
                        "schema_version": 1,
                        "client": "codex",
                        "behavior": "recall",
                        "route_revision": 7,
                        "connection_id": "primary",
                        "read_namespaces": ["default"],
                        "write_namespace": None,
                    },
                    "vlt_primary-canary",
                ),
                (
                    {
                        "schema_version": 1,
                        "client": "codex",
                        "behavior": "recall",
                        "route_revision": 7,
                        "connection_id": "conn_" + ("a" * 32),
                        "read_namespaces": ["history"],
                        "write_namespace": None,
                    },
                    "vlt_secondary-canary",
                ),
            ],
        )
        merged = json.loads(stdout.getvalue())
        self.assertEqual(
            [item["title"] for item in merged["response"]["results"]],
            [
                "Higher duplicate",
                "Secondary two",
                "Primary two",
                "Secondary three",
            ],
        )
        self.assertNotIn("vlt_primary-canary", stdout.getvalue())
        self.assertNotIn("vlt_secondary-canary", stdout.getvalue())

    def test_canonical_recall_surfaces_only_a_fixed_child_failure_kind(
        self,
    ) -> None:
        config = self._routing_config()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_DATA_DIR": directory},
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory,
                    "_load_or_initialize_routing",
                    return_value=config,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="vlt_selected-canary",
                    ):
                        with mock.patch.object(
                            remem_memory,
                            "_run_bounded_capture",
                            return_value=mock.Mock(
                                returncode=1,
                                stdout="",
                                stderr=(
                                    "error: query failed [permission]\n"
                                ),
                            ),
                        ):
                            with contextlib.redirect_stderr(stderr):
                                result = remem_memory.run_command(
                                    "recall",
                                    ["--query", "history", "--no-log"],
                                )

        self.assertEqual(result, 1)
        self.assertEqual(
            stderr.getvalue(),
            "error: query failed [permission]\n",
        )

    def test_named_route_cannot_borrow_primary_override_for_loopback(
        self,
    ) -> None:
        config = self._routing_config()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": directory,
                    "REMEM_API_KEY": "vlt_primary-override-canary",
                    "REMEM_API_URL": "http://127.0.0.1:8765",
                    "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                    "REMEM_MEMORY_DATA_DIR": directory,
                },
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory,
                    "_load_or_initialize_routing",
                    return_value=config,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="vlt_named-keychain-canary",
                    ) as resolve:
                        with mock.patch.object(
                            remem_memory.subprocess,
                            "run",
                        ) as run:
                            with contextlib.redirect_stderr(stderr):
                                result = remem_memory.run_command(
                                    "checkpoint",
                                    [
                                        "--to",
                                        "Secondary/private",
                                        "--ingest",
                                    ],
                                )

        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue(),
            "error: invalid Remem API URL\n",
        )
        resolve.assert_not_called()
        run.assert_not_called()

    def test_canonical_codex_transports_existing_home_primary_override(
        self,
    ) -> None:
        canary = "vlt_existing-home-primary-canary"
        observed = {}

        def run_wrapper(_arguments, **kwargs):
            environment = kwargs["env"]
            observed["environment"] = dict(environment)
            observed["pass_fds"] = tuple(kwargs.get("pass_fds", ()))
            descriptor = int(environment["REMEM_API_KEY_FD"])
            observed["credential"] = os.read(descriptor, 8192).decode()
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": directory,
                    "PATH": "/test/bin",
                    "REMEM_API_KEY": canary,
                },
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    side_effect=run_wrapper,
                ):
                    result = remem_memory.run_command("codex", [])

        self.assertEqual(result, 0)
        self.assertEqual(observed["credential"], canary)
        self.assertNotIn("REMEM_API_KEY", observed["environment"])
        self.assertIn(
            int(observed["environment"]["REMEM_API_KEY_FD"]),
            observed["pass_fds"],
        )

    def test_alias_fails_closed_on_malformed_inherited_descriptors(
        self,
    ) -> None:
        config = self._routing_config()
        valid = {
            "schema_version": 1,
            "client": "codex",
            "behavior": "recall",
            "route_revision": 7,
            "connection_id": "primary",
            "read_namespaces": None,
            "write_namespace": None,
        }
        invalid_descriptors = (
            (
                "duplicate",
                (
                    b'{"schema_version":1,"schema_version":1,'
                    b'"client":"codex","behavior":"recall",'
                    b'"route_revision":7,"connection_id":"primary",'
                    b'"read_namespaces":null,"write_namespace":null}'
                ),
            ),
            ("oversize", b"{" + (b"x" * 4096) + b"}"),
            (
                "stale",
                json.dumps(
                    {**valid, "route_revision": 6}
                ).encode("utf-8"),
            ),
        )
        for case, raw in invalid_descriptors:
            with self.subTest(case=case):
                route_environment, route_fd = self._descriptor_pipe(raw)
                key_fd, key_write = os.pipe()
                os.write(key_write, b"vlt_inherited-canary")
                os.close(key_write)
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        with mock.patch.dict(
                            os.environ,
                            {
                                **route_environment,
                                "REMEM_API_KEY_FD": str(key_fd),
                                "REMEM_MEMORY_DATA_DIR": directory,
                            },
                            clear=True,
                        ):
                            with mock.patch.object(
                                remem_memory,
                                "_load_or_initialize_routing",
                                return_value=config,
                            ):
                                with mock.patch.object(
                                    remem_memory.subprocess,
                                    "run",
                                    return_value=mock.Mock(returncode=0),
                                ) as run:
                                    with contextlib.redirect_stderr(
                                        io.StringIO()
                                    ):
                                        result = remem_memory.main(
                                            [
                                                "--dry-run",
                                                "--query",
                                                "history",
                                            ],
                                            program="remem-memory-recall",
                                        )
                    self.assertEqual(result, 1)
                    run.assert_not_called()
                    with self.assertRaises(OSError):
                        os.read(route_fd, 1)
                    with self.assertRaises(OSError):
                        os.read(key_fd, 1)
                finally:
                    for descriptor in (route_fd, key_fd):
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass

    def test_recall_capture_kills_and_reaps_noisy_or_stalled_child(
        self,
    ) -> None:
        descriptor = {
            "schema_version": 1,
            "client": "codex",
            "behavior": "recall",
            "route_revision": 7,
            "connection_id": "primary",
            "read_namespaces": None,
            "write_namespace": None,
        }
        original_run = subprocess.run
        scripts = (
            (
                "noisy.py",
                (
                    "import os\n"
                    "while True:\n"
                    " os.write(1, b'x' * 4096)\n"
                    " os.write(2, b'y' * 4096)\n"
                ),
            ),
            ("stalled.py", "import time\ntime.sleep(60)\n"),
            (
                "closed-pipes.py",
                (
                    "import os, time\n"
                    "os.close(1)\n"
                    "os.close(2)\n"
                    "time.sleep(60)\n"
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for name, source in scripts:
                with self.subTest(name=name):
                    script = Path(directory) / name
                    script.write_text(source, encoding="utf-8")

                    def guarded_run(*args, **kwargs):
                        kwargs["timeout"] = 0.6
                        return original_run(*args, **kwargs)

                    started = time.monotonic()
                    with mock.patch.object(
                        remem_memory,
                        "_MAX_RECALL_CHILD_OUTPUT_BYTES",
                        4096,
                    ):
                        with mock.patch.object(
                            remem_memory,
                            "_RECALL_CHILD_TIMEOUT_SECONDS",
                            0.15,
                            create=True,
                        ):
                            with mock.patch.object(
                                remem_memory.subprocess,
                                "run",
                                side_effect=guarded_run,
                            ):
                                with self.assertRaises(RuntimeError):
                                    remem_memory._run_routed_child(
                                        script_path=script,
                                        forwarded_args=[],
                                        child_environment={},
                                        route_descriptor=descriptor,
                                        credential="vlt_selected-canary",
                                        capture_output=True,
                                    )
                    self.assertLess(time.monotonic() - started, 0.5)

    def test_routed_checkpoint_log_never_persists_response_body(
        self,
    ) -> None:
        route = {
            "schema_version": 1,
            "client": "codex",
            "behavior": "sessions",
            "route_revision": 2,
            "connection_id": "primary",
            "read_namespaces": None,
            "write_namespace": None,
        }
        route_environment, _route_fd = self._descriptor_pipe(
            json.dumps(route).encode("utf-8")
        )
        key_read, key_write = os.pipe()
        os.write(key_write, b"vlt_selected-canary")
        os.close(key_write)
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "checkpoints.ndjson"
            with mock.patch.dict(
                os.environ,
                {
                    **route_environment,
                    "REMEM_API_KEY_FD": str(key_read),
                },
                clear=True,
            ):
                with mock.patch.object(
                    remem_checkpoint,
                    "ingest_checkpoint",
                    return_value={
                        "document_id": "doc",
                        "private_body": "must-not-be-logged",
                    },
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = remem_checkpoint.main(
                            [
                                "--project",
                                "remem",
                                "--session-id",
                                "s1",
                                "--summary",
                                "safe",
                                "--ingest",
                                "--log-file",
                                str(log_path),
                            ]
                        )

            logged = json.loads(
                log_path.read_text(encoding="utf-8").strip()
            )

        self.assertEqual(result, 0)
        self.assertNotIn("response", logged)
        self.assertNotIn("must-not-be-logged", repr(logged))

    def test_shared_api_accepts_a_complete_manual_query_payload(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return _Response({"results": []})

        payload = {
            "query": "what changed",
            "mode": "rich",
            "max_results": 12,
            "synthesize": True,
            "filters": {"checkpoint_project": ["remem"]},
        }
        api = _API.RememAPI(
            "https://api.remem.io",
            "test-key",
            opener=opener,
        )

        response = api.query_payload(payload, timeout=4.5)

        self.assertEqual(response, {"results": []})
        self.assertEqual(captured["url"], "https://api.remem.io/v1/query")
        self.assertEqual(captured["body"], payload)
        self.assertEqual(captured["timeout"], 4.5)

    def test_recall_helper_uses_shared_stdlib_transport(self) -> None:
        adapter = mock.Mock()
        adapter.query_payload.return_value = {"results": []}
        payload = {
            "query": "history",
            "mode": "fast",
            "max_results": 10,
        }

        with mock.patch.object(
            remem_recall.remem_api,
            "RememAPI",
            return_value=adapter,
        ) as constructor:
            with mock.patch.dict(
                remem_recall.__dict__,
                {"httpx": _ForbiddenHTTPX},
            ):
                response = remem_recall.query_remem(
                    api_url="https://api.remem.io",
                    api_key="test-key",
                    payload=payload,
                )

        self.assertEqual(response, {"results": []})
        constructor.assert_called_once_with(
            "https://api.remem.io",
            "test-key",
            allow_local_dev=True,
        )
        adapter.query_payload.assert_called_once_with(
            payload,
            timeout=45.0,
        )

    def test_checkpoint_helper_uses_shared_stdlib_transport(self) -> None:
        adapter = mock.Mock()
        adapter.ingest.return_value = {"document_id": "doc"}
        payload = {"title": "checkpoint", "content": "summary"}

        with mock.patch.object(
            remem_checkpoint.remem_api,
            "RememAPI",
            return_value=adapter,
        ) as constructor:
            with mock.patch.dict(
                remem_checkpoint.__dict__,
                {"httpx": _ForbiddenHTTPX},
            ):
                response = remem_checkpoint.ingest_checkpoint(
                    api_url="https://api.remem.io",
                    api_key="test-key",
                    payload=payload,
                )

        self.assertEqual(response, {"document_id": "doc"})
        constructor.assert_called_once_with(
            "https://api.remem.io",
            "test-key",
            allow_local_dev=True,
        )
        adapter.ingest.assert_called_once_with(
            payload,
            None,
            timeout=30.0,
        )

    def test_root_helpers_need_no_dependency_manifest(self) -> None:
        self.assertFalse((_ROOT / "requirements.txt").exists())
        for relative in (
            "scripts/remem_checkpoint.py",
            "scripts/remem_recall.py",
            "scripts/remem_rollup.py",
        ):
            with self.subTest(relative=relative):
                source = (_ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("import httpx", source)


if __name__ == "__main__":
    unittest.main()
