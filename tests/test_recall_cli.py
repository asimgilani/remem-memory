import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class RecallCliTests(unittest.TestCase):
    @staticmethod
    def _load_recall_module():
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_recall.py"
        spec = importlib.util.spec_from_file_location(
            "remem_recall_test_module",
            script,
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_recall_dry_run_builds_payload(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_recall.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--query",
                "what changed",
                "--mode",
                "rich",
                "--synthesize",
                "--checkpoint-project",
                "hive",
                "--checkpoint-session",
                "sess-1",
                "--checkpoint-kind",
                "interval",
                "--dry-run",
                "--no-log",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"Expected exit 0 but got {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn('"payload"', result.stdout)
        self.assertIn('"checkpoint_project"', result.stdout)
        self.assertIn('"checkpoint_session"', result.stdout)

    def test_unified_cli_routes_to_recall(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_dev_sessions.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "recall",
                "--query",
                "test",
                "--dry-run",
                "--no-log",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"Expected exit 0 but got {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn('"payload"', result.stdout)


    def test_include_facts_flag_in_payload(self) -> None:
        """--include-facts is forwarded in the query payload."""
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_recall.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--query",
                "what tools do we use",
                "--include-facts",
                "--dry-run",
                "--no-log",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=f"stderr:\n{result.stderr}")
        self.assertIn('"include_facts"', result.stdout)
        self.assertIn("true", result.stdout.lower())

    def test_entity_flag_in_payload(self) -> None:
        """--entity is forwarded in the query payload."""
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_recall.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--query",
                "tech stack",
                "--include-facts",
                "--entity",
                "Acme Corp",
                "--dry-run",
                "--no-log",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=f"stderr:\n{result.stderr}")
        self.assertIn('"entity"', result.stdout)
        self.assertIn("Acme Corp", result.stdout)

    def test_no_facts_flags_omitted_from_payload(self) -> None:
        """Without --include-facts, neither include_facts nor entity appear in payload."""
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "remem_recall.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--query",
                "test",
                "--dry-run",
                "--no-log",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=f"stderr:\n{result.stderr}")
        self.assertNotIn('"include_facts"', result.stdout)
        self.assertNotIn('"entity"', result.stdout)

    def test_fact_response_is_only_emitted_as_escaped_json(self) -> None:
        module = self._load_recall_module()
        response = {
            "results": [],
            "facts": [
                {
                    "id": "01234567-89ab-4def-8123-456789abcdef",
                    "fact_type": "preference",
                    "content": "\x1b]8;;https://attacker.invalid\x07unsafe",
                    "confidence": 0.2,
                    "is_latest": True,
                    "is_provisional": False,
                    "valid_from": None,
                    "valid_until": None,
                    "source_document_id": "fedcba98-7654-3210-fedc-ba9876543210",
                    "entities": ["Alice"],
                    "relationships": [],
                }
            ],
            "fact_count": 1,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        route_read, route_write = os.pipe()
        key_read, key_write = os.pipe()
        os.write(
            route_write,
            json.dumps(
                {
                    "schema_version": 1,
                    "client": "codex",
                    "behavior": "recall",
                    "route_revision": 1,
                    "connection_id": "primary",
                    "read_namespaces": None,
                    "write_namespace": None,
                }
            ).encode("utf-8"),
        )
        os.write(key_write, b"test-key")
        os.close(route_write)
        os.close(key_write)
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_MEMORY_ROUTE_FD": str(route_read),
                "REMEM_API_KEY_FD": str(key_read),
            },
            clear=True,
        ):
            with mock.patch.object(
                module,
                "query_remem",
                return_value=response,
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        result = module.main(
                            [
                                "--query",
                                "facts",
                                "--include-facts",
                                "--no-log",
                            ]
                        )

        parsed = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(parsed["policy_version"], "retrieval-envelope-v1")
        self.assertEqual(parsed["origin"], "python_cli")
        self.assertEqual(parsed["access_mode"], "ordinary")
        self.assertEqual(parsed["trust"], "untrusted_source")
        self.assertNotIn("payload", parsed)
        self.assertNotIn("response", parsed)
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertNotIn("\x07", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_routed_child_consumes_one_descriptor_and_queries_only_its_namespaces(
        self,
    ) -> None:
        module = self._load_recall_module()
        route = {
            "schema_version": 1,
            "client": "claude",
            "behavior": "recall",
            "route_revision": 9,
            "connection_id": "conn_" + ("b" * 32),
            "read_namespaces": ["history", "decisions"],
            "write_namespace": None,
        }
        route_read, route_write = os.pipe()
        key_read, key_write = os.pipe()
        os.write(route_write, json.dumps(route).encode("utf-8"))
        os.write(key_write, b"vlt_selected-only-canary")
        os.close(route_write)
        os.close(key_write)
        captured = {}

        def query_remem(*, api_url, api_key, payload):
            captured["api_url"] = api_url
            captured["api_key"] = api_key
            captured["payload"] = payload
            captured["route_environment"] = os.environ.get(
                "REMEM_MEMORY_ROUTE_FD"
            )
            captured["key_environment"] = os.environ.get(
                "REMEM_API_KEY_FD"
            )
            return {"results": []}

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_MEMORY_ROUTE_FD": str(route_read),
                "REMEM_API_KEY_FD": str(key_read),
                "REMEM_API_URL": "https://api.remem.io",
            },
            clear=True,
        ):
            with mock.patch.object(
                module,
                "query_remem",
                side_effect=query_remem,
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        result = module.main(
                            [
                                "--client",
                                "claude",
                                "--query",
                                "history",
                                "--no-log",
                            ]
                        )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(captured["api_key"], "vlt_selected-only-canary")
        self.assertEqual(
            captured["payload"]["namespaces"],
            ["history", "decisions"],
        )
        self.assertIsNone(captured["route_environment"])
        self.assertIsNone(captured["key_environment"])
        with self.assertRaises(OSError):
            os.read(route_read, 1)
        with self.assertRaises(OSError):
            os.read(key_read, 1)

    def test_routed_child_reports_only_fixed_permanent_failure_kind(
        self,
    ) -> None:
        module = self._load_recall_module()
        route = {
            "schema_version": 1,
            "client": "codex",
            "behavior": "recall",
            "route_revision": 3,
            "connection_id": "primary",
            "read_namespaces": None,
            "write_namespace": None,
        }
        route_read, route_write = os.pipe()
        key_read, key_write = os.pipe()
        os.write(route_write, json.dumps(route).encode("utf-8"))
        os.write(key_write, b"vlt_selected-only-canary")
        os.close(route_write)
        os.close(key_write)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_MEMORY_ROUTE_FD": str(route_read),
                "REMEM_API_KEY_FD": str(key_read),
            },
            clear=True,
        ):
            with mock.patch.object(
                module,
                "query_remem",
                side_effect=module.remem_api.RememAPIError(
                    "body contains private response",
                    kind="permission",
                ),
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        result = module.main(
                            ["--query", "history", "--no-log"]
                        )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "error: query failed [permission]\n",
        )
        self.assertNotIn("private response", stderr.getvalue())

    def test_stdout_and_output_are_the_same_canonical_envelope(self) -> None:
        module = self._load_recall_module()
        response = {
            "results": [
                {
                    "document_id": "11111111-1111-1111-1111-111111111111",
                    "title": "safe-title-neighbor",
                    "source": "api",
                    "chunks": [],
                }
            ]
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "out.json"
            with mock.patch.object(
                module.remem_api,
                "resolve_api_access",
                return_value=("https://api.remem.io", "test-key"),
            ):
                with mock.patch.object(
                    module,
                    "query_remem",
                    return_value=response,
                ) as query:
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            result = module.main(
                                [
                                    "--query",
                                    "history",
                                    "--no-log",
                                    "--output",
                                    str(output_path),
                                ]
                            )
            written = output_path.read_text(encoding="utf-8")
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), written + "\n")
        parsed = json.loads(written)
        self.assertEqual(parsed["origin"], "python_cli")
        self.assertEqual(parsed["access_mode"], "ordinary")
        self.assertNotIn("payload", parsed)
        self.assertNotIn("history", written)
        query.assert_called_once()

    def test_invalid_sensitive_fields_make_zero_requests(self) -> None:
        module = self._load_recall_module()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {"REMEM_RETRIEVAL_SENSITIVE_FIELDS": "{"},
            clear=False,
        ):
            with mock.patch.object(
                module.remem_api,
                "resolve_api_access",
                return_value=("https://api.remem.io", "test-key"),
            ) as resolve:
                with mock.patch.object(
                    module,
                    "query_remem",
                    return_value={"results": []},
                ) as query:
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            result = module.main(
                                ["--query", "history", "--no-log"]
                            )
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "error: invalid sensitive fields\n")
        resolve.assert_not_called()
        query.assert_not_called()

    def test_null_sensitive_fields_make_zero_requests(self) -> None:
        module = self._load_recall_module()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {"REMEM_RETRIEVAL_SENSITIVE_FIELDS": "null"},
            clear=False,
        ):
            with mock.patch.object(
                module.remem_api,
                "resolve_api_access",
                return_value=("https://api.remem.io", "test-key"),
            ) as resolve:
                with mock.patch.object(
                    module,
                    "query_remem",
                    return_value={"results": []},
                ) as query:
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            result = module.main(
                                ["--query", "history", "--no-log"]
                            )
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "error: invalid sensitive fields\n")
        resolve.assert_not_called()
        query.assert_not_called()


if __name__ == "__main__":
    unittest.main()
