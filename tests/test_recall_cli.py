import contextlib
import importlib.util
import io
import json
import subprocess
import sys
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
            "facts": [
                {
                    "fact_type": "preference",
                    "content": "\x1b]8;;https://attacker.invalid\x07unsafe",
                    "confidence": "not-a-number",
                    "entities": [123],
                }
            ],
            "fact_count": "not-a-number",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            module.remem_api,
            "resolve_api_access",
            return_value=("https://api.remem.io", "test-key"),
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
        self.assertEqual(parsed["response"], response)
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertNotIn("\x07", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
