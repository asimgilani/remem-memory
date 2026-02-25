import subprocess
import sys
import unittest
from pathlib import Path


class RecallCliTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
