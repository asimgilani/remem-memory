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


if __name__ == "__main__":
    unittest.main()
