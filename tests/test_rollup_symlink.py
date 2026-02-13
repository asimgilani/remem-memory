import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


class RollupSymlinkExecutionTests(unittest.TestCase):
    def test_rollup_runs_when_invoked_via_symlink(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        scripts_dir = repo_root / "scripts"

        with tempfile.TemporaryDirectory() as td:
            bin_dir = Path(td) / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            link_path = bin_dir / "remem-memory-rollup"
            os.symlink(scripts_dir / "remem_rollup.py", link_path)
            link_path.chmod(link_path.stat().st_mode | stat.S_IXUSR)

            result = subprocess.run(
                [
                    str(link_path),
                    "--project",
                    "smoke",
                    "--session-id",
                    "symlink-test",
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
