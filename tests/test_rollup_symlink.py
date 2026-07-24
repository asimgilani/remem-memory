from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.install_remem_memory import COMMAND_ALIASES


class InstalledAliasExecutionTests(unittest.TestCase):
    def test_every_alias_executes_by_basename_through_canonical_dispatcher(self) -> None:
        live_root = Path(__file__).resolve().parents[1]
        workflow_aliases = [
            alias
            for alias in COMMAND_ALIASES
            if alias
            not in {
                "remem-memory",
                "remem-dev-sessions",
                "remem-session-memory",
            }
        ]

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory) / "checkout"
            shutil.copytree(live_root / "scripts", temporary_root / "scripts")
            shutil.copytree(
                live_root / "plugins" / "remem-memory" / "scripts",
                temporary_root / "plugins" / "remem-memory" / "scripts",
            )
            # Dry-run/helper imports must not depend on globally installed httpx.
            (temporary_root / "scripts" / "httpx.py").write_text(
                "class HTTPError(Exception):\n    pass\n",
                encoding="utf-8",
            )

            canonical = temporary_root / "scripts" / "remem_memory.py"
            canonical.chmod(0o755)
            bin_directory = Path(directory) / "home" / ".local" / "bin"
            bin_directory.mkdir(parents=True)
            for alias in COMMAND_ALIASES:
                (bin_directory / alias).symlink_to(canonical)

            environment = {
                "HOME": str(Path(directory) / "home"),
                "PATH": (
                    f"{bin_directory}{os.pathsep}"
                    f"{Path(sys.executable).parent}{os.pathsep}/usr/bin:/bin"
                ),
            }
            results = {
                alias: subprocess.run(
                    [alias, "--help"],
                    cwd=temporary_root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                for alias in COMMAND_ALIASES
            }
        failures = {
            alias: (result.returncode, result.stdout, result.stderr)
            for alias, result in results.items()
            if result.returncode != 0
        }
        self.assertEqual(failures, {})
        self.assertEqual(len(results), len(COMMAND_ALIASES))


if __name__ == "__main__":
    unittest.main()
