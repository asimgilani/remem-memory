import importlib.util
import sys
import unittest
from pathlib import Path


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "remem_codex_wrapper.py"
_SPEC = importlib.util.spec_from_file_location("remem_codex_wrapper", _SCRIPT_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)


class CodexWrapperTests(unittest.TestCase):
    def test_parse_porcelain_paths_handles_rename_and_untracked(self) -> None:
        lines = [
            " M src/main.py",
            "?? docs/new-file.md",
            "R  old/name.txt -> new/name.txt",
        ]
        paths = _MODULE.parse_porcelain_paths(lines)
        self.assertEqual(["src/main.py", "docs/new-file.md", "new/name.txt"], paths)

    def test_build_checkpoint_summary_mentions_files(self) -> None:
        summary = _MODULE.build_checkpoint_summary(
            kind="interval",
            reason="interval",
            changed_files=["a.py", "b.py", "c.py"],
            max_files=2,
        )
        self.assertIn("Automatic interval checkpoint", summary)
        self.assertIn("a.py, b.py", summary)
        self.assertIn("+1 more", summary)


if __name__ == "__main__":
    unittest.main()
