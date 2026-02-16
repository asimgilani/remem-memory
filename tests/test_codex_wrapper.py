import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


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

    def test_read_codex_transcript_excerpt_skips_bootstrap_noise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"cwd": "/repo"}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "# AGENTS.md instructions for /repo"}],
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "Fix upload retry behavior"}],
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "arguments": "{\"cmd\":\"pytest -q\"}",
                        "call_id": "call-1",
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Implemented retry cap and added tests."}],
                    },
                },
            ]
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

            excerpt = _MODULE._read_codex_transcript_excerpt(str(path), max_messages=20, max_chars=4000)

            self.assertIn("User: Fix upload retry behavior", excerpt)
            self.assertIn("Assistant: Implemented retry cap and added tests.", excerpt)
            self.assertIn("[tool] exec_command", excerpt)
            self.assertNotIn("AGENTS.md instructions", excerpt)

    def test_discover_codex_transcript_path_prefers_matching_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions_root = Path(td)
            repo_a = Path(td) / "repo-a"
            repo_b = Path(td) / "repo-b"
            repo_a.mkdir()
            repo_b.mkdir()

            file_a = sessions_root / "2026" / "02" / "16" / "rollout-a.jsonl"
            file_b = sessions_root / "2026" / "02" / "16" / "rollout-b.jsonl"
            file_a.parent.mkdir(parents=True, exist_ok=True)
            file_a.write_text(
                json.dumps({"type": "session_meta", "payload": {"cwd": str(repo_a)}}) + "\n",
                encoding="utf-8",
            )
            file_b.write_text(
                json.dumps({"type": "session_meta", "payload": {"cwd": str(repo_b)}}) + "\n",
                encoding="utf-8",
            )
            now = time.time()
            os.utime(file_a, (now, now))
            os.utime(file_b, (now - 5, now - 5))

            with mock.patch.dict(os.environ, {"REMEM_MEMORY_CODEX_SESSIONS_DIR": str(sessions_root)}):
                discovered = _MODULE._discover_codex_transcript_path(
                    cwd=repo_a.resolve(),
                    started_at_epoch=now - 60,
                    existing_path="",
                )

            self.assertEqual(str(file_a), discovered)

    @mock.patch.object(_MODULE, "_run_helper", return_value=0)
    def test_run_checkpoint_passes_structured_items(self, run_helper: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as td:
            ok = _MODULE._run_checkpoint(
                cwd=Path(td),
                env={},
                project="remem",
                session_id="sess-1",
                kind="interval",
                summary="checkpoint summary",
                changed_files=["src/a.py"],
                max_files=10,
                log_file=".remem/session-checkpoints.ndjson",
                ingest=False,
                dry_run=False,
                decisions=["use spark summaries"],
                open_questions=["should we summarize every milestone?"],
                next_actions=["add rollup synthesis"],
            )
        self.assertTrue(ok)
        call_args = run_helper.call_args.args
        self.assertEqual("remem_checkpoint.py", call_args[0])
        script_args = call_args[1]
        self.assertIn("--decision", script_args)
        self.assertIn("use spark summaries", script_args)
        self.assertIn("--open-question", script_args)
        self.assertIn("should we summarize every milestone?", script_args)
        self.assertIn("--next-action", script_args)
        self.assertIn("add rollup synthesis", script_args)


if __name__ == "__main__":
    unittest.main()
