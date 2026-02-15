import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "plugins" / "remem-memory" / "scripts" / "auto_memory_hook.py"
_SPEC = importlib.util.spec_from_file_location("auto_memory_hook", _SCRIPT_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)


def _build_cfg():
    return _MODULE.Config(
        cwd=Path("/tmp"),
        project="remem",
        session_id="sess-a",
        api_url="https://api.remem.io",
        api_key="",
        interval_seconds=1200,
        min_events=4,
        state_path=Path("/tmp/state.json"),
        log_path=Path("/tmp/log.ndjson"),
        enabled=True,
        rollup_on_session_end=True,
    )


class AutoMemoryHookTests(unittest.TestCase):
    def test_extract_tool_event_for_write(self) -> None:
        event = _MODULE._extract_tool_event(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "src/main.py"},
            }
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual("Write", event["tool"])
        self.assertEqual(["src/main.py"], event["files"])
        self.assertIn("Write src/main.py", event["summary"])

    def test_should_interval_checkpoint_when_event_threshold_met(self) -> None:
        state = {"events_since_checkpoint": 4, "last_checkpoint_epoch": 0.0}
        self.assertTrue(_MODULE._should_interval_checkpoint(state, _build_cfg()))

    def test_should_not_checkpoint_before_min_events(self) -> None:
        state = {"events_since_checkpoint": 3, "last_checkpoint_epoch": 0.0}
        self.assertFalse(_MODULE._should_interval_checkpoint(state, _build_cfg()))

    def test_read_transcript_excerpt_filters_tool_results(self) -> None:
        rows = [
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": [{"type": "text", "text": "We decided to ship v1."}]},
            },
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "python foo.py"}}],
                },
            },
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "content": "SECRET=shh-this-should-not-appear"}],
                },
            },
            {"type": "user", "message": {"role": "user", "content": "What next?"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "transcript.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "REMEM_MEMORY_SUMMARY_HEAD_LINES": "0",
                    "REMEM_MEMORY_SUMMARY_TAIL_LINES": "50",
                    "REMEM_MEMORY_SUMMARY_MAX_MESSAGES": "20",
                    "REMEM_MEMORY_SUMMARY_MAX_CHARS": "5000",
                },
            ):
                excerpt = _MODULE._read_transcript_excerpt(str(path))
        self.assertIn("We decided to ship v1.", excerpt)
        self.assertIn("Bash python foo.py", excerpt)
        self.assertIn("User: What next?", excerpt)
        self.assertNotIn("SECRET=shh-this-should-not-appear", excerpt)

    def test_checkpoint_payload_includes_structured_summary_when_available(self) -> None:
        cfg = _build_cfg()
        structured = _MODULE.StructuredSummary(
            summary="Implemented LLM-backed transcript summarization for checkpoints.",
            decisions=["Summarize from transcript excerpt, not tool results."],
            open_questions=["Should we add PreCompact hook?"],
            next_actions=["Add rollup synthesis test coverage."],
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
        )
        with mock.patch.object(_MODULE, "_generate_checkpoint_structured_summary", return_value=structured):
            payload = _MODULE._build_checkpoint_payload(
                config=cfg,
                kind="interval",
                hook_event="PostToolUse",
                recent_events=[],
                events_since_checkpoint=5,
                transcript_path="/tmp/fake.jsonl",
            )
        meta = payload["metadata"]
        self.assertEqual(structured.summary, meta["summary"])
        self.assertEqual(structured.decisions, meta["decisions"])
        self.assertIn("## Decisions", payload["content"])


if __name__ == "__main__":
    unittest.main()
