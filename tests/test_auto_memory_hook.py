import importlib.util
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
