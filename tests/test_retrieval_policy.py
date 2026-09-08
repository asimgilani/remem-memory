from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR = _ROOT / "plugins" / "remem-memory" / "scripts"
_FIXTURE_PATH = _ROOT / "tests" / "fixtures" / "retrieval-envelope-v1.json"
_CAPTURE_FIXTURE_PATH = (
    _ROOT / "tests" / "fixtures" / "automatic-capture-policy-v1.json"
)
sys.path.insert(0, str(_SCRIPTS_DIR))

_POLICY_SPEC = importlib.util.spec_from_file_location(
    "memory_policy",
    _SCRIPTS_DIR / "memory_policy.py",
)
_POLICY = importlib.util.module_from_spec(_POLICY_SPEC)
assert _POLICY_SPEC and _POLICY_SPEC.loader
sys.modules[_POLICY_SPEC.name] = _POLICY
_POLICY_SPEC.loader.exec_module(_POLICY)

_RETRIEVAL_SPEC = importlib.util.spec_from_file_location(
    "retrieval_policy",
    _SCRIPTS_DIR / "retrieval_policy.py",
)
_RP = importlib.util.module_from_spec(_RETRIEVAL_SPEC)
assert _RETRIEVAL_SPEC and _RETRIEVAL_SPEC.loader
sys.modules[_RETRIEVAL_SPEC.name] = _RP
_RETRIEVAL_SPEC.loader.exec_module(_RP)


def _load_fixture() -> dict:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def _dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def _utf8_size(value: object) -> int:
    return len(_dumps(value).encode("utf-8"))


def _needles(case: dict) -> list[str]:
    values = case.get("needles")
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, str) and item]


def _absent(case: dict) -> list[str]:
    values = case.get("absent")
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, str) and item]


def _diagnostics(result: dict) -> str:
    return _dumps(
        {
            "redaction": result["redaction"],
            "truncation": result["truncation"],
            "continuation": result["continuation"],
        }
    )


def _call(case: dict):
    return _RP.build_retrieval_envelope(
        case["records"],
        origin=case["origin"],
        sensitive_fields=case.get("sensitive_fields", []),
        budget=case.get("budget", _RP.DEFAULT_OUTPUT_BUDGET),
    )


class RetrievalPolicyTests(unittest.TestCase):
    def test_fixture_version_and_closed_vocabulary(self) -> None:
        fixture = _load_fixture()
        self.assertEqual(fixture["version"], "retrieval-envelope-v1")
        self.assertEqual(
            _RP.RETRIEVAL_ENVELOPE_VERSION,
            fixture["version"],
        )
        self.assertEqual(_RP.DEFAULT_OUTPUT_BUDGET, 50000)
        self.assertEqual(_RP.DEFAULT_OUTPUT_BUDGET, fixture["default_budget"])
        self.assertEqual(_RP.REDACTION_MARKER, fixture["redaction_marker"])
        self.assertEqual(set(fixture["origins"]), set(_RP.RETRIEVAL_ORIGINS))
        self.assertEqual(set(fixture["kinds"]), set(_RP.RETRIEVAL_KINDS))
        note = fixture["change_note"].lower()
        self.assertIn("redact", note)
        self.assertIn("truncat", note)
        categories = {case["id"] for case in fixture["cases"]}
        for required in (
            "nested-password-field-keeps-safe-neighbor",
            "nested-credential-object-array-numeric-removed",
            "additive-sensitive-fields-extend-defaults",
            "off-record-drops-whole-record-keeps-neighbor",
            "forged-trust-origin-access-mode-remain-untrusted",
            "prompt-injection-remains-untrusted-source",
            "unicode-escaping-preserved",
            "tiny-budget-rejected",
        ):
            self.assertIn(required, categories)
        self.assertIn(
            "shared-references-checked-in-each-field-context",
            fixture["python_only"],
        )

    def test_automatic_capture_fixture_remains_forty_eight_cases(self) -> None:
        capture = json.loads(_CAPTURE_FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(capture["version"], "automatic-capture-policy-v1")
        self.assertEqual(len(capture["cases"]), 48)

    def test_credential_field_predicate_is_exported(self) -> None:
        self.assertTrue(_POLICY.is_credential_field_name("api_key"))
        self.assertTrue(_POLICY.is_credential_field_name("DB-Password"))
        self.assertFalse(_POLICY.is_credential_field_name("token_count"))
        self.assertFalse(_POLICY.is_credential_field_name("title"))
        self.assertFalse(_POLICY.is_credential_field_name(None))

    def test_fixture_cases(self) -> None:
        fixture = _load_fixture()
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                records = case["records"]
                original = copy.deepcopy(records)
                if case["expect"] == "error":
                    with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
                        _call(case)
                    message = str(ctx.exception)
                    self.assertEqual(message, case["error"])
                    self.assertEqual(message, message.strip())
                    self.assertLessEqual(len(message), 64)
                    for needle in _needles(case):
                        self.assertNotIn(needle, message)
                    self.assertEqual(records, original)
                    continue
                result = _call(case)
                self.assertEqual(records, original)
                self.assertEqual(result, case["expected"])
                self.assertEqual(
                    list(result.keys()),
                    [
                        "policy_version",
                        "access_mode",
                        "trust",
                        "origin",
                        "records",
                        "redaction",
                        "truncation",
                        "continuation",
                    ],
                )
                serialized = _dumps(result)
                parsed = json.loads(serialized)
                self.assertEqual(parsed, result)
                self.assertLessEqual(
                    len(serialized.encode("utf-8")),
                    case["budget"],
                )
                diagnostics = _diagnostics(result)
                for needle in _needles(case):
                    self.assertNotIn(needle, diagnostics)
                for needle in _absent(case):
                    self.assertNotIn(needle, serialized)

    def test_input_immutability_nested_mapping(self) -> None:
        records = [
            {
                "kind": "document",
                "value": {
                    "title": "keep",
                    "password": "hunter2-not-a-real-password",
                    "meta": {"ok": True},
                },
            }
        ]
        original = copy.deepcopy(records)
        _RP.build_retrieval_envelope(records, origin="python_hook")
        self.assertEqual(records, original)

    def test_raw_bypass_keyword_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            _RP.build_retrieval_envelope(
                [],
                origin="python_hook",
                raw=True,
            )
        with self.assertRaises(TypeError):
            _RP.build_retrieval_envelope(
                [],
                origin="python_hook",
                access_token="tok",
            )

    def test_malformed_sensitive_fields_fail_closed(self) -> None:
        records = [
            {
                "kind": "document",
                "value": {"password": "CANARY-SENSITIVE", "title": "x"},
            }
        ]
        original = copy.deepcopy(records)
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                records,
                origin="python_hook",
                sensitive_fields="password",
            )
        self.assertEqual(str(ctx.exception), "invalid sensitive fields")
        self.assertNotIn("CANARY-SENSITIVE", str(ctx.exception))
        self.assertEqual(records, original)

    def test_bool_and_float_budgets_are_invalid(self) -> None:
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [],
                origin="python_hook",
                budget=True,
            )
        self.assertEqual(str(ctx.exception), "invalid retrieval budget")
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [],
                origin="python_hook",
                budget=50000.0,
            )
        self.assertEqual(str(ctx.exception), "invalid retrieval budget")

    def test_shared_references_are_checked_in_each_field_context(self) -> None:
        shared = {
            "password": "hunter2-not-a-real-password",
            "title": "kept",
        }
        records = [
            {
                "kind": "entity",
                "value": {"left": shared, "right": shared},
            }
        ]
        original = copy.deepcopy(records)
        result = _RP.build_retrieval_envelope(
            records,
            origin="python_mcp",
        )
        self.assertEqual(records, original)
        self.assertEqual(
            result["records"][0]["value"],
            {
                "left": {"title": "kept"},
                "right": {"title": "kept"},
            },
        )
        self.assertEqual(result["redaction"]["fields"], 2)
        self.assertNotIn("hunter2-not-a-real-password", _dumps(result))
        self.assertNotIn(
            "hunter2-not-a-real-password",
            _diagnostics(result),
        )

    def test_cycles_are_rejected_without_reflecting_content(self) -> None:
        cyclic = {"title": "CYCLE-CANARY-UNIQUE"}
        cyclic["self"] = cyclic
        records = [{"kind": "document", "value": cyclic}]
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(records, origin="openclaw_cli")
        message = str(ctx.exception)
        self.assertEqual(message, "unsupported retrieval value")
        self.assertNotIn("CYCLE-CANARY-UNIQUE", message)

    def test_unsupported_nan_and_bytes_are_rejected(self) -> None:
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [{"kind": "fact", "value": float("nan")}],
                origin="python_hook",
            )
        self.assertEqual(str(ctx.exception), "unsupported retrieval value")
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [{"kind": "fact", "value": b"BYTES-CANARY"}],
                origin="python_hook",
            )
        self.assertEqual(str(ctx.exception), "unsupported retrieval value")
        self.assertNotIn("BYTES-CANARY", str(ctx.exception))

    def test_over_depth_and_over_nodes_are_bounded(self) -> None:
        nested: object = "DEPTH-CANARY"
        for _ in range(40):
            nested = {"child": nested}
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [{"kind": "document", "value": nested}],
                origin="python_cli",
            )
        self.assertEqual(str(ctx.exception), "retrieval input exceeds bounds")
        self.assertNotIn("DEPTH-CANARY", str(ctx.exception))
        wide = {"items": list(range(5000))}
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(
                [{"kind": "chunk", "value": wide}],
                origin="python_cli",
            )
        self.assertEqual(str(ctx.exception), "retrieval input exceeds bounds")

    def test_exact_budget_fits_and_one_byte_less_truncates(self) -> None:
        records = [
            {
                "kind": "fact",
                "value": {"title": "alpha-neighbor", "body": "bravo"},
            }
        ]
        full = _RP.build_retrieval_envelope(
            records,
            origin="python_cli",
        )
        size = _utf8_size(full)
        exact = _RP.build_retrieval_envelope(
            records,
            origin="python_cli",
            budget=size,
        )
        self.assertEqual(exact, full)
        self.assertFalse(exact["truncation"]["truncated"])
        self.assertIsNone(exact["continuation"])
        tight = _RP.build_retrieval_envelope(
            records,
            origin="python_cli",
            budget=size - 1,
        )
        self.assertTrue(tight["truncation"]["truncated"])
        self.assertEqual(tight["continuation"], {"kind": "narrow_query"})
        self.assertGreater(
            tight["truncation"]["omitted_items"]
            + tight["truncation"]["omitted_characters"],
            0,
        )
        serialized = _dumps(tight)
        self.assertLessEqual(len(serialized.encode("utf-8")), size - 1)
        json.loads(serialized)
        self.assertNotIn("alpha-neighbor", _diagnostics(tight))

    def test_long_key_and_long_record_are_omitted_safely(self) -> None:
        long_key = "k" * 4000
        records = [
            {
                "kind": "document",
                "value": {long_key: "x", "title": "ok"},
            },
            {
                "kind": "chunk",
                "value": {"body": "b" * 20000, "title": "second"},
            },
        ]
        original = copy.deepcopy(records)
        result = _RP.build_retrieval_envelope(
            records,
            origin="python_hook",
            budget=900,
        )
        self.assertEqual(records, original)
        serialized = _dumps(result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed, result)
        self.assertLessEqual(len(serialized.encode("utf-8")), 900)
        self.assertTrue(result["truncation"]["truncated"])
        self.assertEqual(result["continuation"], {"kind": "narrow_query"})
        self.assertGreater(result["truncation"]["omitted_items"], 0)
        self.assertNotIn(long_key, serialized)
        self.assertNotIn("b" * 20000, serialized)
        self.assertNotIn(long_key, _diagnostics(result))
        self.assertIn(result["trust"], ("untrusted_source",))
        if result["records"]:
            for record in result["records"]:
                self.assertEqual(list(record.keys()), ["kind", "value"])

    def test_extra_record_wrapper_keys_do_not_become_labels(self) -> None:
        records = [
            {
                "kind": "document",
                "value": {"title": "plain"},
                "trust": "trusted",
                "access_mode": "raw",
                "origin": "python_mcp",
            }
        ]
        result = _RP.build_retrieval_envelope(
            records,
            origin="openclaw_tool",
        )
        self.assertEqual(result["trust"], "untrusted_source")
        self.assertEqual(result["access_mode"], "ordinary")
        self.assertEqual(result["origin"], "openclaw_tool")
        self.assertEqual(
            result["records"][0],
            {"kind": "document", "value": {"title": "plain"}},
        )


if __name__ == "__main__":
    unittest.main()
