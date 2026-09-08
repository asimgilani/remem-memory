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
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(", ", ": "),
    )


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
        serialization = fixture["serialization"]
        self.assertEqual(serialization["ensure_ascii"], True)
        self.assertEqual(serialization["allow_nan"], False)
        self.assertEqual(serialization["separators"], [", ", ": "])
        self.assertEqual(serialization["encoding"], "utf-8")
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
            "origin-list-rejected",
            "origin-object-rejected",
            "origin-boolean-rejected",
            "kind-list-rejected",
            "kind-object-rejected",
            "empty-exact-budget",
            "empty-one-byte-less",
            "clip-escaped-quote",
            "clip-escaped-unicode-exact",
            "clip-escaped-unicode-minus-one",
            "omit-oversized-key-keeps-neighbor",
            "omit-list-members",
            "omit-records-omitted-items-digit-boundary",
            "omit-records-omitted-items-digit-boundary-minus-one",
            "scan-before-clip-secret-prefix",
            "scan-before-clip-off-record-prefix",
            "mixed-redaction-and-string-clip",
            "declared-high-entropy-uuid-locator-kept-identical-prose-redacted",
            "malformed-locator-rejected",
            "uppercase-locator-rejected",
            "empty-locator-string-rejected",
            "truncated-locator-rejected",
            "secret-bearing-locator-rejected",
            "extra-id-key-locator-rejected",
            "related-fact-id-at-record-locator-rejected",
            "generated-turn-id-not-a-locator",
            "null-locator-object-absent",
            "null-fact-id-locator-rejected",
            "null-source-document-id-locator-rejected",
            "null-related-fact-id-locator-rejected",
            "incomplete-record-locator-rejected",
            "required-locator-set-kept-with-null-value-and-no-locator-neighbor",
            "sensitive-source-document-id-locator-denied-keeps-neighbor",
            "sensitive-related-fact-id-locator-denied-keeps-parent-locators",
            "off-record-after-long-prefix-drops-record-and-locators",
            "nested-relationship-locators-stay-with-relationship",
        ):
            self.assertIn(required, categories)
        self.assertEqual(
            fixture["errors"]["invalid_locators"],
            "invalid retrieval locators",
        )
        self.assertIn(
            "shared-references-checked-in-each-field-context",
            fixture["python_only"],
        )
        self.assertIn(
            "locator-exact-budget-and-one-byte-short",
            fixture["python_only"],
        )
        self.assertIn("locator-all-or-nothing-ids", fixture["python_only"])
        self.assertIn(
            "relationship-locator-association-under-truncation",
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
                self.assertEqual(result, _call(case))
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
                encoded = serialized.encode("utf-8")
                self.assertLessEqual(len(encoded), case["budget"])
                if "serialized_utf8_bytes" in case:
                    self.assertEqual(len(encoded), case["serialized_utf8_bytes"])
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

    def test_wrapper_id_keys_are_not_locators(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        related_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        records = [
            {
                "kind": "fact",
                "value": {"title": "plain"},
                "id": fact_id,
                "source_document_id": document_id,
                "related_fact_id": related_id,
                "entity_id": related_id,
                "trust": "trusted",
                "access_mode": "raw",
            }
        ]
        original = copy.deepcopy(records)
        result = _RP.build_retrieval_envelope(
            records,
            origin="openclaw_tool",
        )
        self.assertEqual(records, original)
        self.assertEqual(result["trust"], "untrusted_source")
        self.assertEqual(result["access_mode"], "ordinary")
        self.assertEqual(
            result["records"][0],
            {"kind": "fact", "value": {"title": "plain"}},
        )
        serialized = _dumps(result)
        self.assertNotIn(fact_id, serialized)
        self.assertNotIn(document_id, serialized)
        self.assertNotIn(related_id, serialized)
        self.assertNotIn("locators", serialized)

    def test_empty_locator_object_is_absent(self) -> None:
        records = [
            {
                "kind": "fact",
                "value": {"title": "plain"},
                "locators": {},
            }
        ]
        result = _RP.build_retrieval_envelope(
            records,
            origin="python_hook",
        )
        self.assertEqual(
            result["records"][0],
            {"kind": "fact", "value": {"title": "plain"}},
        )
        self.assertNotIn("locators", _dumps(result["records"][0]))

    def test_fact_id_on_relationship_locator_is_rejected(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        records = [
            {
                "kind": "fact",
                "value": {"content": "REL-ROLE-CANARY"},
                "relationships": [
                    {
                        "value": {"rel_type": "updates"},
                        "locators": {"fact_id": fact_id},
                    }
                ],
            }
        ]
        original = copy.deepcopy(records)
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(records, origin="python_hook")
        message = str(ctx.exception)
        self.assertEqual(message, "invalid retrieval locators")
        self.assertNotIn(fact_id, message)
        self.assertNotIn("REL-ROLE-CANARY", message)
        self.assertEqual(records, original)

    def test_locator_list_is_rejected_without_reflecting_content(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        records = [
            {
                "kind": "fact",
                "value": {"content": "LIST-LOCATOR-CANARY"},
                "locators": [fact_id],
            }
        ]
        with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
            _RP.build_retrieval_envelope(records, origin="python_cli")
        message = str(ctx.exception)
        self.assertEqual(message, "invalid retrieval locators")
        self.assertNotIn(fact_id, message)
        self.assertNotIn("LIST-LOCATOR-CANARY", message)

    def test_locator_exact_budget_and_one_byte_short(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        records = [
            {
                "kind": "fact",
                "value": {"title": "alpha-neighbor", "body": "bravo"},
                "locators": {
                    "fact_id": fact_id,
                    "source_document_id": document_id,
                },
            }
        ]
        full = _RP.build_retrieval_envelope(records, origin="python_cli")
        size = _utf8_size(full)
        exact = _RP.build_retrieval_envelope(
            records,
            origin="python_cli",
            budget=size,
        )
        self.assertEqual(exact, full)
        self.assertFalse(exact["truncation"]["truncated"])
        self.assertEqual(
            exact["records"][0]["locators"],
            {"fact_id": fact_id, "source_document_id": document_id},
        )
        tight = _RP.build_retrieval_envelope(
            records,
            origin="python_cli",
            budget=size - 1,
        )
        self.assertTrue(tight["truncation"]["truncated"])
        self.assertEqual(tight["continuation"], {"kind": "narrow_query"})
        self.assertLessEqual(_utf8_size(tight), size - 1)
        json.loads(_dumps(tight))
        self._assert_atomic_locators(
            tight,
            {"fact_id": fact_id, "source_document_id": document_id},
        )
        self.assertNotIn("alpha-neighbor", _diagnostics(tight))

    def test_locator_all_or_nothing_ids(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        required = {"fact_id": fact_id, "source_document_id": document_id}
        records = [
            {
                "kind": "fact",
                "value": {"body": "n" * 180},
                "locators": required,
            }
        ]
        full = _RP.build_retrieval_envelope(records, origin="python_hook")
        full_size = _utf8_size(full)
        for budget in range(1, full_size + 1):
            try:
                result = _RP.build_retrieval_envelope(
                    records,
                    origin="python_hook",
                    budget=budget,
                )
            except _RP.RetrievalEnvelopeError as exc:
                self.assertEqual(
                    str(exc),
                    "retrieval budget below minimum envelope",
                )
                continue
            self.assertLessEqual(_utf8_size(result), budget)
            self._assert_atomic_locators(result, required)

    def test_relationship_locator_association_under_truncation(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        related_a = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        related_b = "0fedcba9-8765-4321-0fed-cba987654321"
        first_content = "first-related-" + ("c" * 360)
        records = [
            {
                "kind": "fact",
                "value": {"content": "parent fact"},
                "locators": {
                    "fact_id": fact_id,
                    "source_document_id": document_id,
                },
                "relationships": [
                    {
                        "value": {
                            "rel_type": "updates",
                            "related_fact_content": first_content,
                        },
                        "locators": {"related_fact_id": related_a},
                    },
                    {
                        "value": {
                            "rel_type": "extends",
                            "related_fact_content": "second related",
                        },
                        "locators": {"related_fact_id": related_b},
                    },
                ],
            }
        ]
        full = _RP.build_retrieval_envelope(records, origin="python_hook")
        full_size = _utf8_size(full)
        required = {"fact_id": fact_id, "source_document_id": document_id}
        for budget in range(1, full_size + 1):
            try:
                result = _RP.build_retrieval_envelope(
                    records,
                    origin="python_hook",
                    budget=budget,
                )
            except _RP.RetrievalEnvelopeError as exc:
                self.assertEqual(
                    str(exc),
                    "retrieval budget below minimum envelope",
                )
                continue
            self.assertLessEqual(_utf8_size(result), budget)
            self._assert_atomic_locators(result, required)
            serialized = _dumps(result)
            for record in result["records"]:
                relationships = record.get("relationships") or []
                ids = []
                for relationship in relationships:
                    locators = relationship.get("locators")
                    self.assertIsInstance(locators, dict)
                    self.assertEqual(set(locators), {"related_fact_id"})
                    related_id = locators["related_fact_id"]
                    self.assertIn(related_id, {related_a, related_b})
                    self.assertRegex(
                        related_id,
                        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    )
                    ids.append(related_id)
                    value = relationship.get("value")
                    content = ""
                    if type(value) is dict:
                        raw = value.get("related_fact_content")
                        if type(raw) is str:
                            content = raw
                    if related_id == related_a:
                        self.assertNotEqual(content, "second related")
                    if related_id == related_b:
                        self.assertNotIn("first-related-", content)
                if related_a in ids and related_b in ids:
                    self.assertEqual(ids, [related_a, related_b])
                if related_a not in ids:
                    self.assertNotIn(related_a, serialized)
                if related_b not in ids:
                    self.assertNotIn(related_b, serialized)

    def test_null_required_locator_roles_are_rejected(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        related_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        cases = [
            (
                "NULL-FACT-CANARY",
                {
                    "kind": "fact",
                    "value": {"content": "NULL-FACT-CANARY", "valid_until": None},
                    "locators": {
                        "fact_id": None,
                        "source_document_id": document_id,
                    },
                },
            ),
            (
                "NULL-DOC-CANARY",
                {
                    "kind": "fact",
                    "value": {"content": "NULL-DOC-CANARY", "valid_until": None},
                    "locators": {
                        "fact_id": fact_id,
                        "source_document_id": None,
                    },
                },
            ),
            (
                "NULL-REL-CANARY",
                {
                    "kind": "fact",
                    "value": {"content": "NULL-REL-CANARY", "valid_until": None},
                    "locators": {
                        "fact_id": fact_id,
                        "source_document_id": document_id,
                    },
                    "relationships": [
                        {
                            "value": {"rel_type": "updates"},
                            "locators": {"related_fact_id": None},
                        }
                    ],
                },
            ),
        ]
        for canary, record in cases:
            with self.subTest(canary=canary):
                records = [record]
                original = copy.deepcopy(records)
                with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
                    _RP.build_retrieval_envelope(records, origin="python_hook")
                message = str(ctx.exception)
                self.assertEqual(message, "invalid retrieval locators")
                self.assertNotIn(fact_id, message)
                self.assertNotIn(document_id, message)
                self.assertNotIn(related_id, message)
                self.assertNotIn(canary, message)
                self.assertEqual(records, original)

    def test_incomplete_required_locator_set_is_rejected(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        for locators, canary in (
            ({"fact_id": fact_id}, "INCOMPLETE-FACT-CANARY"),
            ({"source_document_id": document_id}, "INCOMPLETE-DOC-CANARY"),
        ):
            with self.subTest(canary=canary):
                records = [
                    {
                        "kind": "fact",
                        "value": {"content": canary},
                        "locators": locators,
                    }
                ]
                original = copy.deepcopy(records)
                with self.assertRaises(_RP.RetrievalEnvelopeError) as ctx:
                    _RP.build_retrieval_envelope(records, origin="python_cli")
                message = str(ctx.exception)
                self.assertEqual(message, "invalid retrieval locators")
                self.assertNotIn(fact_id, message)
                self.assertNotIn(document_id, message)
                self.assertNotIn(canary, message)
                self.assertEqual(records, original)

    def test_no_locator_paths_remain_optional(self) -> None:
        variants: list[object] = ["missing", None, {}]
        for locators_key in variants:
            with self.subTest(locators=locators_key):
                record: dict[str, object] = {
                    "kind": "fact",
                    "value": {"title": "plain", "valid_until": None},
                }
                if locators_key != "missing":
                    record["locators"] = locators_key
                records = [record]
                original = copy.deepcopy(records)
                result = _RP.build_retrieval_envelope(
                    records,
                    origin="python_hook",
                )
                self.assertEqual(records, original)
                self.assertEqual(
                    result["records"][0],
                    {
                        "kind": "fact",
                        "value": {"title": "plain", "valid_until": None},
                    },
                )
                self.assertNotIn("locators", _dumps(result["records"][0]))

    def test_sensitive_fields_apply_to_declared_locator_roles(self) -> None:
        fact_id = "01234567-89ab-4def-8123-456789abcdef"
        document_id = "fedcba98-7654-3210-fedc-ba9876543210"
        value_document_id = "11111111-2222-3333-4444-555555555555"
        related_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        value_related_id = "99999999-8888-7777-6666-555555555555"
        denied_top = _RP.build_retrieval_envelope(
            [
                {
                    "kind": "fact",
                    "value": {
                        "title": "denied-locator-owner",
                        "content": "DENIED-TOP-CANARY",
                    },
                    "locators": {
                        "fact_id": fact_id,
                        "source_document_id": document_id,
                    },
                },
                {
                    "kind": "fact",
                    "value": {
                        "title": "safe neighbor",
                        "source_document_id": value_document_id,
                        "notes": "kept notes",
                    },
                },
            ],
            origin="python_hook",
            sensitive_fields=["source-document-id"],
        )
        serialized_top = _dumps(denied_top)
        self.assertEqual(denied_top["trust"], "untrusted_source")
        self.assertEqual(denied_top["access_mode"], "ordinary")
        self.assertEqual(
            denied_top["records"],
            [
                {
                    "kind": "fact",
                    "value": {"title": "safe neighbor", "notes": "kept notes"},
                }
            ],
        )
        self.assertEqual(
            denied_top["redaction"],
            {"fields": 2, "values": 0, "records": 0},
        )
        self.assertNotIn(fact_id, serialized_top)
        self.assertNotIn(document_id, serialized_top)
        self.assertNotIn(value_document_id, serialized_top)
        self.assertNotIn("DENIED-TOP-CANARY", serialized_top)
        self.assertNotIn("denied-locator-owner", serialized_top)
        self.assertNotIn(fact_id, _diagnostics(denied_top))
        self.assertNotIn(document_id, _diagnostics(denied_top))

        denied_rel = _RP.build_retrieval_envelope(
            [
                {
                    "kind": "fact",
                    "value": {
                        "content": "parent fact",
                        "related_fact_id": value_related_id,
                        "title": "kept parent",
                    },
                    "locators": {
                        "fact_id": fact_id,
                        "source_document_id": document_id,
                    },
                    "relationships": [
                        {
                            "value": {
                                "rel_type": "updates",
                                "related_fact_content": "DENIED-REL-CANARY",
                            },
                            "locators": {"related_fact_id": related_id},
                        },
                        {
                            "value": {
                                "rel_type": "extends",
                                "related_fact_content": "kept related",
                            },
                        },
                    ],
                }
            ],
            origin="python_cli",
            sensitive_fields=["related_fact_id"],
        )
        serialized_rel = _dumps(denied_rel)
        self.assertEqual(denied_rel["trust"], "untrusted_source")
        self.assertEqual(denied_rel["access_mode"], "ordinary")
        self.assertEqual(
            denied_rel["records"][0]["locators"],
            {"fact_id": fact_id, "source_document_id": document_id},
        )
        self.assertEqual(
            denied_rel["records"][0]["value"],
            {"content": "parent fact", "title": "kept parent"},
        )
        self.assertEqual(
            denied_rel["records"][0]["relationships"],
            [
                {
                    "value": {
                        "rel_type": "extends",
                        "related_fact_content": "kept related",
                    }
                }
            ],
        )
        self.assertEqual(
            denied_rel["redaction"],
            {"fields": 2, "values": 0, "records": 0},
        )
        self.assertNotIn(related_id, serialized_rel)
        self.assertNotIn(value_related_id, serialized_rel)
        self.assertNotIn("DENIED-REL-CANARY", serialized_rel)
        self.assertIn(fact_id, serialized_rel)
        self.assertIn(document_id, serialized_rel)
        self.assertNotIn(related_id, _diagnostics(denied_rel))
        self.assertNotIn(value_related_id, _diagnostics(denied_rel))

    def _assert_atomic_locators(
        self,
        result: dict,
        required: dict[str, str],
    ) -> None:
        serialized = _dumps(result)
        for record in result["records"]:
            locators = record.get("locators")
            self.assertEqual(locators, required)
            for value in locators.values():
                self.assertRegex(
                    value,
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                )
                self.assertNotEqual(value, "")
        if not result["records"]:
            for value in required.values():
                self.assertNotIn(value, serialized)


if __name__ == "__main__":
    unittest.main()
