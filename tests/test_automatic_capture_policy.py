from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR = _ROOT / "plugins" / "remem-memory" / "scripts"
_FIXTURE_PATH = (
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

_HOOK_SPEC = importlib.util.spec_from_file_location(
    "remem_memory_hook",
    _SCRIPTS_DIR / "remem_memory_hook.py",
)
_HOOK = importlib.util.module_from_spec(_HOOK_SPEC)
assert _HOOK_SPEC and _HOOK_SPEC.loader
sys.modules[_HOOK_SPEC.name] = _HOOK
_HOOK_SPEC.loader.exec_module(_HOOK)

import remem_routing as _ROUTING
import auto_memory_hook as _AUTO


def _load_fixture() -> dict:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def _needles(case: dict) -> list[str]:
    values = case.get("needles")
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, str) and item]


def _blob(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=True)


def _assert_needles_absent(test, blob: object, needles: list[str]) -> None:
    rendered = _blob(blob)
    for needle in needles:
        test.assertNotIn(needle, rendered)


def _fixture_case(fixture: dict, case_id: str) -> dict:
    for case in fixture["cases"]:
        if case["id"] == case_id:
            return case
    raise AssertionError(f"missing fixture case {case_id}")


def _auto_config(directory: str, *, cwd: str = "/tmp") -> object:
    return _AUTO.Config(
        cwd=Path(cwd),
        project="remem",
        session_id="sess-a",
        api_url="https://api.remem.io",
        api_key="test-key",
        interval_seconds=1200,
        min_events=4,
        state_path=Path(directory) / "state.json",
        log_path=Path(directory) / "memory.ndjson",
        enabled=True,
        rollup_on_session_end=True,
    )


def _prompt_dependencies(directory: str, api=None):
    return _HOOK.Dependencies(
        api=api if api is not None else FakeAPI(),
        state_dir=Path(directory),
        settings=_HOOK.Settings(mode="auto", sensitivity="balanced"),
    )


class FakeAPI:
    def __init__(self):
        self.ingests = []
        self.queries = []

    def query(self, prompt, namespaces, timeout):
        self.queries.append(
            {
                "prompt": prompt,
                "namespaces": namespaces,
                "timeout": timeout,
            }
        )
        return {"results": []}

    def ingest(self, payload, namespace, timeout, *, idempotency_key=None):
        captured = {
            "payload": payload,
            "namespace": namespace,
            "timeout": timeout,
        }
        if idempotency_key is not None:
            captured["idempotency_key"] = idempotency_key
        self.ingests.append(captured)
        return {"ok": True}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, amount=None):
        del amount
        return json.dumps(self.payload).encode("utf-8")


def routing_config(*, global_routes, revision=4):
    primary = _ROUTING.Connection("primary", "Primary", "default", True)
    return _ROUTING.RoutingConfig(
        schema_version=1,
        revision=revision,
        connections=(primary,),
        global_routes=_ROUTING.RouteLayer(global_routes),
        client_routes={},
        mcp_connections={},
        legacy_namespace_migration_completed=True,
        migration_write_blocked=False,
        deprecations=(),
    )


def routed(config):
    def resolve(behavior, client):
        return (
            config,
            _ROUTING.resolve_routes(
                config,
                behavior=behavior,
                client=client,
            ),
        )

    return resolve


def worker_claim_payload(session_id, events):
    return {
        "session_id": session_id,
        "claim": {
            "schema_version": 1,
            "event_ids": [event["id"] for event in events],
        },
    }


class AutomaticCapturePolicyTests(unittest.TestCase):
    def test_fixture_is_versioned_and_covers_required_categories(self) -> None:
        fixture = _load_fixture()
        self.assertEqual(fixture["version"], "automatic-capture-policy-v1")
        self.assertEqual(
            _POLICY.AUTOMATIC_CAPTURE_POLICY_VERSION,
            fixture["version"],
        )
        categories = {case["category"] for case in fixture["cases"]}
        for required in (
            "explicit-key",
            "private-key",
            "credential-field",
            "high-entropy",
            "off-record-directive",
            "off-record-span",
            "safe",
            "false-positive",
            "nested-metadata",
        ):
            self.assertIn(required, categories)
        self.assertTrue(
            any(case["expect"] == "allow" for case in fixture["cases"])
        )
        self.assertTrue(
            any(case["category"] == "false-positive" for case in fixture["cases"])
        )
        self.assertIn("explicit user-requested raw storage", fixture["scope"]["does_not_apply_to"])
        self.assertIn(
            "not complete protection",
            fixture["scope"]["guarantee"].lower(),
        )

    def test_evaluator_matches_every_fixture_case(self) -> None:
        fixture = _load_fixture()
        evaluate = _POLICY.evaluate_automatic_capture
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                trusted = tuple(case.get("trusted_fragments") or ())
                decision = evaluate(
                    case["payload"],
                    trusted_fragments=trusted,
                )
                self.assertEqual(decision.reason, case["reason"], case["id"])
                if case["expect"] == "allow":
                    self.assertTrue(decision.allowed)
                    self.assertEqual(decision.matched_count, 0)
                else:
                    self.assertFalse(decision.allowed)
                    self.assertGreater(decision.matched_count, 0)
                    dumped = json.dumps(
                        {
                            "reason": decision.reason,
                            "matched_count": decision.matched_count,
                        },
                        ensure_ascii=True,
                    )
                    _assert_needles_absent(self, dumped, _needles(case))

    def test_rejected_fixture_payloads_never_enter_log_or_ingest(self) -> None:
        fixture = _load_fixture()
        for case in fixture["cases"]:
            if case["expect"] != "reject":
                continue
            needles = _needles(case)
            if not needles:
                continue
            with self.subTest(case=case["id"]):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "memory.ndjson"
                    cfg = _AUTO.Config(
                        cwd=Path("/tmp"),
                        project="remem",
                        session_id="sess-a",
                        api_url="https://api.remem.io",
                        api_key="test-key",
                        interval_seconds=1200,
                        min_events=4,
                        state_path=Path(directory) / "state.json",
                        log_path=path,
                        enabled=True,
                        rollup_on_session_end=True,
                    )
                    with mock.patch.object(
                        _AUTO.urllib_request,
                        "urlopen",
                    ) as urlopen:
                        self.assertIsNone(
                            _AUTO._ingest(cfg, case["payload"])
                        )
                        written = _AUTO._append_ndjson(
                            path,
                            {
                                "event": "auto_checkpoint",
                                "payload": case["payload"],
                            },
                        )
                    self.assertFalse(written)
                    self.assertFalse(path.exists())
                    urlopen.assert_not_called()

    def test_background_payload_drops_fixture_secrets_and_off_record(self) -> None:
        fixture = _load_fixture()
        for case in fixture["cases"]:
            if case["expect"] != "reject":
                continue
            payload = case["payload"]
            content = payload.get("content") if isinstance(payload, dict) else None
            if not isinstance(content, str) or not content.strip():
                continue
            needles = _needles(case)
            if not needles:
                continue
            with self.subTest(case=case["id"]):
                minimized = _HOOK._background_payload(
                    {
                        "hook_event_name": "Stop",
                        "session_id": "s1",
                        "cwd": "/tmp/project",
                        "turn_id": "t1",
                        "last_assistant_message": content,
                    },
                    "stop",
                )
                serialized = json.dumps(minimized, ensure_ascii=True)
                _assert_needles_absent(self, serialized, needles)

    def test_legacy_secret_queue_event_is_discarded_without_ingest(self) -> None:
        canary = "vlt_legacyQueueCanary000001"
        event_id = "a" * 32
        target = _ROUTING.RouteTarget("primary", "durable-memory")
        config = routing_config(
            global_routes={"memory": (target,)},
        )
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            _HOOK.StateStore(Path(directory)).save(
                "s1",
                {
                    "current_prompt": "Remember that I prefer concise answers.",
                    "turn_id": "t1",
                    "off_record": False,
                    "off_record_seen": False,
                    "completed_turn_ids": [],
                    "metrics": {"hits": 0, "misses": 0},
                },
            )
            store = _HOOK.BackgroundQueueStore(Path(directory))
            event = {
                "schema_version": 1,
                "id": event_id,
                "client": "codex",
                "behavior": "memory",
                "lifecycle_mode": "stop",
                "connection_id": "primary",
                "namespace": "durable-memory",
                "route_revision": 4,
                "session_id": "s1",
                "payload": {
                    "hook_event_name": "Stop",
                    "session_id": "s1",
                    "cwd": "/tmp/project",
                    "turn_id": "t1",
                    "last_assistant_message": (
                        f"Saved with api_key={canary}."
                    ),
                    "_turn_state": {
                        "current_prompt": (
                            "Remember that I prefer concise answers."
                        ),
                        "turn_id": "t1",
                        "off_record": False,
                        "off_record_seen": False,
                    },
                },
                "off_record_seen": False,
            }
            queues = Path(directory) / "queues"
            queues.mkdir(mode=0o700)
            queue_path = store.path_for("s1")
            queue_path.write_text(
                json.dumps({"events": [event]}, ensure_ascii=True),
                encoding="utf-8",
            )
            os.chmod(queue_path, 0o600)
            self.assertIn(canary, queue_path.read_text(encoding="utf-8"))
            dependencies = _HOOK.Dependencies(
                api=api,
                state_dir=Path(directory),
                background_writes=True,
            )
            object.__setattr__(
                dependencies,
                "routing_resolver",
                routed(config),
            )
            object.__setattr__(
                dependencies,
                "connection_credential_resolver",
                lambda connection: "key",
            )
            _HOOK.handle_event(
                worker_claim_payload("s1", [event]),
                harness="codex",
                mode="worker_drain",
                dependencies=dependencies,
            )
            raw = queue_path.read_text(encoding="utf-8")
            loaded = store.load("s1")

        self.assertEqual(api.ingests, [])
        self.assertEqual(loaded, [])
        self.assertNotIn(canary, raw)
        self.assertNotIn(canary, json.dumps(loaded, ensure_ascii=True))

    def test_legacy_prepared_nested_secret_is_not_ingested_or_retried(
        self,
    ) -> None:
        canary = "vlt_legacyPreparedCanary0001"
        event_id = "b" * 32
        target = _ROUTING.RouteTarget("primary", "session-history")
        config = routing_config(
            global_routes={"sessions": (target,)},
        )
        with tempfile.TemporaryDirectory() as directory:
            engineering = _AUTO._load_config(
                {"cwd": str(directory), "session_id": "s1"},
                connection_id="primary",
            )
            state = _AUTO._default_state("s1")
            state["project"] = engineering.project
            state["events_since_checkpoint"] = 4
            state["recent_events"] = [
                {
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "tool": "Write",
                    "summary": "Write src/a.py",
                    "files": ["src/a.py"],
                    "seq": 4,
                }
            ]
            payload = {
                "title": "secret checkpoint",
                "content": "Automatic milestone checkpoint.",
                "metadata": {
                    "project": engineering.project,
                    "session_id": "s1",
                    "summary": f"Model returned api_key={canary}",
                    "decisions": ["keep going"],
                },
                "source_id": f"auto-checkpoint:{event_id}:milestone",
            }
            digest = _AUTO._stable_digest(payload)
            coverage = {
                "through_seq": 4,
                "events_since": 4,
                "window": 1,
                "digest": digest,
            }
            state["receipts"] = {
                event_id: {
                    "done": [],
                    "started_at": "2026-01-01T00:00:00+00:00",
                    "complete": False,
                    "protocol": 2,
                    "checkpoint_input": coverage,
                }
            }
            _AUTO._save_state(engineering.state_path, state)
            engineering.log_path.parent.mkdir(parents=True, exist_ok=True)
            engineering.log_path.write_text(
                json.dumps(
                    {
                        "event": "auto_checkpoint_prepared",
                        "operation_id": event_id,
                        "payload": payload,
                        "payload_digest": digest,
                        "coverage": {
                            "through_seq": 4,
                            "events_since": 4,
                            "window": 1,
                        },
                    },
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            event = {
                "schema_version": 1,
                "id": event_id,
                "client": "codex",
                "behavior": "sessions",
                "lifecycle_mode": "session_end",
                "connection_id": "primary",
                "namespace": "session-history",
                "route_revision": 4,
                "session_id": "s1",
                "payload": {
                    "hook_event_name": "SessionEnd",
                    "session_id": "s1",
                    "cwd": str(directory),
                },
                "off_record_seen": False,
            }
            store = _HOOK.BackgroundQueueStore(Path(directory))
            store.save("s1", [event])
            queue_path = store.path_for("s1")
            calls = []

            class ScriptedAPI(_AUTO.RememAPI):
                def __init__(self, *args, **kwargs):
                    kwargs["opener"] = opener
                    kwargs["sleep"] = lambda delay: None
                    super().__init__(*args, **kwargs)
                    self._sleep = lambda delay: None

            def opener(request, timeout):
                del timeout
                recorded = {
                    "headers": {
                        key.lower(): value
                        for key, value in request.headers.items()
                    },
                    "body": json.loads(request.data.decode("utf-8")),
                    "raw": request.data.decode("utf-8"),
                }
                calls.append(recorded)
                return FakeResponse({"ok": True})

            dependencies = _HOOK.Dependencies(
                api=None,
                state_dir=Path(directory),
                background_writes=True,
                credential_resolver=lambda: "test-key",
            )
            object.__setattr__(
                dependencies,
                "routing_resolver",
                routed(config),
            )
            object.__setattr__(
                dependencies,
                "connection_credential_resolver",
                lambda connection: "test-key",
            )
            with mock.patch.object(_AUTO, "RememAPI", ScriptedAPI):
                _HOOK.handle_event(
                    worker_claim_payload("s1", [event]),
                    harness="codex",
                    mode="worker_drain",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    worker_claim_payload("s1", [event]),
                    harness="codex",
                    mode="worker_drain",
                    dependencies=dependencies,
                )
            loaded = store.load("s1")
            raw_queue = (
                queue_path.read_text(encoding="utf-8")
                if queue_path.exists()
                else ""
            )
            state_blob = engineering.state_path.read_text(encoding="utf-8")
            log_blob = engineering.log_path.read_text(encoding="utf-8")

        self.assertEqual(calls, [])
        self.assertEqual(loaded, [])
        self.assertNotIn(canary, raw_queue)
        self.assertNotIn(canary, state_blob)
        self.assertNotIn(
            canary,
            json.dumps(json.loads(state_blob).get("receipts") or {}),
        )
        self.assertIn(canary, log_blob)

    def test_allowed_capture_still_retries_then_acknowledges(self) -> None:
        target = _ROUTING.RouteTarget("primary", "durable-memory")
        config = routing_config(global_routes={"memory": (target,)})

        class RecoveringAPI(FakeAPI):
            def __init__(self):
                super().__init__()
                self.fail = True

            def ingest(
                self, payload, namespace, timeout, *, idempotency_key=None
            ):
                super().ingest(
                    payload,
                    namespace,
                    timeout,
                    idempotency_key=idempotency_key,
                )
                if self.fail:
                    raise _HOOK.RememAPIError(
                        "synthetic transient failure",
                        kind="transient",
                    )
                return {"ok": True}

        api = RecoveringAPI()
        with tempfile.TemporaryDirectory() as directory:
            _HOOK.StateStore(Path(directory)).save(
                "s1",
                {
                    "current_prompt": "Remember that I prefer concise answers.",
                    "turn_id": "t1",
                    "off_record": False,
                    "off_record_seen": False,
                    "completed_turn_ids": [],
                    "metrics": {"hits": 0, "misses": 0},
                },
            )
            event = _HOOK._background_event(
                client="codex",
                behavior="memory",
                lifecycle_mode="stop",
                target=target,
                route_revision=4,
                session_id="s1",
                payload=_HOOK._background_payload(
                    {
                        "hook_event_name": "Stop",
                        "session_id": "s1",
                        "cwd": "/tmp/project",
                        "turn_id": "t1",
                        "last_assistant_message": (
                            "I will keep future answers concise."
                        ),
                        "_turn_state": _HOOK.StateStore(
                            Path(directory)
                        ).load("s1"),
                    },
                    "stop",
                ),
                off_record_seen=False,
            )
            store = _HOOK.BackgroundQueueStore(Path(directory))
            store.save("s1", [event])
            dependencies = _HOOK.Dependencies(
                api=api,
                state_dir=Path(directory),
                background_writes=True,
            )
            object.__setattr__(
                dependencies,
                "routing_resolver",
                routed(config),
            )
            object.__setattr__(
                dependencies,
                "connection_credential_resolver",
                lambda connection: "key",
            )
            _HOOK.handle_event(
                worker_claim_payload("s1", [event]),
                harness="codex",
                mode="worker_drain",
                dependencies=dependencies,
            )
            retained = store.load("s1")
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]["delivery_status"], "retry")
            self.assertEqual(retained[0]["failure_reason"], "transient")
            self.assertNotEqual(retained[0]["failure_reason"], "policy")
            api.fail = False
            _HOOK.handle_event(
                worker_claim_payload("s1", retained),
                harness="codex",
                mode="worker_drain",
                dependencies=dependencies,
            )
            self.assertEqual(store.load("s1"), [])
            self.assertEqual(len(api.ingests), 2)
            content = api.ingests[-1]["payload"]["content"]
            self.assertIn("prefer concise answers", content)

    def test_propagate_ingest_raises_policy_rejection_not_request(self) -> None:
        canary = "vlt_propagateCanary00000001"
        with tempfile.TemporaryDirectory() as directory:
            cfg = _AUTO.Config(
                cwd=Path(directory),
                project="remem",
                session_id="sess-a",
                api_url="https://api.remem.io",
                api_key="test-key",
                interval_seconds=1200,
                min_events=4,
                state_path=Path(directory) / "state.json",
                log_path=Path(directory) / "memory.ndjson",
                enabled=True,
                rollup_on_session_end=True,
                request_identity="c" * 32,
                propagate_delivery_failure=True,
            )
            with self.assertRaises(_AUTO.EngineeringWriteRejected):
                _AUTO._ingest(
                    cfg,
                    {"content": f"api_key={canary}"},
                )

    def test_user_prompt_state_save_drops_malicious_identifier(self) -> None:
        fixture = _load_fixture()
        secret_case = _fixture_case(fixture, "identifier-secret")
        allowed_case = _fixture_case(fixture, "identifier-allowed")
        canary = secret_case["needles"][0]
        allowed_turn = allowed_case["payload"]["turn_id"]
        prompt = "Remember that I prefer concise answers."
        with tempfile.TemporaryDirectory() as directory:
            _HOOK.handle_event(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "session_id": "s1",
                    "turn_id": canary,
                    "cwd": "/tmp/project",
                    "prompt": prompt,
                },
                harness="codex",
                mode="user_prompt_submit",
                dependencies=_prompt_dependencies(directory),
            )
            store = _HOOK.StateStore(Path(directory))
            secret_path = store.path_for("s1")
            secret_raw = secret_path.read_text(encoding="utf-8")
            secret_state = store.load("s1")
            _HOOK.handle_event(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "session_id": "s2",
                    "turn_id": allowed_turn,
                    "cwd": "/tmp/project",
                    "prompt": prompt,
                },
                harness="codex",
                mode="user_prompt_submit",
                dependencies=_prompt_dependencies(directory),
            )
            allowed_path = store.path_for("s2")
            allowed_raw = allowed_path.read_text(encoding="utf-8")
            allowed_state = store.load("s2")

        _assert_needles_absent(self, secret_raw, [canary])
        self.assertNotEqual(secret_state["turn_id"], canary)
        self.assertNotIn(canary, secret_state["turn_id"])
        self.assertIn(allowed_turn, allowed_raw)
        self.assertEqual(allowed_state["turn_id"], allowed_turn)
        _assert_needles_absent(self, allowed_raw, [canary])

    def test_legacy_completed_turn_ids_are_dropped_on_next_save(self) -> None:
        fixture = _load_fixture()
        canary = _fixture_case(fixture, "identifier-secret")["needles"][0]
        with tempfile.TemporaryDirectory() as directory:
            store = _HOOK.StateStore(Path(directory))
            store.save(
                "s1",
                {
                    "current_prompt": "Remember that I prefer concise answers.",
                    "turn_id": "t-safe",
                    "off_record": False,
                    "off_record_seen": False,
                    "completed_turn_ids": ["t-safe"],
                    "metrics": {"hits": 0, "misses": 0},
                },
            )
            path = store.path_for("s1")
            parsed = json.loads(path.read_text(encoding="utf-8"))
            parsed["completed_turn_ids"] = [canary, "t-safe"]
            parsed["turn_id"] = canary
            path.write_text(
                json.dumps(parsed, ensure_ascii=True, separators=(",", ":")),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            self.assertIn(canary, path.read_text(encoding="utf-8"))
            _HOOK.handle_event(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "session_id": "s1",
                    "turn_id": "t-next",
                    "cwd": "/tmp/project",
                    "prompt": "Thanks",
                },
                harness="codex",
                mode="user_prompt_submit",
                dependencies=_prompt_dependencies(directory),
            )
            raw = path.read_text(encoding="utf-8")
            state = store.load("s1")

        _assert_needles_absent(self, raw, [canary])
        self.assertNotIn(canary, state["turn_id"])
        self.assertNotIn(canary, state["completed_turn_ids"])
        self.assertEqual(state["turn_id"], "t-next")
        self.assertIn("t-safe", state["completed_turn_ids"])

    def test_engineering_state_save_drops_off_record_identifiers(self) -> None:
        fixture = _load_fixture()
        canary = _fixture_case(fixture, "off-record-slash-command")["needles"][0]
        poison_path = f"/tmp/foo /remem off-record {canary}.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = _AUTO._default_state("sess-a")
            state["project"] = "off the record"
            state["session_id"] = f"sess /remem off-record {canary}"
            state["transcript_path"] = poison_path
            _AUTO._save_state(path, state)
            raw = path.read_text(encoding="utf-8")
            loaded = json.loads(raw)

        _assert_needles_absent(self, raw, [canary, "/remem off-record"])
        self.assertNotEqual(loaded["project"], "off the record")
        self.assertNotIn("/remem off-record", loaded["session_id"])
        self.assertEqual(loaded["transcript_path"], "")

    def test_rollup_legacy_off_record_never_reaches_provider_or_fallback(
        self,
    ) -> None:
        fixture = _load_fixture()
        rejected = _fixture_case(fixture, "nested-off-record-summary")
        allowed = _fixture_case(fixture, "safe-checkpoint")
        needles = _needles(rejected)
        rejected_row = {
            "event": "auto_checkpoint",
            "payload": {
                "title": "secret checkpoint",
                "content": (
                    "## Summary\nOff the record: STARLING-PRIVATE-CONTEXT"
                ),
                "metadata": {
                    "project": "remem",
                    "session_id": "sess-a",
                    **rejected["payload"]["metadata"],
                },
            },
        }
        allowed_row = {
            "event": "auto_checkpoint",
            "payload": {
                **allowed["payload"],
                "metadata": {
                    "project": "remem",
                    "session_id": "sess-a",
                    **allowed["payload"]["metadata"],
                },
            },
        }
        provider_prompts: list[str] = []

        def fake_openai(prompt, *, model, max_tokens, timeout):
            del model, max_tokens, timeout
            provider_prompts.append(prompt)
            return json.dumps(
                {
                    "summary": "Safe rollup of allowed checkpoints.",
                    "decisions": ["ship v1"],
                    "open_questions": [],
                    "next_actions": [],
                }
            )

        with tempfile.TemporaryDirectory() as directory:
            cfg = _auto_config(directory, cwd="/tmp")
            with mock.patch.object(_AUTO, "_llm_enabled", return_value=True):
                with mock.patch.object(
                    _AUTO,
                    "_select_llm_provider",
                    return_value="openai",
                ):
                    with mock.patch.object(
                        _AUTO,
                        "_llm_model_for",
                        return_value="test-model",
                    ):
                        with mock.patch.object(
                            _AUTO,
                            "_call_openai",
                            side_effect=fake_openai,
                        ) as call_openai:
                            mixed = _AUTO._build_rollup_payload(
                                cfg,
                                [rejected_row, allowed_row],
                            )
                            rejected_only = _AUTO._build_rollup_payload(
                                cfg,
                                [rejected_row],
                            )
                            markdown_only = _AUTO._build_rollup_payload(
                                cfg,
                                [
                                    {
                                        "event": "auto_checkpoint",
                                        "payload": {
                                            "title": "legacy markdown",
                                            "content": (
                                                "## Summary\nOff the record: "
                                                "STARLING-PRIVATE-CONTEXT"
                                            ),
                                            "metadata": {
                                                "project": "remem",
                                                "session_id": "sess-a",
                                            },
                                        },
                                    }
                                ],
                            )

        for blob in (
            *provider_prompts,
            mixed,
            rejected_only,
            markdown_only,
            str(call_openai.call_args_list),
        ):
            _assert_needles_absent(self, blob, needles)
            self.assertNotIn("Off the record", _blob(blob))
        self.assertGreaterEqual(call_openai.call_count, 1)
        self.assertIn("ship v1", mixed["metadata"]["decisions"])
        self.assertNotIn("do not store this", mixed["metadata"]["decisions"])
        self.assertNotIn("STARLING-PRIVATE-CONTEXT", rejected_only["content"])
        self.assertNotIn("STARLING-PRIVATE-CONTEXT", markdown_only["content"])

    def test_cwd_overlap_does_not_mask_ingest_or_rollup_provider_prompt(
        self,
    ) -> None:
        fixture = _load_fixture()
        cases = (
            ("/remem", "trusted-cwd-overlaps-slash-command"),
            ("/", "trusted-root-overlaps-slash-command"),
        )
        provider_prompts: list[str] = []

        def fake_openai(prompt, *, model, max_tokens, timeout):
            del model, max_tokens, timeout
            provider_prompts.append(prompt)
            return json.dumps(
                {
                    "summary": "should not see rejected source",
                    "decisions": [],
                    "open_questions": [],
                    "next_actions": [],
                }
            )

        for cwd, case_id in cases:
            case = _fixture_case(fixture, case_id)
            needles = _needles(case)
            with self.subTest(cwd=cwd, case=case_id):
                with tempfile.TemporaryDirectory() as directory:
                    cfg = _auto_config(directory, cwd=cwd)
                    with mock.patch.object(
                        _AUTO.urllib_request,
                        "urlopen",
                    ) as urlopen:
                        self.assertIsNone(
                            _AUTO._ingest(cfg, case["payload"])
                        )
                    urlopen.assert_not_called()
                    with mock.patch.object(
                        _AUTO,
                        "_llm_enabled",
                        return_value=True,
                    ):
                        with mock.patch.object(
                            _AUTO,
                            "_select_llm_provider",
                            return_value="openai",
                        ):
                            with mock.patch.object(
                                _AUTO,
                                "_llm_model_for",
                                return_value="test-model",
                            ):
                                with mock.patch.object(
                                    _AUTO,
                                    "_call_openai",
                                    side_effect=fake_openai,
                                ) as call_openai:
                                    payload = _AUTO._build_rollup_payload(
                                        cfg,
                                        [
                                            {
                                                "event": "auto_checkpoint",
                                                "payload": {
                                                    "title": "overlap",
                                                    "content": "safe body",
                                                    "metadata": {
                                                        "project": "remem",
                                                        "session_id": "sess-a",
                                                        "summary": case[
                                                            "payload"
                                                        ].get(
                                                            "content",
                                                            "",
                                                        )
                                                        or case["payload"]
                                                        .get("metadata", {})
                                                        .get("summary", ""),
                                                    },
                                                },
                                            }
                                        ],
                                    )
                    _assert_needles_absent(self, payload, needles)
                    _assert_needles_absent(
                        self,
                        str(call_openai.call_args_list),
                        needles,
                    )
                    for prompt in provider_prompts:
                        _assert_needles_absent(self, prompt, needles)

    def test_checkpoint_provider_prompt_drops_assistant_off_record(
        self,
    ) -> None:
        fixture = _load_fixture()
        canary = _fixture_case(fixture, "off-record-slash-command")["needles"][0]
        excerpt = (
            "User: continue the checkpoint.\n"
            f"Assistant: /remem off-record evaluate {canary}."
        )
        provider_prompts: list[str] = []

        def fake_openai(prompt, *, model, max_tokens, timeout):
            del model, max_tokens, timeout
            provider_prompts.append(prompt)
            return json.dumps(
                {
                    "summary": "leaked assistant directive",
                    "decisions": [],
                    "open_questions": [],
                    "next_actions": [],
                }
            )

        with tempfile.TemporaryDirectory() as directory:
            cfg = _auto_config(directory, cwd="/tmp")
            with mock.patch.object(_AUTO, "_llm_enabled", return_value=True):
                with mock.patch.object(
                    _AUTO,
                    "_read_transcript_excerpt",
                    return_value=excerpt,
                ):
                    with mock.patch.object(
                        _AUTO,
                        "_select_llm_provider",
                        return_value="openai",
                    ):
                        with mock.patch.object(
                            _AUTO,
                            "_llm_model_for",
                            return_value="test-model",
                        ):
                            with mock.patch.object(
                                _AUTO,
                                "_call_openai",
                                side_effect=fake_openai,
                            ) as call_openai:
                                with mock.patch.object(
                                    _AUTO,
                                    "_git_branch",
                                    return_value=None,
                                ):
                                    payload = _AUTO._build_checkpoint_payload(
                                        config=cfg,
                                        kind="interval",
                                        hook_event="PostToolUse",
                                        recent_events=[
                                            {
                                                "summary": "Write src/main.py",
                                                "files": ["src/main.py"],
                                            }
                                        ],
                                        events_since_checkpoint=4,
                                        transcript_path="/tmp/transcript.jsonl",
                                    )

        call_openai.assert_not_called()
        self.assertEqual(provider_prompts, [])
        _assert_needles_absent(self, payload, [canary])
        self.assertNotIn("/remem off-record", _blob(payload))


if __name__ == "__main__":
    unittest.main()
