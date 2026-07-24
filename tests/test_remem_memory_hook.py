import contextlib
import ctypes
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "remem-memory"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS_DIR))

_HOOK_SPEC = importlib.util.spec_from_file_location(
    "remem_memory_hook", _SCRIPTS_DIR / "remem_memory_hook.py"
)
_HOOK = importlib.util.module_from_spec(_HOOK_SPEC)
assert _HOOK_SPEC and _HOOK_SPEC.loader
sys.modules[_HOOK_SPEC.name] = _HOOK
_HOOK_SPEC.loader.exec_module(_HOOK)

_API_SPEC = importlib.util.spec_from_file_location(
    "remem_api", _SCRIPTS_DIR / "remem_api.py"
)
_API = importlib.util.module_from_spec(_API_SPEC)
assert _API_SPEC and _API_SPEC.loader
sys.modules[_API_SPEC.name] = _API
_API_SPEC.loader.exec_module(_API)


class FakeAPI:
    def __init__(self, query_response=None):
        self.query_response = (
            query_response if query_response is not None else {"results": []}
        )
        self.queries = []
        self.ingests = []

    def query(self, prompt, namespaces, timeout):
        self.queries.append(
            {
                "prompt": prompt,
                "namespaces": namespaces,
                "timeout": timeout,
            }
        )
        return self.query_response

    def ingest(self, payload, namespace, timeout):
        self.ingests.append(
            {
                "payload": payload,
                "namespace": namespace,
                "timeout": timeout,
            }
        )
        return {"ok": True}


class FailingAPI(FakeAPI):
    def __init__(self, message):
        super().__init__()
        self.message = message

    def query(self, prompt, namespaces, timeout):
        raise RuntimeError(self.message)


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


class FakeCFunction:
    def __init__(self, implementation):
        self.implementation = implementation
        self.argtypes = None
        self.restype = None
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.implementation(*args)


class FakeSecurityFramework:
    def __init__(
        self,
        *,
        finds=(),
        add_status=0,
        modify_status=0,
        interaction_allowed=True,
        interaction_set_statuses=(),
    ):
        self.finds = list(finds)
        self.add_status = add_status
        self.modify_status = modify_status
        self.interaction_allowed = interaction_allowed
        self.interaction_set_statuses = list(interaction_set_statuses)
        self.interaction_events = []
        self.buffers = []
        self.freed = []
        self.added = []
        self.modified = []
        self.SecKeychainGetUserInteractionAllowed = FakeCFunction(
            self._get_interaction
        )
        self.SecKeychainSetUserInteractionAllowed = FakeCFunction(
            self._set_interaction
        )
        self.SecKeychainFindGenericPassword = FakeCFunction(self._find)
        self.SecKeychainAddGenericPassword = FakeCFunction(self._add)
        self.SecKeychainItemModifyContent = FakeCFunction(self._modify)
        self.SecKeychainItemFreeContent = FakeCFunction(self._free)

    def _get_interaction(self, allowed):
        self.interaction_events.append(("get", self.interaction_allowed))
        allowed._obj.value = int(self.interaction_allowed)
        return 0

    def _set_interaction(self, allowed):
        requested = bool(
            allowed.value if hasattr(allowed, "value") else allowed
        )
        self.interaction_events.append(("set", requested))
        status = (
            self.interaction_set_statuses.pop(0)
            if self.interaction_set_statuses
            else 0
        )
        if status == 0:
            self.interaction_allowed = requested
        return status

    def _find(
        self,
        keychain,
        service_length,
        service,
        account_length,
        account,
        password_length,
        password_data,
        item,
    ):
        del keychain
        self.interaction_events.append(
            ("find", self.interaction_allowed)
        )
        status, value, item_value = self.finds.pop(0)
        if status == 0:
            encoded = value.encode("utf-8")
            buffer = ctypes.create_string_buffer(encoded)
            self.buffers.append(buffer)
            password_length._obj.value = len(encoded)
            password_data._obj.value = ctypes.addressof(buffer)
            item._obj.value = item_value
        return status

    def _add(
        self,
        keychain,
        service_length,
        service,
        account_length,
        account,
        password_length,
        password_data,
        item,
    ):
        del keychain
        self.added.append(
            (
                ctypes.string_at(service, service_length).decode("utf-8"),
                ctypes.string_at(account, account_length).decode("utf-8"),
                ctypes.string_at(password_data, password_length).decode("utf-8"),
            )
        )
        if item is not None:
            item._obj.value = 902
        return self.add_status

    def _modify(self, item, attributes, password_length, password_data):
        del attributes
        self.modified.append(
            (
                item.value,
                ctypes.string_at(password_data, password_length).decode("utf-8"),
            )
        )
        return self.modify_status

    def _free(self, attributes, password_data):
        del attributes
        self.freed.append(password_data.value)
        return 0


class FakeCoreFoundation:
    def __init__(self):
        self.released = []
        self.CFRelease = FakeCFunction(self._release)

    def _release(self, item):
        self.released.append(item.value)


class FakeKeychain:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.reads = []
        self.writes = []

    def read(self, service, account=None):
        self.reads.append((service, account))
        return self.values.get((service, account))

    def write(self, service, account, value):
        self.writes.append((service, account, value))
        self.values[(service, account)] = value


def prompt_payload(prompt, *, session_id="s1", turn_id="t1"):
    return {
        "hook_event_name": "UserPromptSubmit",
        "session_id": session_id,
        "turn_id": turn_id,
        "cwd": "/tmp/project",
        "prompt": prompt,
    }


def stop_payload(*, session_id="s1", turn_id="t1", assistant=None):
    return {
        "hook_event_name": "Stop",
        "session_id": session_id,
        "turn_id": turn_id,
        "cwd": "/tmp/project",
        "stop_hook_active": False,
        "last_assistant_message": (
            assistant
            if assistant is not None
            else "I will keep future answers concise."
        ),
    }


class RememAPITests(unittest.TestCase):
    def test_query_uses_fixed_endpoint_headers_and_bounded_request(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse({"results": []})

        api = _API.RememAPI(
            "https://api.remem.io/",
            "vlt_test-credential-not-real",
            opener=opener,
        )

        response = api.query("history", ["*"], timeout=2.0)

        request = captured["request"]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(response, {"results": []})
        self.assertEqual(request.full_url, "https://api.remem.io/v1/query")
        self.assertEqual(body["query"], "history")
        self.assertEqual(body["namespaces"], ["*"])
        self.assertEqual(body["mode"], "fast")
        self.assertEqual(body["max_results"], 4)
        self.assertIs(body["include_facts"], True)
        self.assertEqual(captured["timeout"], 2.0)
        headers = {key.lower(): value for key, value in request.headers.items()}
        self.assertEqual(
            headers["authorization"], "Bearer vlt_test-credential-not-real"
        )
        self.assertEqual(
            headers["x-api-key"], "vlt_test-credential-not-real"
        )

    def test_ingest_adds_namespace_only_when_configured(self) -> None:
        bodies = []

        def opener(request, timeout):
            bodies.append(json.loads(request.data.decode("utf-8")))
            return FakeResponse({"ok": True})

        api = _API.RememAPI("https://api.remem.io", "test-key", opener=opener)
        api.ingest({"title": "One"}, None, timeout=2.0)
        api.ingest({"title": "Two"}, "personal", timeout=2.0)

        self.assertNotIn("namespace", bodies[0])
        self.assertEqual(bodies[1]["namespace"], "personal")

    def test_request_errors_are_fixed_and_do_not_include_response_details(self) -> None:
        def opener(request, timeout):
            raise RuntimeError("vlt_secret-canary")

        api = _API.RememAPI("https://api.remem.io", "test-key", opener=opener)

        with self.assertRaises(_API.RememAPIError) as caught:
            api.query("history", ["*"], timeout=2.0)

        self.assertEqual(str(caught.exception), "Remem request failed")
        self.assertNotIn("secret-canary", str(caught.exception))

    def test_response_body_read_is_bounded(self) -> None:
        amounts = []

        class TrackingResponse(FakeResponse):
            def read(self, amount=None):
                amounts.append(amount)
                return super().read(amount)

        def opener(request, timeout):
            return TrackingResponse({"results": []})

        api = _API.RememAPI("https://api.remem.io", "test-key", opener=opener)
        api.query("history", ["*"], timeout=2.0)

        self.assertEqual(amounts, [_API._MAX_RESPONSE_BYTES + 1])

    def test_query_defensively_bounds_direct_call_to_api_limit(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured.update(json.loads(request.data.decode("utf-8")))
            return FakeResponse({"results": []})

        api = _API.RememAPI("https://api.remem.io", "test-key", opener=opener)
        api.query("x" * 5000, ["*"], timeout=2.0)

        self.assertLessEqual(len(captured["query"]), 2000)

    def test_default_redirect_handler_never_forwards_credentials(self) -> None:
        handler = _API._NoRedirectHandler()

        redirected = handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://untrusted.example/path",
        )

        self.assertIsNone(redirected)

    def test_default_transport_ignores_ambient_proxies_and_custom_ca_env(
        self,
    ) -> None:
        tls_context = object()
        built = mock.Mock()
        built.open = mock.Mock()
        with mock.patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "https://proxy.example",
                "HTTP_PROXY": "http://proxy.example",
                "SSL_CERT_FILE": "/tmp/untrusted-ca.pem",
                "SSL_CERT_DIR": "/tmp/untrusted-certs",
            },
            clear=False,
        ):
            with mock.patch.object(
                _API,
                "_system_tls_context",
                return_value=tls_context,
            ):
                with mock.patch.object(
                    _API.urllib_request,
                    "build_opener",
                    return_value=built,
                ) as build_opener:
                    api = _API.RememAPI(
                        "https://api.remem.io",
                        "test-key",
                    )

        handlers = build_opener.call_args.args
        proxy_handler = next(
            handler
            for handler in handlers
            if isinstance(handler, _API.urllib_request.ProxyHandler)
        )
        https_handler = next(
            handler
            for handler in handlers
            if isinstance(handler, _API.urllib_request.HTTPSHandler)
        )
        self.assertEqual(proxy_handler.proxies, {})
        self.assertIs(https_handler._context, tls_context)
        self.assertIs(api._opener, built.open)

    def test_api_origin_is_exactly_production_by_default(self) -> None:
        for origin in ("https://api.remem.io", "https://api.remem.io/"):
            with self.subTest(origin=origin):
                self.assertEqual(
                    _API.RememAPI(origin, "test-key").api_url,
                    origin.rstrip("/"),
                )

        rejected = (
            "https://attacker.example",
            "https://api.remem.io:443",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        )
        for origin in rejected:
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(
                    _API.RememAPIError,
                    "Invalid Remem API URL",
                ):
                    _API.RememAPI(origin, "test-key")

    def test_loopback_requires_explicit_local_dev_and_explicit_key(self) -> None:
        for origin in (
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ):
            with self.subTest(origin=origin):
                self.assertEqual(
                    _API.normalize_api_origin_for_environment(
                        origin,
                        {
                            "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                            "REMEM_API_KEY": "local-only-key",
                        },
                    ),
                    origin,
                )

        rejected_environments = (
            {},
            {"REMEM_MEMORY_ALLOW_LOCAL_DEV": "1"},
            {"REMEM_API_KEY": "local-only-key"},
            {
                "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                "REMEM_API_KEY_FD": "3",
            },
        )
        for environment in rejected_environments:
            with self.subTest(environment=environment):
                with self.assertRaisesRegex(
                    _API.RememAPIError,
                    "Invalid Remem API URL",
                ):
                    _API.normalize_api_origin_for_environment(
                        "http://127.0.0.1:8000",
                        environment,
                    )

    def test_fake_credential_fd_never_enables_keychain_for_loopback(
        self,
    ) -> None:
        keychain = mock.Mock()
        with self.assertRaisesRegex(
            _API.RememAPIError,
            "Invalid Remem API URL",
        ):
            _API.resolve_api_access(
                "http://127.0.0.1:8000",
                environment={
                    "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                    "REMEM_API_KEY_FD": "3",
                },
                keychain=keychain,
            )

        keychain.read.assert_not_called()

    def test_invalid_origin_is_rejected_before_keychain_resolution(self) -> None:
        keychain = mock.Mock()

        with self.assertRaisesRegex(
            _API.RememAPIError,
            "Invalid Remem API URL",
        ):
            _API.resolve_api_access(
                "https://attacker.example",
                environment={},
                keychain=keychain,
            )

        keychain.read.assert_not_called()

    def test_api_origin_rejects_exfiltration_shapes_with_fixed_error(self) -> None:
        canary = "secret-canary"
        rejected = (
            f"http://{canary}.example",
            f"https://user:{canary}@api.remem.io",
            f"https://api.remem.io/{canary}",
            f"https://api.remem.io?key={canary}",
            f"https://api.remem.io#{canary}",
        )
        for origin in rejected:
            with self.subTest(origin=origin):
                with self.assertRaises(_API.RememAPIError) as caught:
                    _API.RememAPI(origin, "test-key")
                self.assertEqual(
                    str(caught.exception),
                    "Invalid Remem API URL",
                )
                self.assertNotIn(canary, str(caught.exception))

    def test_environment_credential_wins_without_keychain_lookup(self) -> None:
        keychain = mock.Mock()

        resolved = _API.resolve_api_key(
            environment={"REMEM_API_KEY": " env-key "},
            keychain=keychain,
        )

        self.assertEqual(resolved, "env-key")
        keychain.read.assert_not_called()

    def test_explicit_credential_fd_is_consumed_once_without_keychain(
        self,
    ) -> None:
        canary = "vlt_anonymous-fd-canary"
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, canary.encode("utf-8"))
        os.close(write_descriptor)
        environment = {
            "REMEM_API_KEY_FD": str(read_descriptor),
        }
        keychain = mock.Mock()

        try:
            resolved = _API.consume_explicit_api_key(environment)
        finally:
            try:
                os.close(read_descriptor)
            except OSError:
                pass

        self.assertEqual(resolved, canary)
        self.assertNotIn("REMEM_API_KEY_FD", environment)
        keychain.read.assert_not_called()

    def test_credential_fd_reads_partial_chunks_to_eof(self) -> None:
        environment = {"REMEM_API_KEY_FD": "73"}
        with mock.patch.object(
            _API.os,
            "read",
            side_effect=[b"partial-", b"credential", b""],
        ) as read:
            with mock.patch.object(_API.os, "close") as close:
                resolved = _API.consume_explicit_api_key(environment)

        self.assertEqual(resolved, "partial-credential")
        self.assertEqual(read.call_count, 3)
        close.assert_called_once_with(73)

    def test_credential_fd_rejects_oversize_payload(self) -> None:
        environment = {"REMEM_API_KEY_FD": "74"}
        oversized = b"x" * (_API._MAX_CREDENTIAL_BYTES + 1)
        with mock.patch.object(
            _API.os,
            "read",
            side_effect=[oversized, b""],
        ):
            with mock.patch.object(_API.os, "close"):
                resolved = _API.consume_explicit_api_key(environment)

        self.assertIsNone(resolved)

    def test_keychain_resolution_reads_only_the_canonical_item(self) -> None:
        keychain = FakeKeychain()

        resolved = _API.resolve_api_key(environment={}, keychain=keychain)

        self.assertIsNone(resolved)
        self.assertEqual(
            keychain.reads,
            [
                (_API.KEYCHAIN_SERVICE, _API.KEYCHAIN_ACCOUNT),
            ],
        )

    def test_store_api_key_writes_only_the_canonical_item(self) -> None:
        keychain = FakeKeychain()

        _API.store_api_key(" canonical-key ", keychain=keychain)

        self.assertEqual(
            keychain.writes,
            [
                (
                    _API.KEYCHAIN_SERVICE,
                    _API.KEYCHAIN_ACCOUNT,
                    "canonical-key",
                )
            ],
        )

    def test_credential_helpers_accept_the_documented_positional_injection(
        self,
    ) -> None:
        keychain = FakeKeychain(
            {
                (
                    _API.KEYCHAIN_SERVICE,
                    _API.KEYCHAIN_ACCOUNT,
                ): "resolved-key",
            }
        )

        self.assertEqual(
            _API.resolve_api_key({}, keychain),
            "resolved-key",
        )
        _API.store_api_key("stored-key", keychain)

        self.assertEqual(
            keychain.writes[-1],
            (
                _API.KEYCHAIN_SERVICE,
                _API.KEYCHAIN_ACCOUNT,
                "stored-key",
            ),
        )

    def test_macos_keychain_is_lazy_and_declares_explicit_ctypes_signatures(
        self,
    ) -> None:
        security = FakeSecurityFramework(finds=[(-25300, "", 0)])
        core_foundation = FakeCoreFoundation()
        loader = mock.Mock(return_value=(security, core_foundation))
        keychain = _API.MacOSKeychain(framework_loader=loader)
        loader.assert_not_called()

        self.assertIsNone(keychain.read("service", "account"))

        loader.assert_called_once_with()
        self.assertEqual(
            len(security.SecKeychainFindGenericPassword.argtypes),
            8,
        )
        self.assertIs(
            security.SecKeychainFindGenericPassword.restype,
            ctypes.c_int32,
        )
        self.assertEqual(
            len(security.SecKeychainAddGenericPassword.argtypes),
            8,
        )
        self.assertEqual(
            len(security.SecKeychainItemModifyContent.argtypes),
            4,
        )
        self.assertEqual(
            len(security.SecKeychainItemFreeContent.argtypes),
            2,
        )
        self.assertEqual(
            len(
                security.SecKeychainGetUserInteractionAllowed.argtypes
            ),
            1,
        )
        self.assertEqual(
            len(
                security.SecKeychainSetUserInteractionAllowed.argtypes
            ),
            1,
        )
        self.assertEqual(len(core_foundation.CFRelease.argtypes), 1)

    def test_macos_keychain_read_disables_and_restores_user_interaction(
        self,
    ) -> None:
        security = FakeSecurityFramework(finds=[(0, "stored-key", 701)])
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=FakeCoreFoundation(),
        )

        self.assertEqual(keychain.read("service", "account"), "stored-key")

        self.assertEqual(
            security.interaction_events,
            [
                ("get", True),
                ("set", False),
                ("find", False),
                ("set", True),
            ],
        )

    def test_macos_keychain_read_restoration_failure_is_fixed_and_frees_refs(
        self,
    ) -> None:
        security = FakeSecurityFramework(
            finds=[(0, "stored-key", 711)],
            interaction_set_statuses=[0, -50],
        )
        core_foundation = FakeCoreFoundation()
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=core_foundation,
        )

        with self.assertRaises(_API.RememKeychainError) as caught:
            keychain.read("service", "account")

        self.assertEqual(
            str(caught.exception),
            "Remem credential lookup failed",
        )
        self.assertEqual(len(security.freed), 1)
        self.assertEqual(core_foundation.released, [711])

    def test_macos_keychain_deliberate_write_keeps_interaction_available(
        self,
    ) -> None:
        security = FakeSecurityFramework(finds=[(-25300, "", 0)])
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=FakeCoreFoundation(),
        )

        keychain.write("service", "account", "new-key")

        self.assertEqual(
            security.interaction_events,
            [("find", True)],
        )

    def test_macos_keychain_read_frees_password_buffer_and_item_reference(
        self,
    ) -> None:
        security = FakeSecurityFramework(finds=[(0, "stored-key", 701)])
        core_foundation = FakeCoreFoundation()
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=core_foundation,
        )

        self.assertEqual(keychain.read("service", "account"), "stored-key")

        self.assertEqual(len(security.freed), 1)
        self.assertEqual(core_foundation.released, [701])

    def test_macos_keychain_add_releases_returned_item_reference(self) -> None:
        security = FakeSecurityFramework(finds=[(-25300, "", 0)])
        core_foundation = FakeCoreFoundation()
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=core_foundation,
        )

        keychain.write("service", "account", "new-key")

        self.assertEqual(
            security.added,
            [("service", "account", "new-key")],
        )
        self.assertEqual(core_foundation.released, [902])

    def test_macos_keychain_update_frees_lookup_buffer_and_item_reference(
        self,
    ) -> None:
        security = FakeSecurityFramework(finds=[(0, "old-key", 801)])
        core_foundation = FakeCoreFoundation()
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=core_foundation,
        )

        keychain.write("service", "account", "new-key")

        self.assertEqual(security.modified, [(801, "new-key")])
        self.assertEqual(len(security.freed), 1)
        self.assertEqual(core_foundation.released, [801])

    def test_keychain_failures_surface_only_fixed_non_secret_errors(self) -> None:
        canary = "vlt_keychain-secret-canary"
        security = FakeSecurityFramework(
            finds=[(-50, canary, 0), (-25300, "", 0)],
            add_status=-50,
        )
        keychain = _API.MacOSKeychain(
            security=security,
            core_foundation=FakeCoreFoundation(),
        )

        with self.assertRaises(_API.RememKeychainError) as read_error:
            keychain.read("service", "account")
        with self.assertRaises(_API.RememKeychainError) as write_error:
            keychain.write("service", "account", canary)

        self.assertEqual(
            str(read_error.exception),
            "Remem credential lookup failed",
        )
        self.assertEqual(
            str(write_error.exception),
            "Remem credential storage failed",
        )
        self.assertNotIn(canary, str(read_error.exception))
        self.assertNotIn(canary, str(write_error.exception))


class RememMemoryHookTests(unittest.TestCase):
    def _dependencies(
        self,
        directory,
        api,
        *,
        engineering_handler=None,
        settings=None,
        credential_resolver=None,
        background_writes=False,
    ):
        return _HOOK.Dependencies(
            api=api,
            state_dir=Path(directory),
            engineering_handler=engineering_handler,
            settings=settings,
            credential_resolver=credential_resolver,
            background_writes=background_writes,
        )

    def test_user_prompt_submit_queries_all_namespaces_and_injects_context(
        self,
    ) -> None:
        api = FakeAPI(
            query_response={
                "results": [
                    {
                        "title": "Preference",
                        "content": "Prefers concise answers.",
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            output = _HOOK.handle_event(
                prompt_payload("How should you format this for me?"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=self._dependencies(directory, api),
            )

        self.assertEqual(api.queries[0]["namespaces"], ["*"])
        self.assertEqual(
            output["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit",
        )
        self.assertIn(
            "BEGIN UNTRUSTED REMEM MEMORY",
            output["hookSpecificOutput"]["additionalContext"],
        )

    def test_production_query_shape_injects_safe_chunks_and_facts(self) -> None:
        api = FakeAPI(
            query_response={
                "results": [
                    {
                        "document_id": "doc-1",
                        "title": "Family",
                        "chunks": [
                            {
                                "content": "The user's son's name is Sam.",
                                "score": 0.95,
                            },
                            {
                                "content": (
                                    "token=abcdefghijklmnopqrstuvwxyz123456"
                                ),
                                "score": 0.9,
                            },
                        ],
                    },
                    {
                        "document_id": "doc-2",
                        "title": "api_key=vlt_abcdefghijklmnop",
                        "chunks": [{"content": "Do not inject this document."}],
                    },
                ],
                "facts": [
                    {
                        "fact_type": "preference",
                        "content": "The user prefers concise answers.",
                    },
                    {
                        "fact_type": "fact",
                        "content": "password=hunter2",
                    },
                ],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            output = _HOOK.handle_event(
                prompt_payload("What is my son's name?"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=self._dependencies(directory, api),
            )

        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Family", context)
        self.assertIn("The user's son's name is Sam.", context)
        self.assertIn("The user prefers concise answers.", context)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", context)
        self.assertNotIn("hunter2", context)
        self.assertNotIn("Do not inject this document.", context)
        self.assertLessEqual(len(context), 6000)

    def test_first_substantive_prompt_queries_but_trivial_prompt_does_not(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_api = FakeAPI(
                {
                    "results": [
                        {"title": "Context", "content": "Prior useful context."}
                    ]
                }
            )
            first = _HOOK.handle_event(
                prompt_payload(
                    "Help me plan the order of work for this deployment.",
                    session_id="first-session",
                ),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=self._dependencies(directory, first_api),
            )
            trivial_api = FakeAPI()
            trivial = _HOOK.handle_event(
                prompt_payload("Thanks", session_id="trivial-session"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=self._dependencies(directory, trivial_api),
            )

        self.assertIn("hookSpecificOutput", first)
        self.assertEqual(len(first_api.queries), 1)
        self.assertEqual(trivial, {})
        self.assertEqual(trivial_api.queries, [])

    def test_recall_failure_fails_open_without_leaking_diagnostics(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(stderr):
                output = _HOOK.handle_event(
                    prompt_payload("What did we decide?"),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=self._dependencies(
                        directory, FailingAPI("vlt_secret-canary")
                    ),
                )

        self.assertEqual(output, {})
        self.assertNotIn("secret-canary", stderr.getvalue())

    def test_prompt_state_uses_hashed_session_filename_and_atomic_shape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = _HOOK.StateStore(Path(directory))
            state.save(
                "private-session-name",
                {
                    "current_prompt": "Remember my preference.",
                    "turn_id": "t1",
                    "off_record": False,
                    "off_record_seen": False,
                    "completed_turn_ids": [],
                    "metrics": {"hits": 0, "misses": 0},
                },
            )
            path = state.path_for("private-session-name")
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertNotIn("private-session-name", path.name)
        self.assertEqual(len(path.stem), 64)
        self.assertEqual(
            set(stored),
            {
                "current_prompt",
                "turn_id",
                "off_record",
                "off_record_seen",
                "completed_turn_ids",
                "metrics",
            },
        )

    def test_stop_captures_one_durable_memory_and_never_continues_agent(
        self,
    ) -> None:
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, api)
            _HOOK.handle_event(
                prompt_payload("Remember that I prefer concise answers."),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            output = _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertEqual(output, {"continue": True})
        self.assertEqual(len(api.ingests), 1)
        self.assertNotIn("decision", output)
        self.assertIsNone(api.ingests[0]["namespace"])
        self.assertEqual(
            api.ingests[0]["payload"]["metadata"]["memory_kind"],
            "conversation_turn",
        )

    def test_stop_uses_explicit_personal_namespace(self) -> None:
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, api)
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_PERSONAL_NAMESPACE": "personal"},
                clear=False,
            ):
                _HOOK.handle_event(
                    prompt_payload("Remember that I prefer concise answers."),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    stop_payload(),
                    harness="codex",
                    mode="stop",
                    dependencies=dependencies,
                )

        self.assertEqual(api.ingests[0]["namespace"], "personal")

    def test_stop_is_idempotent_by_session_and_turn(self) -> None:
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, api)
            _HOOK.handle_event(
                prompt_payload("Remember that I prefer concise answers."),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            first = _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )
            second = _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertEqual(first, {"continue": True})
        self.assertEqual(second, {"continue": True})
        self.assertEqual(len(api.ingests), 1)

    def test_off_record_and_credential_prompts_never_query_or_capture(self) -> None:
        for prompt in (
            "Off the record: remember that I prefer blue.",
            "Use api_key=vlt_abcdefghijklmnopqrstuvwxyz",
        ):
            with self.subTest(prompt=prompt):
                api = FakeAPI()
                with tempfile.TemporaryDirectory() as directory:
                    dependencies = self._dependencies(directory, api)
                    recall = _HOOK.handle_event(
                        prompt_payload(prompt),
                        harness="codex",
                        mode="user_prompt_submit",
                        dependencies=dependencies,
                    )
                    stop = _HOOK.handle_event(
                        stop_payload(),
                        harness="codex",
                        mode="stop",
                        dependencies=dependencies,
                    )
                self.assertEqual(recall, {})
                self.assertEqual(stop, {"continue": True})
                self.assertEqual(api.queries, [])
                self.assertEqual(api.ingests, [])

    def test_suppressed_prompt_text_is_not_persisted_and_state_is_private(
        self,
    ) -> None:
        canary = "vlt_abcdefghijklmnopqrstuvwxyz"
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, api)
            _HOOK.handle_event(
                prompt_payload(f"Off the record: api_key={canary}"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            store = _HOOK.StateStore(Path(directory))
            path = store.path_for("s1")
            serialized = path.read_text(encoding="utf-8")
            file_mode = path.stat().st_mode & 0o777
            directory_mode = path.parent.stat().st_mode & 0o777

        self.assertNotIn(canary, serialized)
        self.assertEqual(json.loads(serialized)["current_prompt"], "")
        self.assertEqual(file_mode, 0o600)
        self.assertEqual(directory_mode, 0o700)

    def test_off_record_seen_disables_future_engineering_summaries_only(
        self,
    ) -> None:
        engineering_calls = []
        api = FakeAPI()

        def engineering_handler(mode, payload):
            engineering_calls.append(
                (
                    mode,
                    payload["hook_event_name"],
                    os.environ.get("REMEM_MEMORY_SUMMARY_ENABLED"),
                )
            )
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=engineering_handler,
            )
            with mock.patch.dict(
                os.environ,
                {
                    "REMEM_MEMORY_SUMMARY_ENABLED": "1",
                    "REMEM_MEMORY_SUMMARY_PROVIDER": "openai",
                    "OPENAI_API_KEY": "summary-provider-key",
                },
                clear=False,
            ):
                _HOOK.handle_event(
                    prompt_payload(
                        "Off the record: do not retain this turn.",
                        turn_id="private-turn",
                    ),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                with mock.patch.object(
                    _HOOK.subprocess,
                    "Popen",
                ) as off_record_popen:
                    for mode, payload in (
                        (
                            "post_tool_use",
                            {
                                "hook_event_name": "PostToolUse",
                                "session_id": "s1",
                                "tool_name": "Write",
                            },
                        ),
                        (
                            "stop",
                            stop_payload(turn_id="private-turn"),
                        ),
                        (
                            "pre_compact",
                            {
                                "hook_event_name": "PreCompact",
                                "session_id": "s1",
                            },
                        ),
                        (
                            "session_end",
                            {
                                "hook_event_name": "SessionEnd",
                                "session_id": "s1",
                            },
                        ),
                    ):
                        _HOOK.handle_event(
                            payload,
                            harness="codex",
                            mode=mode,
                            dependencies=dependencies,
                        )
                self.assertEqual(engineering_calls, [])
                self.assertEqual(api.ingests, [])
                off_record_popen.assert_not_called()

                _HOOK.handle_event(
                    prompt_payload(
                        "Remember that I prefer concise answers.",
                        turn_id="normal-turn",
                    ),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                        "tool_input": {"file_path": "src/main.py"},
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    stop_payload(turn_id="normal-turn"),
                    harness="codex",
                    mode="stop",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PreCompact",
                        "session_id": "s1",
                    },
                    harness="codex",
                    mode="pre_compact",
                    dependencies=dependencies,
                )

                with mock.patch.object(
                    _HOOK.subprocess,
                    "Popen",
                ) as popen:
                    process = popen.return_value
                    process.stdin = mock.Mock()
                    _HOOK.handle_event(
                        {
                            "hook_event_name": "SessionEnd",
                            "session_id": "s1",
                        },
                        harness="codex",
                        mode="session_end",
                        dependencies=dependencies,
                    )
                    worker_environment = popen.call_args.kwargs["env"]

                self.assertEqual(
                    worker_environment[
                        "REMEM_MEMORY_SUMMARY_ENABLED"
                    ],
                    "0",
                )
                self.assertNotIn("OPENAI_API_KEY", worker_environment)
                _HOOK.handle_event(
                    {"session_id": "s1"},
                    harness="codex",
                    mode="worker_drain",
                    dependencies=dependencies,
                )
                self.assertEqual(
                    os.environ["REMEM_MEMORY_SUMMARY_ENABLED"],
                    "1",
                )

            state = _HOOK.StateStore(Path(directory)).load("s1")

        self.assertFalse(state["off_record"])
        self.assertTrue(state["off_record_seen"])
        self.assertEqual(
            engineering_calls,
            [
                ("post_tool_use", "PostToolUse", "0"),
                ("task_completed", "Stop", "0"),
                ("pre_compact", "PreCompact", "0"),
                ("session_end", "SessionEnd", "0"),
            ],
        )
        self.assertEqual(len(api.ingests), 1)
        self.assertIn(
            "Remember that I prefer concise answers.",
            api.ingests[0]["payload"]["content"],
        )

    def test_engineering_modes_route_through_existing_handler(self) -> None:
        calls = []

        def engineering_handler(mode, payload):
            calls.append((mode, payload["hook_event_name"]))
            return 0

        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=engineering_handler,
            )
            _HOOK.handle_event(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "s1",
                    "tool_name": "Write",
                },
                harness="codex",
                mode="post_tool_use",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                {
                    "hook_event_name": "PreCompact",
                    "session_id": "s1",
                },
                harness="codex",
                mode="pre_compact",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertEqual(
            calls,
            [
                ("post_tool_use", "PostToolUse"),
                ("pre_compact", "PreCompact"),
                ("task_completed", "Stop"),
            ],
        )

    def test_wrapper_engineering_disable_keeps_personal_memory_only(
        self,
    ) -> None:
        calls = []
        api = FakeAPI()

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: calls.append(
                    (mode, payload["hook_event_name"])
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_ENGINEERING_ENABLED": "0"},
                clear=False,
            ):
                _HOOK.handle_event(
                    prompt_payload(
                        "Remember that I prefer concise answers.",
                    ),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                with mock.patch.object(
                    _HOOK.subprocess,
                    "Popen",
                ) as popen:
                    self.assertEqual(
                        _HOOK.handle_event(
                            {
                                "hook_event_name": "PostToolUse",
                                "session_id": "s1",
                                "tool_name": "Write",
                            },
                            harness="codex",
                            mode="post_tool_use",
                            dependencies=dependencies,
                        ),
                        {},
                    )
                    self.assertEqual(
                        _HOOK.handle_event(
                            {
                                "hook_event_name": "PreCompact",
                                "session_id": "s1",
                            },
                            harness="codex",
                            mode="pre_compact",
                            dependencies=dependencies,
                        ),
                        {},
                    )
                    self.assertEqual(
                        _HOOK.handle_event(
                            {
                                "hook_event_name": "SessionEnd",
                                "session_id": "s1",
                            },
                            harness="codex",
                            mode="session_end",
                            dependencies=dependencies,
                        ),
                        {},
                    )
                    self.assertEqual(
                        _HOOK.handle_event(
                            stop_payload(),
                            harness="codex",
                            mode="stop",
                            dependencies=dependencies,
                        ),
                        {"continue": True},
                    )

        self.assertEqual(calls, [])
        self.assertEqual(len(api.ingests), 1)
        self.assertEqual(
            api.ingests[0]["payload"]["metadata"]["memory_kind"],
            "conversation_turn",
        )
        popen.assert_not_called()

    def test_worker_environment_forwards_wrapper_engineering_disable(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin:/bin",
                "REMEM_MEMORY_ENGINEERING_ENABLED": "0",
                "REMEM_MEMORY_SUMMARY_ENABLED": "0",
            },
            clear=True,
        ):
            environment = _HOOK._worker_environment(None, "codex")

        self.assertEqual(
            environment["REMEM_MEMORY_ENGINEERING_ENABLED"],
            "0",
        )

    def test_wrapper_session_override_wins_and_reaches_worker(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"REMEM_MEMORY_WRAPPER_SESSION_ID": "wrapper-session"},
            clear=True,
        ):
            self.assertEqual(
                _HOOK._session_id({"session_id": "host-session"}),
                "wrapper-session",
            )
            environment = _HOOK._worker_environment(None, "codex")

        self.assertEqual(
            environment["REMEM_MEMORY_WRAPPER_SESSION_ID"],
            "wrapper-session",
        )

    def test_engineering_handler_receives_transient_resolved_credential(
        self,
    ) -> None:
        seen = []

        def engineering_handler(mode, payload):
            seen.append(os.environ.get("REMEM_API_KEY"))
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=engineering_handler,
                credential_resolver=lambda: "vlt_transient-credential",
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_API_KEY": ""},
                clear=False,
            ):
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )
                self.assertEqual(os.environ.get("REMEM_API_KEY"), "")

        self.assertEqual(seen, ["vlt_transient-credential"])

    def test_engineering_preserves_explicit_summary_provider_settings(
        self,
    ) -> None:
        seen = []

        def engineering_handler(mode, payload):
            del mode, payload
            seen.append(
                (
                    os.environ.get("REMEM_MEMORY_SUMMARY_ENABLED"),
                    os.environ.get("REMEM_MEMORY_SUMMARY_PROVIDER"),
                )
            )
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=engineering_handler,
            )
            with mock.patch.dict(
                os.environ,
                {
                    "REMEM_MEMORY_SUMMARY_ENABLED": "1",
                    "REMEM_MEMORY_SUMMARY_PROVIDER": "openai",
                },
                clear=False,
            ):
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                        "tool_input": {"file_path": "src/main.py"},
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )
                self.assertEqual(
                    os.environ["REMEM_MEMORY_SUMMARY_ENABLED"],
                    "1",
                )

        self.assertEqual(seen, [("1", "openai")])

    def test_engineering_marks_and_restores_invoking_harness(self) -> None:
        seen = []

        def engineering_handler(mode, payload):
            del mode, payload
            seen.append(os.environ.get("REMEM_MEMORY_HARNESS"))
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=engineering_handler,
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_HARNESS": "outer-value"},
                clear=False,
            ):
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )
                self.assertEqual(
                    os.environ["REMEM_MEMORY_HARNESS"],
                    "outer-value",
                )

        self.assertEqual(seen, ["codex"])

    def test_codex_write_paths_are_sanitized_before_memory_handlers(
        self,
    ) -> None:
        canary = "vlt_abcdefghijklmnopqrstuvwxyz"
        unsafe_path = f"/tmp/api_key={canary}"
        calls = []
        api = FakeAPI()

        def engineering_handler(mode, payload):
            calls.append((mode, json.dumps(payload)))
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=engineering_handler,
            )
            _HOOK.handle_event(
                prompt_payload(
                    "Remember that I prefer concise answers.",
                    session_id="s1",
                    turn_id="t1",
                ),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            common = {
                "session_id": "s1",
                "cwd": unsafe_path,
                "transcript_path": f"{unsafe_path}/transcript.jsonl",
            }
            _HOOK.handle_event(
                {
                    **common,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Write",
                    "tool_input": {"file_path": "src/main.py"},
                },
                harness="codex",
                mode="post_tool_use",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                {**common, "hook_event_name": "PreCompact"},
                harness="codex",
                mode="pre_compact",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                {
                    **stop_payload(session_id="s1", turn_id="t1"),
                    **common,
                },
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                {**common, "hook_event_name": "SessionEnd"},
                harness="codex",
                mode="worker_session_end",
                dependencies=dependencies,
            )

        self.assertEqual(
            [mode for mode, _ in calls],
            ["post_tool_use", "pre_compact", "task_completed", "session_end"],
        )
        self.assertTrue(all(canary not in payload for _, payload in calls))
        self.assertEqual(len(api.ingests), 1)
        self.assertEqual(api.ingests[0]["payload"]["source_path"], "")

    def test_session_end_spawns_best_effort_rollup_and_returns_valid_json(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, FakeAPI())
            with mock.patch.object(_HOOK.subprocess, "Popen") as popen:
                process = popen.return_value
                process.stdin = mock.Mock()
                output = _HOOK.handle_event(
                    {
                        "hook_event_name": "SessionEnd",
                        "session_id": "s1",
                        "cwd": "/tmp/project",
                        "reason": "other",
                    },
                    harness="codex",
                    mode="session_end",
                    dependencies=dependencies,
                )
                queued = _HOOK.BackgroundQueueStore(
                    Path(directory)
                ).load("s1")

        self.assertEqual(output, {})
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertIs(popen.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        written = process.stdin.write.call_args.args[0]
        self.assertEqual(
            json.loads(written.decode("utf-8")),
            {"session_id": "s1"},
        )
        self.assertEqual(queued[0]["mode"], "session_end")
        self.assertEqual(
            queued[0]["payload"]["hook_event_name"],
            "SessionEnd",
        )
        process.stdin.close.assert_called_once_with()

    def test_background_worker_uses_isolated_python_and_anonymous_key_fd(
        self,
    ) -> None:
        canary = "vlt_trusted-worker-canary"
        observed = {}

        def launch(arguments, **kwargs):
            descriptor = kwargs["pass_fds"][0]
            observed["arguments"] = list(arguments)
            observed["environment"] = dict(kwargs["env"])
            observed["pass_fds"] = tuple(kwargs["pass_fds"])
            observed["credential"] = os.read(descriptor, 8192).decode("utf-8")
            process = mock.Mock()
            process.stdin = mock.Mock()
            return process

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, FakeAPI())
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": "/tmp/home",
                    "PATH": "/usr/bin:/bin",
                    "TMPDIR": "/tmp",
                    "LANG": "en_US.UTF-8",
                    "REMEM_API_KEY": canary,
                    "REMEM_API_URL": "https://api.remem.io",
                    "REMEM_MEMORY_SUMMARY_ENABLED": "1",
                    "REMEM_MEMORY_SUMMARY_PROVIDER": "anthropic",
                    "ANTHROPIC_API_KEY": "anthropic-summary-canary",
                    "AWS_SECRET_ACCESS_KEY": "aws-canary",
                    "SSH_AUTH_SOCK": "/tmp/ssh-canary",
                    "PYTHONPATH": "/tmp/python-canary",
                    "PYTHONINSPECT": "1",
                    "DYLD_INSERT_LIBRARIES": "/tmp/dyld-canary",
                    "LD_PRELOAD": "/tmp/ld-canary",
                    "NODE_OPTIONS": "--require=/tmp/node-canary",
                    "NODE_PATH": "/tmp/node-path-canary",
                    "BASH_ENV": "/tmp/bash-canary",
                    "ENV": "/tmp/shell-canary",
                    "ZDOTDIR": "/tmp/zsh-canary",
                    "PERL5OPT": "-M/tmp/perl-canary",
                    "RUBYOPT": "-r/tmp/ruby-canary",
                    "UNRELATED_SECRET": "unrelated-canary",
                },
                clear=True,
            ):
                with mock.patch.object(
                    _HOOK.subprocess,
                    "Popen",
                    side_effect=launch,
                ):
                    _HOOK.handle_event(
                        {
                            "hook_event_name": "SessionEnd",
                            "session_id": "s1",
                            "cwd": "/tmp/project",
                        },
                        harness="claude",
                        mode="session_end",
                        dependencies=dependencies,
                    )

        self.assertEqual(observed["credential"], canary)
        self.assertEqual(observed["arguments"][0], str(Path(sys.executable).resolve()))
        self.assertEqual(observed["arguments"][1], "-I")
        self.assertEqual(observed["arguments"][2], "-c")
        self.assertEqual(
            Path(observed["arguments"][5]),
            Path(_HOOK.__file__).resolve(),
        )
        worker_environment = observed["environment"]
        self.assertNotIn("REMEM_API_KEY", worker_environment)
        self.assertTrue(worker_environment["REMEM_API_KEY_FD"].isdigit())
        self.assertEqual(
            observed["pass_fds"],
            (int(worker_environment["REMEM_API_KEY_FD"]),),
        )
        self.assertEqual(
            worker_environment["ANTHROPIC_API_KEY"],
            "anthropic-summary-canary",
        )
        allowed = {
            "HOME",
            "PATH",
            "TMPDIR",
            "TEMP",
            "TMP",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "REMEM_API_KEY_FD",
            "REMEM_API_URL",
            "REMEM_MEMORY_DATA_DIR",
            "REMEM_MEMORY_SUMMARY_ENABLED",
            "REMEM_MEMORY_SUMMARY_PROVIDER",
            "ANTHROPIC_API_KEY",
        }
        self.assertLessEqual(set(worker_environment), allowed)
        for name in worker_environment:
            self.assertFalse(name.startswith("PYTHON"), name)
            self.assertFalse(name.startswith("DYLD"), name)
            self.assertFalse(name.startswith("LD_"), name)
        self.assertNotIn(canary, json.dumps(observed["arguments"]))
        self.assertNotIn(canary, json.dumps(worker_environment))

    def test_background_worker_without_env_key_resolves_keychain_in_process(
        self,
    ) -> None:
        canary = "vlt_worker-keychain-canary"
        observed = {}

        def handle(payload, harness, mode, dependencies=None):
            del payload, harness, mode, dependencies
            observed["credential"] = os.environ.get("REMEM_API_KEY")
            observed["descriptor"] = os.environ.get("REMEM_API_KEY_FD")
            return {}

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "HOME": "/tmp/home",
                "REMEM_API_URL": "https://api.remem.io",
            },
            clear=True,
        ):
            with mock.patch.object(
                _HOOK,
                "resolve_api_key",
                return_value=canary,
            ) as resolve:
                with mock.patch.object(
                    _HOOK,
                    "handle_event",
                    side_effect=handle,
                ):
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            self.assertEqual(
                                _HOOK.main(
                                    [
                                        "--mode",
                                        "worker_session_end",
                                        "--harness",
                                        "claude",
                                    ]
                                ),
                                0,
                            )
            self.assertNotIn("REMEM_API_KEY", os.environ)

        resolve.assert_called_once()
        self.assertEqual(observed["credential"], canary)
        self.assertIsNone(observed["descriptor"])
        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())

    def test_background_worker_consumes_explicit_key_fd_once(self) -> None:
        canary = "vlt_worker-fd-canary"
        observed = {}
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, canary.encode("utf-8"))
        os.close(write_descriptor)

        def handle(payload, harness, mode, dependencies=None):
            del payload, harness, mode, dependencies
            observed["credential"] = os.environ.get("REMEM_API_KEY")
            observed["descriptor"] = os.environ.get("REMEM_API_KEY_FD")
            return {}

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with mock.patch.dict(
                os.environ,
                {
                    "REMEM_API_KEY_FD": str(read_descriptor),
                    "REMEM_API_URL": "https://api.remem.io",
                },
                clear=True,
            ):
                with mock.patch.object(
                    _HOOK,
                    "resolve_api_key",
                ) as resolve:
                    with mock.patch.object(
                        _HOOK,
                        "handle_event",
                        side_effect=handle,
                    ):
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                self.assertEqual(
                                    _HOOK.main(
                                        [
                                            "--mode",
                                            "worker_stop",
                                            "--harness",
                                            "claude",
                                        ]
                                    ),
                                    0,
                                )
                self.assertNotIn("REMEM_API_KEY", os.environ)
                self.assertNotIn("REMEM_API_KEY_FD", os.environ)
        finally:
            try:
                os.close(read_descriptor)
            except OSError:
                pass

        resolve.assert_not_called()
        self.assertEqual(observed["credential"], canary)
        self.assertIsNone(observed["descriptor"])
        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())

    def test_worker_environment_forwards_only_selected_provider_credentials(
        self,
    ) -> None:
        common = {
            "HOME": "/tmp/home",
            "PATH": "/usr/bin:/bin",
            "REMEM_MEMORY_SUMMARY_ENABLED": "1",
            "CLAUDE_CONFIG_DIR": "/tmp/claude",
            "CLAUDE_CODE_OAUTH_TOKEN": "claude-oauth-canary",
            "ANTHROPIC_API_KEY": "anthropic-canary",
            "ANTHROPIC_AUTH_TOKEN": "anthropic-auth-canary",
            "OPENAI_API_KEY": "openai-canary",
            "CODEX_HOME": "/tmp/codex",
        }
        expected = {
            "claude_cli": {
                "CLAUDE_CONFIG_DIR",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
            },
            "codex_cli": {"CODEX_HOME"},
            "anthropic": {
                "ANTHROPIC_API_KEY",
            },
            "openai": {"OPENAI_API_KEY"},
        }
        all_credentials = set().union(*expected.values())

        for provider, selected_credentials in expected.items():
            with self.subTest(provider=provider):
                with mock.patch.dict(
                    os.environ,
                    {
                        **common,
                        "REMEM_MEMORY_SUMMARY_PROVIDER": provider,
                    },
                    clear=True,
                ):
                    environment = _HOOK._worker_environment(
                        None,
                        "claude",
                    )

                self.assertEqual(
                    environment["REMEM_MEMORY_SUMMARY_PROVIDER"],
                    provider,
                )
                self.assertEqual(
                    set(environment) & all_credentials,
                    selected_credentials,
                )

    def test_worker_credential_fd_read_loops_until_eof(self) -> None:
        chunks = [
            b"vlt_partial-",
            b"read-canary",
            b"",
        ]
        with mock.patch.object(
            _HOOK.os,
            "read",
            side_effect=chunks,
        ) as read:
            with mock.patch.object(_HOOK.os, "close") as close:
                credential = _HOOK._consume_credential_descriptor("17")

        self.assertEqual(credential, "vlt_partial-read-canary")
        self.assertEqual(read.call_count, 3)
        close.assert_called_once_with(17)

    def test_harness_detection_uses_codex_plugin_root(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CLAUDE_PLUGIN_ROOT": "/plugin"},
            clear=True,
        ):
            self.assertEqual(_HOOK._detect_harness(), "claude")
        with mock.patch.dict(
            os.environ,
            {
                "PLUGIN_ROOT": "/plugin",
                "CLAUDE_PLUGIN_ROOT": "/plugin",
            },
            clear=True,
        ):
            self.assertEqual(_HOOK._detect_harness(), "codex")

    def test_claude_user_prompt_cli_emits_one_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment["REMEM_MEMORY_DATA_DIR"] = directory
            environment["REMEM_MEMORY_AUTO_ENABLED"] = "0"
            result = subprocess.run(
                [
                    sys.executable,
                    str(_SCRIPTS_DIR / "remem_memory_hook.py"),
                    "--mode",
                    "user_prompt_submit",
                    "--harness",
                    "claude",
                ],
                input=json.dumps(prompt_payload("What did we decide?")),
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
                env=environment,
            )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIsInstance(json.loads(result.stdout), dict)

    def test_codex_worker_stop_cli_emits_continue_and_writes_one_memory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture_dir = Path(directory)
            capture_path = fixture_dir / "requests.ndjson"
            (fixture_dir / "sitecustomize.py").write_text(
                "\n".join(
                    (
                        "import os",
                        "import urllib.request",
                        "class _Response:",
                        "    def __enter__(self): return self",
                        "    def __exit__(self, *args): return False",
                        "    def read(self, amount=None): return b'{\"ok\":true}'",
                        "def _open(self, request, data=None, timeout=None):",
                        "    del self, data, timeout",
                        "    with open(os.environ['FAKE_REMEM_CAPTURE'], 'ab') as stream:",
                        "        stream.write(request.data + b'\\n')",
                        "    return _Response()",
                        "urllib.request.OpenerDirector.open = _open",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            _HOOK.StateStore(fixture_dir).save(
                "s1",
                {
                    "current_prompt": (
                        "Remember that I prefer concise answers."
                    ),
                    "turn_id": "t1",
                    "off_record": False,
                    "completed_turn_ids": [],
                    "metrics": {"hits": 0, "misses": 0},
                },
            )
            payload = stop_payload()
            payload["cwd"] = directory
            environment = os.environ.copy()
            environment.update(
                {
                    "REMEM_MEMORY_DATA_DIR": directory,
                    "FAKE_REMEM_CAPTURE": str(capture_path),
                    "PYTHONPATH": os.pathsep.join(
                        filter(
                            None,
                            (
                                directory,
                                environment.get("PYTHONPATH", ""),
                            ),
                        )
                    ),
                }
            )
            read_descriptor, write_descriptor = os.pipe()
            try:
                os.write(write_descriptor, b"test-key")
            finally:
                os.close(write_descriptor)
            environment["REMEM_API_KEY_FD"] = str(read_descriptor)
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(_SCRIPTS_DIR / "remem_memory_hook.py"),
                        "--mode",
                        "worker_stop",
                        "--harness",
                        "codex",
                    ],
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                    env=environment,
                    pass_fds=(read_descriptor,),
                )
            finally:
                os.close(read_descriptor)
            requests = [
                json.loads(line)
                for line in capture_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {"continue": True})
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            requests[0]["metadata"]["memory_kind"],
            "conversation_turn",
        )

    def test_all_claude_write_events_spawn_bounded_workers_never_inline(
        self,
    ) -> None:
        inline_calls = []

        def fail_inline(mode, payload):
            inline_calls.append((mode, payload))
            raise AssertionError("Claude write event ran inline")

        payloads = {
            "post_tool_use": {
                "hook_event_name": "PostToolUse",
                "session_id": "s1",
                "cwd": "/tmp/project",
                "tool_name": "apply_patch",
                "tool_input": {"patch": "x" * 100_000},
                "tool_response": "y" * 100_000,
            },
            "stop": stop_payload(assistant="A" * 100_000),
            "pre_compact": {
                "hook_event_name": "PreCompact",
                "session_id": "s1",
                "cwd": "/tmp/project",
                "transcript_path": "/tmp/transcript.jsonl",
            },
            "session_end": {
                "hook_event_name": "SessionEnd",
                "session_id": "s1",
                "cwd": "/tmp/project",
                "reason": "other",
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=fail_inline,
            )
            with mock.patch.object(_HOOK.subprocess, "Popen") as popen:
                process = popen.return_value
                process.stdin = mock.Mock()
                with mock.patch.dict(
                    os.environ,
                    {
                        "REMEM_MEMORY_SUMMARY_ENABLED": "1",
                        "REMEM_MEMORY_SUMMARY_PROVIDER": "anthropic",
                    },
                    clear=False,
                ):
                    outputs = [
                        _HOOK.handle_event(
                            payload,
                            harness="claude",
                            mode=mode,
                            dependencies=dependencies,
                        )
                        for mode, payload in payloads.items()
                    ]

        self.assertEqual(outputs, [{}, {}, {}, {}])
        self.assertEqual(inline_calls, [])
        self.assertEqual(popen.call_count, 4)
        worker_modes = [
            call.args[0][call.args[0].index("--mode") + 1]
            for call in popen.call_args_list
        ]
        self.assertEqual(
            worker_modes,
            [
                "worker_drain",
                "worker_drain",
                "worker_drain",
                "worker_drain",
            ],
        )
        for write in process.stdin.write.call_args_list:
            serialized = write.args[0]
            self.assertLess(len(serialized), 10_000)
            self.assertNotIn(b"tool_response", serialized)
            self.assertNotIn(b"x" * 9_000, serialized)
        for call in popen.call_args_list:
            self.assertEqual(
                call.kwargs["env"]["REMEM_MEMORY_SUMMARY_ENABLED"],
                "1",
            )
            self.assertEqual(
                call.kwargs["env"]["REMEM_MEMORY_SUMMARY_PROVIDER"],
                "anthropic",
            )

    def test_background_payload_forwards_only_a_bounded_safe_patch(self) -> None:
        prefix = (
            "*** Begin Patch\n"
            "*** Update File: src/main.py\n"
        )
        payload = _HOOK._background_payload(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": prefix + ("+x\n" * 100_000),
                },
            },
            "post_tool_use",
        )
        secret = _HOOK._background_payload(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: "
                        "tmp/api_key=vlt_abcdefghijklmnopqrstuvwxyz\n"
                        "*** End Patch\n"
                    ),
                },
            },
            "post_tool_use",
        )

        self.assertIsNotNone(payload)
        assert payload is not None
        forwarded = payload["tool_input"]["patch"]
        self.assertTrue(forwarded.startswith(prefix))
        self.assertLessEqual(len(forwarded), 8_192)
        self.assertIsNone(secret)

        codex_payload = _HOOK._background_payload(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": prefix + ("+x\n" * 100_000),
                },
            },
            "post_tool_use",
        )
        self.assertIsNotNone(codex_payload)
        assert codex_payload is not None
        self.assertLessEqual(
            len(codex_payload["tool_input"]["command"]),
            8_192,
        )

    def test_worker_modes_preserve_all_engineering_dispatch(self) -> None:
        calls = []

        def engineering_handler(mode, payload):
            calls.append(mode)
            return 0

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=engineering_handler,
            )
            for worker_mode, payload in (
                (
                    "worker_post_tool_use",
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                    },
                ),
                ("worker_stop", stop_payload()),
                (
                    "worker_pre_compact",
                    {
                        "hook_event_name": "PreCompact",
                        "session_id": "s1",
                    },
                ),
                (
                    "worker_session_end",
                    {
                        "hook_event_name": "SessionEnd",
                        "session_id": "s1",
                    },
                ),
            ):
                _HOOK.handle_event(
                    payload,
                    harness="claude",
                    mode=worker_mode,
                    dependencies=dependencies,
                )

        self.assertEqual(
            calls,
            ["post_tool_use", "task_completed", "pre_compact", "session_end"],
        )

    def test_background_workers_drain_claude_events_in_hook_arrival_order(
        self,
    ) -> None:
        calls = []
        launches = []

        class CapturingInput:
            def __init__(self) -> None:
                self.value = b""

            def write(self, value) -> None:
                self.value += value

            def close(self) -> None:
                pass

        def launch(arguments, **kwargs):
            process = mock.Mock()
            process.stdin = CapturingInput()
            launches.append((list(arguments), process, kwargs))
            return process

        def engineering_handler(mode, payload):
            calls.append((mode, payload["hook_event_name"]))
            return 0

        events = (
            (
                "post_tool_use",
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "s1",
                    "tool_name": "Write",
                    "tool_input": {"file_path": "src/main.py"},
                },
            ),
            ("stop", stop_payload()),
            (
                "session_end",
                {
                    "hook_event_name": "SessionEnd",
                    "session_id": "s1",
                },
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=engineering_handler,
            )
            with mock.patch.object(
                _HOOK.subprocess,
                "Popen",
                side_effect=launch,
            ):
                for mode, payload in events:
                    _HOOK.handle_event(
                        payload,
                        harness="claude",
                        mode=mode,
                        dependencies=dependencies,
                    )

            self.assertEqual(len(launches), 3)
            for arguments, process, _kwargs in reversed(launches):
                worker_mode = arguments[arguments.index("--mode") + 1]
                _HOOK.handle_event(
                    json.loads(process.stdin.value.decode("utf-8")),
                    harness="claude",
                    mode=worker_mode,
                    dependencies=dependencies,
                )

        self.assertEqual(
            calls,
            [
                ("post_tool_use", "PostToolUse"),
                ("task_completed", "Stop"),
                ("session_end", "SessionEnd"),
            ],
        )

    def test_codex_runtime_writes_are_queued_and_roll_up_in_order(
        self,
    ) -> None:
        calls = []
        launches = []

        class CapturingInput:
            def __init__(self) -> None:
                self.value = b""

            def write(self, value) -> None:
                self.value += value

            def close(self) -> None:
                pass

        def launch(arguments, **kwargs):
            process = mock.Mock()
            process.stdin = CapturingInput()
            launches.append((list(arguments), process, kwargs))
            return process

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=lambda mode, payload: calls.append(mode),
                background_writes=True,
            )
            with mock.patch.object(
                _HOOK.subprocess,
                "Popen",
                side_effect=launch,
            ):
                post_output = _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                        "tool_input": {"file_path": "src/main.py"},
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )
                stop_output = _HOOK.handle_event(
                    stop_payload(),
                    harness="codex",
                    mode="stop",
                    dependencies=dependencies,
                )
                precompact_output = _HOOK.handle_event(
                    {
                        "hook_event_name": "PreCompact",
                        "session_id": "s1",
                    },
                    harness="codex",
                    mode="pre_compact",
                    dependencies=dependencies,
                )

            self.assertEqual(calls, [])
            self.assertEqual(post_output, {})
            self.assertEqual(stop_output, {"continue": True})
            self.assertEqual(precompact_output, {})
            self.assertEqual(len(launches), 3)

            for arguments, process, _kwargs in reversed(launches):
                _HOOK.handle_event(
                    json.loads(process.stdin.value.decode("utf-8")),
                    harness="codex",
                    mode=arguments[arguments.index("--mode") + 1],
                    dependencies=dependencies,
                )

        self.assertEqual(
            calls,
            [
                "post_tool_use",
                "task_completed",
                "pre_compact",
                "session_end",
            ],
        )

    def test_delayed_claude_stop_uses_its_queued_turn_snapshot(self) -> None:
        launches = []
        engineering_calls = []

        class CapturingInput:
            def __init__(self) -> None:
                self.value = b""

            def write(self, value) -> None:
                self.value += value

            def close(self) -> None:
                pass

        def launch(arguments, **kwargs):
            process = mock.Mock()
            process.stdin = CapturingInput()
            launches.append((list(arguments), process, kwargs))
            return process

        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: engineering_calls.append(
                    (
                        mode,
                        os.environ.get(
                            "REMEM_MEMORY_SUMMARY_ENABLED"
                        ),
                    )
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_SUMMARY_ENABLED": "1"},
                clear=False,
            ):
                _HOOK.handle_event(
                    prompt_payload(
                        "Remember that I prefer concise answers.",
                        turn_id="turn-a",
                    ),
                    harness="claude",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                with mock.patch.object(
                    _HOOK.subprocess,
                    "Popen",
                    side_effect=launch,
                ):
                    _HOOK.handle_event(
                        stop_payload(
                            turn_id="turn-a",
                            assistant=(
                                "I will keep future answers concise."
                            ),
                        ),
                        harness="claude",
                        mode="stop",
                        dependencies=dependencies,
                    )

                _HOOK.handle_event(
                    prompt_payload(
                        "Off the record: do not retain this next turn.",
                        turn_id="turn-b",
                    ),
                    harness="claude",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )

                arguments, process, _kwargs = launches[0]
                _HOOK.handle_event(
                    json.loads(process.stdin.value.decode("utf-8")),
                    harness="claude",
                    mode=arguments[arguments.index("--mode") + 1],
                    dependencies=dependencies,
                )
                self.assertEqual(
                    os.environ["REMEM_MEMORY_SUMMARY_ENABLED"],
                    "1",
                )

        self.assertEqual(engineering_calls, [("task_completed", "0")])
        self.assertEqual(len(api.ingests), 1)
        content = api.ingests[0]["payload"]["content"]
        self.assertIn("Remember that I prefer concise answers.", content)
        self.assertNotIn("do not retain this next turn", content)

    def test_worker_clears_backlog_if_memory_mode_changes_to_off(self) -> None:
        calls = []
        launches = []

        class CapturingInput:
            def __init__(self) -> None:
                self.value = b""

            def write(self, value) -> None:
                self.value += value

            def close(self) -> None:
                pass

        def launch(arguments, **kwargs):
            process = mock.Mock()
            process.stdin = CapturingInput()
            launches.append((list(arguments), process, kwargs))
            return process

        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                FakeAPI(),
                engineering_handler=lambda mode, payload: calls.append(mode),
            )
            with mock.patch.object(
                _HOOK.subprocess,
                "Popen",
                side_effect=launch,
            ):
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                    },
                    harness="claude",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )

            Path(directory, "settings.json").write_text(
                '{"mode":"off","sensitivity":"balanced"}',
                encoding="utf-8",
            )
            arguments, process, _kwargs = launches[0]
            _HOOK.handle_event(
                json.loads(process.stdin.value.decode("utf-8")),
                harness="claude",
                mode=arguments[arguments.index("--mode") + 1],
                dependencies=dependencies,
            )
            queue = _HOOK.BackgroundQueueStore(Path(directory))
            self.assertEqual(queue.load("s1"), [])

        self.assertEqual(calls, [])

    def test_background_worker_failure_is_silent_and_fail_open(self) -> None:
        canary = "vlt_abcdefghijklmnopqrstuvwxyz"
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, FakeAPI())
            with mock.patch.object(
                _HOOK.subprocess,
                "Popen",
                side_effect=RuntimeError(canary),
            ):
                with contextlib.redirect_stderr(stderr):
                    output = _HOOK.handle_event(
                        stop_payload(),
                        harness="claude",
                        mode="stop",
                        dependencies=dependencies,
                    )

        self.assertEqual(output, {})
        self.assertEqual(stderr.getvalue(), "")

    def test_background_payload_omits_secret_common_paths(self) -> None:
        canary = "vlt_abcdefghijklmnopqrstuvwxyz"

        minimized = _HOOK._background_payload(
            {
                "hook_event_name": "PreCompact",
                "session_id": "s1",
                "cwd": f"/tmp/api_key={canary}",
                "transcript_path": f"/tmp/token={canary}.jsonl",
            },
            "pre_compact",
        )

        self.assertIsNotNone(minimized)
        assert minimized is not None
        self.assertNotIn("cwd", minimized)
        self.assertNotIn("transcript_path", minimized)
        self.assertNotIn(canary, json.dumps(minimized))

    def test_settings_defaults_and_invalid_values_fail_safely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            self.assertEqual(
                _HOOK.load_settings(data_dir),
                _HOOK.Settings(mode="auto", sensitivity="balanced"),
            )
            (data_dir / "settings.json").write_text(
                '{"mode": "invalid", "sensitivity": "reckless"}',
                encoding="utf-8",
            )
            self.assertEqual(
                _HOOK.load_settings(data_dir),
                _HOOK.Settings(mode="auto", sensitivity="balanced"),
            )
            (data_dir / "settings.json").write_text("{broken", encoding="utf-8")
            self.assertEqual(
                _HOOK.load_settings(data_dir),
                _HOOK.Settings(mode="auto", sensitivity="balanced"),
            )

    def test_off_mode_suppresses_recall_capture_and_engineering(self) -> None:
        calls = []
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "settings.json").write_text(
                '{"mode": "off", "sensitivity": "aggressive"}',
                encoding="utf-8",
            )
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: calls.append(mode),
            )
            recall = _HOOK.handle_event(
                prompt_payload("What did we decide last time?"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "s1",
                    "tool_name": "Write",
                },
                harness="codex",
                mode="post_tool_use",
                dependencies=dependencies,
            )
            stop = _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertEqual(recall, {})
        self.assertEqual(stop, {"continue": True})
        self.assertEqual(api.queries, [])
        self.assertEqual(api.ingests, [])
        self.assertEqual(calls, [])

    def test_legacy_auto_disabled_environment_still_suppresses_all_hooks(
        self,
    ) -> None:
        calls = []
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: calls.append(mode),
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_AUTO_ENABLED": "0"},
                clear=False,
            ):
                recall = _HOOK.handle_event(
                    prompt_payload("What did we decide last time?"),
                    harness="codex",
                    mode="user_prompt_submit",
                    dependencies=dependencies,
                )
                _HOOK.handle_event(
                    {
                        "hook_event_name": "PostToolUse",
                        "session_id": "s1",
                        "tool_name": "Write",
                    },
                    harness="codex",
                    mode="post_tool_use",
                    dependencies=dependencies,
                )

        self.assertEqual(recall, {})
        self.assertEqual(api.queries, [])
        self.assertEqual(calls, [])

    def test_recall_only_mode_queries_but_suppresses_all_writes(self) -> None:
        calls = []
        api = FakeAPI(
            {
                "results": [
                    {"title": "Decision", "content": "Use a Mac host."}
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "settings.json").write_text(
                '{"mode": "recall-only", "sensitivity": "aggressive"}',
                encoding="utf-8",
            )
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: calls.append(mode),
            )
            recall = _HOOK.handle_event(
                prompt_payload("What did we decide last time?"),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            stop = _HOOK.handle_event(
                stop_payload(),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertIn("hookSpecificOutput", recall)
        self.assertEqual(stop, {"continue": True})
        self.assertEqual(len(api.queries), 1)
        self.assertEqual(api.ingests, [])
        self.assertEqual(calls, [])

    def test_sensitivity_setting_controls_ordinary_turn_capture(self) -> None:
        prompt = "Please compare these two deployment approaches in detail."
        assistant = "The first is safer because it narrows network access."

        for sensitivity, expected in (("balanced", 0), ("aggressive", 1)):
            with self.subTest(sensitivity=sensitivity):
                api = FakeAPI()
                with tempfile.TemporaryDirectory() as directory:
                    Path(directory, "settings.json").write_text(
                        json.dumps(
                            {"mode": "auto", "sensitivity": sensitivity}
                        ),
                        encoding="utf-8",
                    )
                    dependencies = self._dependencies(directory, api)
                    _HOOK.handle_event(
                        prompt_payload(prompt),
                        harness="codex",
                        mode="user_prompt_submit",
                        dependencies=dependencies,
                    )
                    _HOOK.handle_event(
                        stop_payload(assistant=assistant),
                        harness="codex",
                        mode="stop",
                        dependencies=dependencies,
                    )
                self.assertEqual(len(api.ingests), expected)

    def test_capture_uses_bounded_sanitized_assistant_text(self) -> None:
        api = FakeAPI()
        assistant = "A durable explanation. " + ("detail " * 5000)
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(directory, api)
            _HOOK.handle_event(
                prompt_payload("Remember that I prefer concise answers."),
                harness="codex",
                mode="user_prompt_submit",
                dependencies=dependencies,
            )
            _HOOK.handle_event(
                stop_payload(assistant=assistant),
                harness="codex",
                mode="stop",
                dependencies=dependencies,
            )

        self.assertEqual(len(api.ingests), 1)
        content = api.ingests[0]["payload"]["content"]
        self.assertLessEqual(len(content), 4100)
        self.assertNotEqual(content, f"User: Remember that I prefer concise answers.\n\nAssistant: {assistant}")

    def test_state_failures_return_valid_json_without_diagnostics_or_writes(
        self,
    ) -> None:
        canary = "vlt_state-secret-canary"
        api = FakeAPI()
        calls = []
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            dependencies = self._dependencies(
                directory,
                api,
                engineering_handler=lambda mode, payload: calls.append(mode),
            )
            with mock.patch.object(
                _HOOK.StateStore,
                "load",
                side_effect=PermissionError(canary),
            ):
                with contextlib.redirect_stderr(stderr):
                    output = _HOOK.handle_event(
                        {
                            "hook_event_name": "PostToolUse",
                            "session_id": "s1",
                            "tool_name": "Write",
                        },
                        harness="codex",
                        mode="post_tool_use",
                        dependencies=dependencies,
                    )

        self.assertEqual(output, {})
        self.assertEqual(calls, [])
        self.assertEqual(api.ingests, [])
        self.assertNotIn(canary, stderr.getvalue())

    def test_corrupt_state_fails_open_without_engineering_write(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            store = _HOOK.StateStore(Path(directory))
            store.save("s1", _HOOK._default_state())
            store.path_for("s1").write_text("[]", encoding="utf-8")
            output = _HOOK.handle_event(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "s1",
                    "tool_name": "Write",
                },
                harness="codex",
                mode="post_tool_use",
                dependencies=self._dependencies(
                    directory,
                    FakeAPI(),
                    engineering_handler=lambda mode, payload: calls.append(mode),
                ),
            )

        self.assertEqual(output, {})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
