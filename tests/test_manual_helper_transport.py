from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts import remem_checkpoint, remem_recall


_ROOT = Path(__file__).resolve().parents[1]
_API_PATH = (
    _ROOT
    / "plugins"
    / "remem-memory"
    / "scripts"
    / "remem_api.py"
)


def _load_api():
    spec = importlib.util.spec_from_file_location(
        "manual_helper_remem_api_tests",
        _API_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_API = _load_api()


class _Response:
    def __init__(self, payload):
        self._encoded = json.dumps(payload).encode("utf-8")

    def read(self, amount=None):
        return self._encoded[:amount]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _ForbiddenHTTPX:
    class Client:
        def __init__(self, *args, **kwargs):
            raise AssertionError("manual helpers must not use httpx")


class ManualHelperTransportTests(unittest.TestCase):
    def test_shared_api_accepts_a_complete_manual_query_payload(self) -> None:
        captured = {}

        def opener(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return _Response({"results": []})

        payload = {
            "query": "what changed",
            "mode": "rich",
            "max_results": 12,
            "synthesize": True,
            "filters": {"checkpoint_project": ["remem"]},
        }
        api = _API.RememAPI(
            "https://api.remem.io",
            "test-key",
            opener=opener,
        )

        response = api.query_payload(payload, timeout=4.5)

        self.assertEqual(response, {"results": []})
        self.assertEqual(captured["url"], "https://api.remem.io/v1/query")
        self.assertEqual(captured["body"], payload)
        self.assertEqual(captured["timeout"], 4.5)

    def test_recall_helper_uses_shared_stdlib_transport(self) -> None:
        adapter = mock.Mock()
        adapter.query_payload.return_value = {"results": []}
        payload = {
            "query": "history",
            "mode": "fast",
            "max_results": 10,
        }

        with mock.patch.object(
            remem_recall.remem_api,
            "RememAPI",
            return_value=adapter,
        ) as constructor:
            with mock.patch.dict(
                remem_recall.__dict__,
                {"httpx": _ForbiddenHTTPX},
            ):
                response = remem_recall.query_remem(
                    api_url="https://api.remem.io",
                    api_key="test-key",
                    payload=payload,
                )

        self.assertEqual(response, {"results": []})
        constructor.assert_called_once_with(
            "https://api.remem.io",
            "test-key",
            allow_local_dev=True,
        )
        adapter.query_payload.assert_called_once_with(
            payload,
            timeout=45.0,
        )

    def test_checkpoint_helper_uses_shared_stdlib_transport(self) -> None:
        adapter = mock.Mock()
        adapter.ingest.return_value = {"document_id": "doc"}
        payload = {"title": "checkpoint", "content": "summary"}

        with mock.patch.object(
            remem_checkpoint.remem_api,
            "RememAPI",
            return_value=adapter,
        ) as constructor:
            with mock.patch.dict(
                remem_checkpoint.__dict__,
                {"httpx": _ForbiddenHTTPX},
            ):
                response = remem_checkpoint.ingest_checkpoint(
                    api_url="https://api.remem.io",
                    api_key="test-key",
                    payload=payload,
                )

        self.assertEqual(response, {"document_id": "doc"})
        constructor.assert_called_once_with(
            "https://api.remem.io",
            "test-key",
            allow_local_dev=True,
        )
        adapter.ingest.assert_called_once_with(
            payload,
            None,
            timeout=30.0,
        )

    def test_root_helpers_need_no_dependency_manifest(self) -> None:
        self.assertFalse((_ROOT / "requirements.txt").exists())
        for relative in (
            "scripts/remem_checkpoint.py",
            "scripts/remem_recall.py",
            "scripts/remem_rollup.py",
        ):
            with self.subTest(relative=relative):
                source = (_ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("import httpx", source)


if __name__ == "__main__":
    unittest.main()
