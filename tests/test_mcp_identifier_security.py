from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


_ROOT = Path(__file__).resolve().parents[1]
_SERVER_PATH = (
    _ROOT
    / "plugins"
    / "remem-memory"
    / "mcp"
    / "remem_mcp"
    / "server.py"
)


class _Record:
    def __init__(self, **values):
        self.__dict__.update(values)


class _Server:
    def __init__(self, name):
        self.name = name

    @staticmethod
    def list_tools():
        return lambda function: function

    @staticmethod
    def call_tool():
        return lambda function: function


def _load_server():
    httpx = types.ModuleType("httpx")
    httpx.HTTPStatusError = type("HTTPStatusError", (Exception,), {})
    httpx.AsyncClient = object

    mcp = types.ModuleType("mcp")
    mcp_server = types.ModuleType("mcp.server")
    mcp_server.Server = _Server
    mcp_stdio = types.ModuleType("mcp.server.stdio")
    mcp_stdio.stdio_server = object
    mcp_types = types.ModuleType("mcp.types")
    mcp_types.TextContent = _Record
    mcp_types.Tool = _Record

    modules = {
        "httpx": httpx,
        "mcp": mcp,
        "mcp.server": mcp_server,
        "mcp.server.stdio": mcp_stdio,
        "mcp.types": mcp_types,
    }
    spec = importlib.util.spec_from_file_location(
        "bundled_mcp_identifier_tests",
        _SERVER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    with mock.patch.dict(sys.modules, modules):
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_API_KEY_FD": "",
                "REMEM_API_KEY": "must-be-discarded",
            },
            clear=False,
        ):
            spec.loader.exec_module(module)
    return module


_SERVER = _load_server()


class MCPIdentifierSecurityTests(unittest.TestCase):
    def test_path_identifiers_reject_traversal_query_and_slashes(self) -> None:
        cases = (
            ("remem_get_document", "document_id"),
            ("remem_get_document_chunks", "document_id"),
            ("remem_get_entity_facts", "entity_id"),
            ("remem_extract_facts", "document_id"),
        )
        malicious_values = (
            "../../query",
            "abc?namespaces=*",
            "abc/def",
        )

        for tool, field in cases:
            for value in malicious_values:
                with self.subTest(tool=tool, field=field, value=value):
                    request = mock.AsyncMock()
                    with mock.patch.object(_SERVER, "_request", request):
                        result = asyncio.run(
                            _SERVER.call_tool(tool, {field: value})
                        )

                    request.assert_not_awaited()
                    self.assertEqual(len(result), 1)
                    self.assertIn(f"Invalid {field}", result[0].text)
                    self.assertNotIn(value, result[0].text)

    def test_canonical_uuid_is_normalized_before_path_construction(self) -> None:
        supplied = "A8098C1A-F86E-11DA-BD1A-00112444BE1E"
        expected = "a8098c1a-f86e-11da-bd1a-00112444be1e"
        request = mock.AsyncMock(return_value={"title": "ok"})

        with mock.patch.object(_SERVER, "_request", request):
            result = asyncio.run(
                _SERVER.call_tool(
                    "remem_get_document",
                    {"document_id": supplied},
                )
            )

        self.assertEqual(len(result), 1)
        request.assert_awaited_once_with(
            "GET",
            f"/v1/documents/{expected}",
            params=None,
        )


if __name__ == "__main__":
    unittest.main()
