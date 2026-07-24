"""Packaged Remem MCP server.

This bundled MCP server runs locally over stdio and proxies tool calls to the
configured Remem API. Its launcher supplies the API key through a one-use
anonymous file descriptor rather than process arguments or environment values.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

MAX_RESPONSE_CHARS = 50_000
_ERROR_KINDS = frozenset(
    ("auth", "permission", "namespace", "request", "transient")
)
_TRANSIENT_HTTP_STATUSES = frozenset((429, 500, 502, 503, 504))
_RETRY_DELAYS = (0.25, 0.5)


def _get_base_url() -> str:
    return os.getenv("REMEM_API_URL", "http://localhost:8000").rstrip("/")


def _read_api_key() -> str:
    raw_descriptor = os.environ.pop("REMEM_API_KEY_FD", "")
    os.environ.pop("REMEM_API_KEY", None)
    if not raw_descriptor.isascii() or not raw_descriptor.isdigit():
        return ""
    descriptor = int(raw_descriptor)
    if descriptor < 3:
        return ""

    chunks = bytearray()
    try:
        while len(chunks) <= 8192:
            chunk = os.read(descriptor, 8193 - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
    except OSError:
        return ""
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if not chunks or len(chunks) > 8192:
        return ""
    try:
        return bytes(chunks).decode("utf-8")
    except UnicodeDecodeError:
        return ""


_API_KEY = _read_api_key()

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

server = Server("remem-mcp")


def _get_api_key() -> str:
    return _API_KEY


def _get_default_mode() -> str:
    mode = os.getenv("REMEM_DEFAULT_MODE", "fast").strip().lower()
    return mode if mode in {"fast", "rich"} else "fast"


def _get_default_max_results() -> int:
    raw = os.getenv("REMEM_MAX_RESULTS")
    if not raw:
        return 10
    try:
        value = int(raw)
    except ValueError:
        return 10
    return max(1, min(100, value))


class _RequestError(RuntimeError):
    """Fixed, non-secret failure safe to return through MCP."""

    def __init__(self, status: int | None, kind: str) -> None:
        checked_kind = kind if kind in _ERROR_KINDS else "request"
        checked_status = (
            status
            if isinstance(status, int) and 100 <= status <= 599
            else None
        )
        self.status = checked_status
        self.kind = checked_kind
        rendered_status = (
            str(checked_status)
            if checked_status is not None
            else "unavailable"
        )
        super().__init__(
            "Remem request failed: "
            f"status={rendered_status} kind={checked_kind}"
        )


def _http_error_kind(status: int) -> str:
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if status == 404:
        return "namespace"
    if status in _TRANSIENT_HTTP_STATUSES:
        return "transient"
    return "request"


_sleep = asyncio.sleep


def _truncate_response(text: str, max_size: int = MAX_RESPONSE_CHARS) -> str:
    if len(text) <= max_size:
        return text
    truncated = text[: max_size - 200]
    return truncated + "\n\n[Response truncated. Narrow your query for more detail.]"


def _canonical_resource_id(value: Any, field: str) -> str:
    """Return a canonical UUID safe to interpolate as one URL path segment."""

    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"Invalid {field}: expected a canonical UUID")
    try:
        canonical = str(uuid.UUID(value))
    except (AttributeError, ValueError):
        raise ValueError(
            f"Invalid {field}: expected a canonical UUID"
        ) from None
    if value.lower() != canonical:
        raise ValueError(f"Invalid {field}: expected a canonical UUID")
    return canonical


async def _request(
    method: str,
    path: str,
    *,
    json_body: Any | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    api_key = _get_api_key()
    if not api_key:
        raise _RequestError(None, "auth")

    base_url = _get_base_url()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Idempotency-Key": str(uuid.uuid4()),
    }

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for attempt in range(3):
            try:
                response = await client.request(
                    method,
                    f"{base_url}{path}",
                    headers=headers,
                    json=json_body,
                    params=params,
                )
            except (httpx.TimeoutException, httpx.NetworkError):
                failure = _RequestError(None, "transient")
            except Exception:
                raise _RequestError(None, "request") from None
            else:
                status = getattr(response, "status_code", None)
                if not isinstance(status, int):
                    raise _RequestError(None, "request")
                if 200 <= status < 300:
                    try:
                        return response.json()
                    except Exception:
                        raise _RequestError(status, "request") from None
                failure = _RequestError(
                    status,
                    _http_error_kind(status),
                )
            if failure.kind != "transient" or attempt == 2:
                raise failure
            await _sleep(_RETRY_DELAYS[attempt])
    raise _RequestError(None, "transient")


# ---------------------------------------------------------------------------
# Shared schema fragments
# ---------------------------------------------------------------------------

_NAMESPACES_SCHEMA: dict[str, Any] = {
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "string",
        "minLength": 1,
        "pattern": r".*\S.*",
    },
    "description": (
        "Filter results to these namespaces. "
        'Use ["*"] to search across all namespaces.'
    ),
}

_NAMESPACE_SCHEMA: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "pattern": r".*\S.*",
    "description": (
        "Target namespace for this write operation. "
        "When omitted, the selected key's server-defined default is used."
    ),
}


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="remem_query",
            description="Query Remem for relevant context. Returns the raw JSON response from /v1/query.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "mode": {
                        "type": "string",
                        "description": "Query mode",
                        "enum": ["fast", "rich"],
                        "default": _get_default_mode(),
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Max document results (default 10)",
                        "default": _get_default_max_results(),
                    },
                    "synthesize": {
                        "type": "boolean",
                        "description": "If true, request LLM synthesis (rich mode only)",
                        "default": False,
                    },
                    "filters": {
                        "type": "object",
                        "description": (
                            "Optional Remem query filters. Example: "
                            "{\"checkpoint_project\": [\"remem\"], \"checkpoint_session\": [\"sess-alpha\"]}"
                        ),
                        "additionalProperties": True,
                    },
                    "include_facts": {
                        "type": "boolean",
                        "description": "Include memory layer facts in results",
                    },
                    "entity": {
                        "type": "string",
                        "description": "Scope facts to a specific entity name",
                    },
                    "facts_only_latest": {
                        "type": "boolean",
                        "description": "Only return latest (non-superseded) facts",
                        "default": True,
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="remem_search",
            description="Search your Remem knowledge base and return formatted chunks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {
                        "type": "integer",
                        "description": "Max document results (default 10)",
                        "default": _get_default_max_results(),
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="remem_summarize",
            description="Search and synthesize an answer to a question using Remem (rich mode).",
            inputSchema={
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "Question to answer"},
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["question"],
            },
        ),
        Tool(
            name="remem_get_document",
            description="Fetch a document by ID (raw JSON from GET /v1/documents/{document_id}).",
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {"type": "string", "description": "Document UUID"},
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="remem_get_document_chunks",
            description="Fetch decrypted chunks for a document (GET /v1/documents/{document_id}/chunks).",
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {"type": "string", "description": "Document UUID"},
                    "include_content": {
                        "type": "boolean",
                        "description": "Include decrypted chunk content",
                        "default": True,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max chunks to return (default 200, max 1000)",
                        "default": 200,
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="remem_memory_query",
            description="Query the memory/knowledge graph for current facts about entities.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query for facts"},
                    "entity": {
                        "type": "string",
                        "description": "Optional entity name to scope results to",
                    },
                    "latest_only": {
                        "type": "boolean",
                        "description": "Only return latest (non-superseded) facts",
                        "default": True,
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="remem_list_entities",
            description="List memory entities (people, orgs, projects, etc.) in your knowledge base.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "description": "Filter by entity type (e.g. person, org, project, technology)",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max entities to return (default 50, max 200)",
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Pagination offset (default 0)",
                        "default": 0,
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
            },
        ),
        Tool(
            name="remem_get_entity_facts",
            description="Get facts associated with a specific entity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string", "description": "Entity UUID"},
                    "latest_only": {
                        "type": "boolean",
                        "description": "Only return latest (non-superseded) facts",
                        "default": True,
                    },
                    "fact_type": {
                        "type": "string",
                        "description": "Filter by fact type: fact, preference, episode, decision",
                    },
                    "namespaces": _NAMESPACES_SCHEMA,
                },
                "required": ["entity_id"],
            },
        ),
        Tool(
            name="remem_extract_facts",
            description="Trigger fact extraction for a document (async, returns immediately).",
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {"type": "string", "description": "Document UUID"},
                    "namespace": _NAMESPACE_SCHEMA,
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="remem_ingest",
            description="Ingest a text document into Remem (POST /v1/documents/ingest).",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Optional title"},
                    "content": {"type": "string", "description": "Document content"},
                    "metadata": {"type": "object", "description": "Optional metadata object"},
                    "source": {
                        "type": "string",
                        "description": "Ingestion source (default: api)",
                        "default": "api",
                    },
                    "source_id": {"type": "string", "description": "Optional external source id"},
                    "source_path": {"type": "string", "description": "Optional source path/URI"},
                    "mime_type": {"type": "string", "description": "Optional MIME type"},
                    "return_id": {
                        "type": "boolean",
                        "description": "If true, return the document_id immediately",
                        "default": False,
                    },
                    "namespace": _NAMESPACE_SCHEMA,
                },
                "required": ["content"],
            },
        ),
    ]


def _format_search_results(data: dict[str, Any]) -> str:
    results = []
    for doc in data.get("results", []):
        title = doc.get("title") or "Untitled"
        for chunk in doc.get("chunks", []):
            try:
                score = float(chunk.get("score", 0.0))
            except Exception:
                score = 0.0
            content = chunk.get("content") or ""
            results.append(f"**{title}** (score: {score:.2f})\n{content}\n")

    if not results:
        return "No results found."

    return "\n---\n".join(results)


# ---------------------------------------------------------------------------
# Namespace helpers
# ---------------------------------------------------------------------------

def _resolve_write_namespace(arguments: dict[str, Any]) -> str | None:
    """Return the namespace for a write operation, or *None* to omit."""
    if "namespace" not in arguments:
        return None
    namespace = arguments["namespace"]
    if not isinstance(namespace, str) or not namespace.strip():
        raise _RequestError(None, "request")
    return namespace


def _resolve_read_namespaces(arguments: dict[str, Any]) -> list[str] | None:
    """Return the namespaces list for a read operation, or *None* to omit."""
    if "namespaces" not in arguments:
        return None
    namespaces = arguments["namespaces"]
    if (
        not isinstance(namespaces, list)
        or not namespaces
        or any(
            not isinstance(namespace, str) or not namespace.strip()
            for namespace in namespaces
        )
    ):
        raise _RequestError(None, "request")
    return list(namespaces)


def _inject_namespaces_post(payload: dict[str, Any], namespaces: list[str] | None) -> None:
    """Add ``namespaces`` to a POST JSON payload if provided."""
    if namespaces is not None:
        payload["namespaces"] = namespaces


def _inject_namespaces_get(params: dict[str, Any], namespaces: list[str] | None) -> None:
    """Add ``namespaces`` to GET query params if provided (comma-separated)."""
    if namespaces is not None:
        params["namespaces"] = ",".join(namespaces)


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "remem_query":
            mode = str(arguments.get("mode") or _get_default_mode()).strip().lower()
            if mode not in {"fast", "rich"}:
                mode = _get_default_mode()

            max_results = arguments.get("max_results", _get_default_max_results())
            try:
                max_results = int(max_results)
            except Exception:
                max_results = _get_default_max_results()

            payload: dict[str, Any] = {
                "query": arguments["query"],
                "mode": mode,
                "max_results": max_results,
                "synthesize": bool(arguments.get("synthesize", False)),
            }
            raw_filters = arguments.get("filters")
            if isinstance(raw_filters, dict):
                payload["filters"] = raw_filters
            if "include_facts" in arguments:
                payload["include_facts"] = bool(arguments["include_facts"])
            if arguments.get("entity"):
                payload["entity"] = arguments["entity"]
            if "facts_only_latest" in arguments:
                payload["facts_only_latest"] = bool(arguments["facts_only_latest"])

            _inject_namespaces_post(payload, _resolve_read_namespaces(arguments))

            data = await _request(
                "POST",
                "/v1/query",
                json_body=payload,
            )
            return [TextContent(type="text", text=_truncate_response(json.dumps(data, indent=2)))]

        if name == "remem_search":
            limit = arguments.get("limit", _get_default_max_results())
            try:
                limit = int(limit)
            except Exception:
                limit = _get_default_max_results()

            payload = {
                "query": arguments["query"],
                "mode": "fast",
                "max_results": limit,
            }
            _inject_namespaces_post(payload, _resolve_read_namespaces(arguments))

            data = await _request(
                "POST",
                "/v1/query",
                json_body=payload,
            )
            return [TextContent(type="text", text=_truncate_response(_format_search_results(data)))]

        if name == "remem_summarize":
            payload = {
                "query": arguments["question"],
                "mode": "rich",
                "max_results": _get_default_max_results(),
                "synthesize": True,
            }
            _inject_namespaces_post(payload, _resolve_read_namespaces(arguments))

            data = await _request(
                "POST",
                "/v1/query",
                json_body=payload,
            )
            synthesis = data.get("synthesis")
            if synthesis:
                sources = data.get("sources") or []
                sources_text = "\n".join(str(s) for s in sources) if sources else "(none)"
                text = f"{synthesis}\n\n**Sources:**\n{sources_text}"
                return [TextContent(type="text", text=_truncate_response(text))]
            return [TextContent(type="text", text="No synthesis returned.")]

        if name == "remem_get_document":
            document_id = _canonical_resource_id(
                arguments.get("document_id"),
                "document_id",
            )
            params: dict[str, Any] = {}
            _inject_namespaces_get(params, _resolve_read_namespaces(arguments))
            doc = await _request(
                "GET",
                f"/v1/documents/{document_id}",
                params=params or None,
            )
            return [TextContent(type="text", text=_truncate_response(json.dumps(doc, indent=2)))]

        if name == "remem_get_document_chunks":
            document_id = _canonical_resource_id(
                arguments.get("document_id"),
                "document_id",
            )
            params = {
                "include_content": bool(arguments.get("include_content", True)),
                "limit": int(arguments.get("limit", 200)),
            }
            _inject_namespaces_get(params, _resolve_read_namespaces(arguments))
            chunks = await _request(
                "GET",
                f"/v1/documents/{document_id}/chunks",
                params=params,
            )
            return [TextContent(type="text", text=_truncate_response(json.dumps(chunks, indent=2)))]

        if name == "remem_memory_query":
            payload: dict[str, Any] = {
                "query": arguments["query"],
                "mode": "fast",
                "max_results": 10,
                "include_facts": True,
                "facts_only_latest": bool(arguments.get("latest_only", True)),
            }
            if arguments.get("entity"):
                payload["entity"] = arguments["entity"]

            _inject_namespaces_post(payload, _resolve_read_namespaces(arguments))

            data = await _request("POST", "/v1/query", json_body=payload)

            facts = data.get("facts", [])
            if not facts:
                return [TextContent(type="text", text="No facts found.")]

            lines = []
            for f in facts:
                line = f"- [{f.get('fact_type', 'fact')}] {f.get('content', '')}"
                if f.get("confidence"):
                    line += f" (confidence: {f['confidence']:.1f})"
                if f.get("entities"):
                    line += f" | entities: {', '.join(f['entities'])}"
                lines.append(line)

            return [TextContent(type="text", text=_truncate_response("\n".join(lines)))]

        if name == "remem_list_entities":
            params: dict[str, Any] = {
                "limit": int(arguments.get("limit", 50)),
                "offset": int(arguments.get("offset", 0)),
            }
            if arguments.get("entity_type"):
                params["type"] = arguments["entity_type"]

            _inject_namespaces_get(params, _resolve_read_namespaces(arguments))

            data = await _request("GET", "/v1/entities", params=params)
            entities = data.get("entities", [])
            if not entities:
                return [TextContent(type="text", text="No entities found.")]

            lines = [f"**Entities** ({data.get('total', len(entities))} total)\n"]
            for e in entities:
                lines.append(
                    f"- **{e.get('name', '?')}** ({e.get('entity_type', '?')}) "
                    f"— {e.get('fact_count', 0)} facts, {e.get('mention_count', 0)} mentions "
                    f"[id: {e.get('id', '?')}]"
                )
            return [TextContent(type="text", text=_truncate_response("\n".join(lines)))]

        if name == "remem_get_entity_facts":
            params: dict[str, Any] = {
                "latest_only": bool(arguments.get("latest_only", True)),
            }
            if arguments.get("fact_type"):
                params["fact_type"] = arguments["fact_type"]

            _inject_namespaces_get(params, _resolve_read_namespaces(arguments))

            entity_id = _canonical_resource_id(
                arguments.get("entity_id"),
                "entity_id",
            )
            data = await _request("GET", f"/v1/entities/{entity_id}/facts", params=params)

            entity = data.get("entity", {})
            facts = data.get("facts", [])
            lines = [f"**{entity.get('name', '?')}** ({entity.get('entity_type', '?')})\n"]

            if not facts:
                lines.append("No facts found.")
            else:
                for f in facts:
                    line = f"- [{f.get('fact_type', 'fact')}] {f.get('content', '')}"
                    if f.get("confidence"):
                        line += f" (confidence: {f['confidence']:.1f})"
                    lines.append(line)
                    for rel in f.get("relationships", []):
                        lines.append(f"  -> {rel.get('rel_type', '?')}: {rel.get('related_fact_content', '')}")

            return [TextContent(type="text", text=_truncate_response("\n".join(lines)))]

        if name == "remem_extract_facts":
            doc_id = _canonical_resource_id(
                arguments.get("document_id"),
                "document_id",
            )
            params: dict[str, Any] = {}
            ns = _resolve_write_namespace(arguments)
            if ns:
                params["namespace"] = ns
            data = await _request(
                "POST",
                f"/v1/documents/{doc_id}/extract-facts",
                params=params or None,
            )
            return [TextContent(type="text", text=json.dumps(data, indent=2))]

        if name == "remem_ingest":
            # Preserve empty-string source; only default when the caller
            # omits it entirely (None / missing key). Empty string is a
            # valid label that the API accepts and the worker normalizes.
            source = arguments.get("source")
            if source is None:
                source = "api"
            payload = {
                "title": arguments.get("title"),
                "content": arguments["content"],
                "metadata": arguments.get("metadata") or {},
                "source": source,
                "source_id": arguments.get("source_id"),
                "source_path": arguments.get("source_path"),
                "mime_type": arguments.get("mime_type"),
                "return_id": bool(arguments.get("return_id", False)),
            }
            ns = _resolve_write_namespace(arguments)
            if ns:
                payload["namespace"] = ns
            result = await _request("POST", "/v1/documents/ingest", json_body=payload)
            return [TextContent(type="text", text=_truncate_response(json.dumps(result, indent=2)))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except _RequestError as exc:
        return [TextContent(type="text", text=str(exc))]
    except Exception as exc:
        return [TextContent(type="text", text=_truncate_response(f"Error: {exc}"))]


async def _main_async() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

def main() -> None:
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
