#!/usr/bin/env python3
"""Map MCP query, search, summarize, and memory_query onto the ordinary envelope."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ORIGIN = "python_mcp"
_ERROR = "invalid retrieval response"
_JSON_SEPARATORS = (", ", ": ")
_CANONICAL_UUID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_FACT_DROPPED = frozenset({"id", "source_document_id", "relationships"})
_RELATIONSHIP_DROPPED = frozenset({"related_fact_id"})


class RetrievalAdapterError(ValueError):
    """Fixed bounded failure for MCP retrieval envelope mapping."""


def _sibling_path(name: str) -> Path:
    path = Path(__file__).resolve().parent / f"{name}.py"
    if path.is_symlink() or not path.is_file():
        raise RetrievalAdapterError(_ERROR)
    return path


def _load_local_module(name: str):
    path = _sibling_path(name)
    resolved = path.resolve()
    existing = sys.modules.get(name)
    if existing is not None:
        current = getattr(existing, "__file__", None)
        if isinstance(current, str):
            try:
                current_path = Path(current)
                if (
                    not current_path.is_symlink()
                    and current_path.resolve() == resolved
                ):
                    return existing
            except (OSError, RuntimeError):
                pass
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RetrievalAdapterError(_ERROR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load_local_module("memory_policy")
_retrieval_policy = _load_local_module("retrieval_policy")
DEFAULT_OUTPUT_BUDGET = _retrieval_policy.DEFAULT_OUTPUT_BUDGET


def serialize_query_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize a /v1/query body as one ordinary python_mcp envelope."""

    return _serialize(_query_records(response), budget)


def serialize_search_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize selected query documents as one ordinary python_mcp envelope."""

    return _serialize(_search_records(response), budget)


def serialize_summarize_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize selected query synthesis as one ordinary python_mcp envelope."""

    return _serialize(_summarize_records(response), budget)


def serialize_memory_query_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize selected query facts as one ordinary python_mcp envelope."""

    return _serialize(_memory_query_records(response), budget)


def _serialize(records: list[dict[str, object]], budget: object) -> str:
    try:
        envelope = _retrieval_policy.build_retrieval_envelope(
            records,
            origin=ORIGIN,
            budget=budget,
        )
    except _retrieval_policy.RetrievalEnvelopeError:
        raise RetrievalAdapterError(_ERROR) from None
    return _dumps(envelope)


def _query_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    records = [
        {"kind": "document", "value": item}
        for item in _collection(data, "results")
    ]
    records.extend(
        _fact_record(item) for item in _optional_collection(data, "facts")
    )
    records.extend(_summarize_records(data))
    return records


def _search_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    return [
        {"kind": "document", "value": item}
        for item in _collection(data, "results")
    ]


def _summarize_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    if "synthesis" not in data or data["synthesis"] is None:
        return []
    text = data["synthesis"]
    if type(text) is not str:
        raise RetrievalAdapterError(_ERROR)
    record: dict[str, object] = {"kind": "synthesis", "value": text}
    source_locators = _source_locators(data)
    if source_locators:
        record["source_locators"] = source_locators
    return [record]


def _memory_query_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    return [_fact_record(item) for item in _optional_collection(data, "facts")]


def _source_locators(data: dict[str, object]) -> list[dict[str, str]] | None:
    if "sources" not in data:
        return None
    raw = data["sources"]
    if raw is None:
        raise RetrievalAdapterError(_ERROR)
    members = _string_list(raw)
    if not members:
        return None
    return [{"source_document_id": _canonical_uuid(item)} for item in members]


def _fact_record(item: dict[str, object]) -> dict[str, object]:
    if "id" not in item or "source_document_id" not in item:
        raise RetrievalAdapterError(_ERROR)
    locators = {
        "fact_id": _canonical_uuid(item["id"]),
        "source_document_id": _canonical_uuid(item["source_document_id"]),
    }
    relationships = None
    if "relationships" in item:
        relationships = _relationship_records(item["relationships"])
    record: dict[str, object] = {
        "kind": "fact",
        "value": _mapping_without(item, _FACT_DROPPED),
        "locators": locators,
    }
    if relationships:
        record["relationships"] = relationships
    return record


def _relationship_records(value: object) -> list[dict[str, object]] | None:
    members = _object_list(value)
    if not members:
        return None
    relationships: list[dict[str, object]] = []
    for item in members:
        if "related_fact_id" not in item:
            raise RetrievalAdapterError(_ERROR)
        relationships.append(
            {
                "value": _mapping_without(item, _RELATIONSHIP_DROPPED),
                "locators": {
                    "related_fact_id": _canonical_uuid(item["related_fact_id"]),
                },
            }
        )
    return relationships


def _mapping_without(
    item: dict[str, object],
    dropped: frozenset[str],
) -> dict[str, object]:
    return {key: value for key, value in item.items() if key not in dropped}


def _canonical_uuid(value: object) -> str:
    if type(value) is not str or _CANONICAL_UUID.fullmatch(value) is None:
        raise RetrievalAdapterError(_ERROR)
    return value


def _collection(data: dict[str, object], key: str) -> list[dict[str, object]]:
    if key not in data:
        return []
    return _object_list(data[key])


def _optional_collection(data: dict[str, object], key: str) -> list[dict[str, object]]:
    if key not in data or data[key] is None:
        return []
    return _object_list(data[key])


def _object_list(value: object) -> list[dict[str, object]]:
    if type(value) is not list:
        raise RetrievalAdapterError(_ERROR)
    members: list[dict[str, object]] = []
    for item in value:
        if type(item) is not dict:
            raise RetrievalAdapterError(_ERROR)
        members.append(item)
    return members


def _string_list(value: object) -> list[str]:
    if type(value) is not list:
        raise RetrievalAdapterError(_ERROR)
    members: list[str] = []
    for item in value:
        if type(item) is not str:
            raise RetrievalAdapterError(_ERROR)
        members.append(item)
    return members


def _require_mapping(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise RetrievalAdapterError(_ERROR)
    return value


def _dumps(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=_JSON_SEPARATORS,
    )


__all__ = [
    "DEFAULT_OUTPUT_BUDGET",
    "ORIGIN",
    "RetrievalAdapterError",
    "serialize_memory_query_response",
    "serialize_query_response",
    "serialize_search_response",
    "serialize_summarize_response",
]
