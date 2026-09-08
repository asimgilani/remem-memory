#!/usr/bin/env python3
"""Map MCP query/search responses onto the ordinary retrieval envelope."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ORIGIN = "python_mcp"
_ERROR = "invalid retrieval response"
_JSON_SEPARATORS = (", ", ": ")


class RetrievalAdapterError(ValueError):
    """Fixed bounded failure for MCP query/search envelope mapping."""


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
        {"kind": "fact", "value": item}
        for item in _collection(data, "facts")
    )
    if "synthesis" in data and data["synthesis"] is not None:
        records.append(
            {
                "kind": "synthesis",
                "value": _synthesis_value(data),
            }
        )
    return records


def _search_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    return [
        {"kind": "document", "value": item}
        for item in _collection(data, "results")
    ]


def _synthesis_value(data: dict[str, object]) -> dict[str, object]:
    if "sources" not in data:
        sources: object = []
    else:
        sources = data["sources"]
        if type(sources) is not list:
            raise RetrievalAdapterError(_ERROR)
    return {"text": data["synthesis"], "sources": sources}


def _collection(data: dict[str, object], key: str) -> list[dict[str, object]]:
    if key not in data:
        return []
    value = data[key]
    if type(value) is not list:
        raise RetrievalAdapterError(_ERROR)
    members: list[dict[str, object]] = []
    for item in value:
        if type(item) is not dict:
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
    "serialize_query_response",
    "serialize_search_response",
]
