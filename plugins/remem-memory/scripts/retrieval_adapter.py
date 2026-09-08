#!/usr/bin/env python3
"""Map Remem retrieval responses onto the ordinary envelope."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ORIGIN = "python_mcp"
CLI_ORIGIN = "python_cli"
HOOK_ORIGIN = "python_hook"
_ERROR = "invalid retrieval response"
_JSON_SEPARATORS = (", ", ": ")
_CANONICAL_UUID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_DOCUMENT_DROPPED = frozenset({"document_id", "chunks"})
_DOCUMENT_IDENTITY = frozenset({"document_id"})
_CHUNK_DROPPED = frozenset({"chunk_id", "document_id"})
_ENTITY_DROPPED = frozenset({"id"})
_FACT_DROPPED = frozenset({"id", "source_document_id", "relationships"})
_RELATIONSHIP_DROPPED = frozenset({"related_fact_id"})
_ORDINARY_ENVELOPE_FIELDS = frozenset(
    {
        "policy_version",
        "access_mode",
        "trust",
        "origin",
        "records",
        "redaction",
        "truncation",
        "continuation",
    }
)
_CHILD_OWNER_FIELDS = {
    "document": frozenset({"kind", "value", "locators", "chunks"}),
    "chunk": frozenset({"kind", "value", "locators"}),
    "fact": frozenset({"kind", "value", "locators", "relationships"}),
    "entity": frozenset({"kind", "value", "locators", "facts"}),
    "synthesis": frozenset({"kind", "value", "source_locators"}),
}
_CHILD_OWNER_REQUIRED = {
    "document": frozenset({"kind", "value", "locators"}),
    "chunk": frozenset({"kind", "value", "locators"}),
    "fact": frozenset({"kind", "value", "locators"}),
    "entity": frozenset({"kind", "value", "locators"}),
    "synthesis": frozenset({"kind", "value"}),
}
_CHILD_LOCATOR_ROLES = {
    "document": frozenset({"document_id"}),
    "chunk": frozenset({"chunk_id", "document_id"}),
    "fact": frozenset({"fact_id", "source_document_id"}),
    "entity": frozenset({"entity_id"}),
}
_CHILD_MEMBER_FIELDS = frozenset({"locators", "value"})


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


def sensitive_fields_from_environment(environment: object = None) -> tuple[str, ...]:
    """Return additive sensitive fields, or fail closed on invalid configuration."""

    try:
        return _retrieval_policy.load_sensitive_fields(environment)
    except _retrieval_policy.RetrievalEnvelopeError:
        raise RetrievalAdapterError(_ERROR) from None


def serialize_query_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize a /v1/query body as one ordinary python_mcp envelope."""

    return _serialize(
        _query_records(response),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_search_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize selected query documents as one ordinary python_mcp envelope."""

    return _serialize(
        _search_records(response),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_summarize_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize selected query synthesis as one ordinary python_mcp envelope."""

    return _serialize(
        _summarize_records(response),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_memory_query_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize selected query facts as one ordinary python_mcp envelope."""

    return _serialize(
        _memory_query_records(response),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_document_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize GET document detail as one ordinary python_mcp envelope."""

    return _serialize(
        _document_records(response, requested_id),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_document_chunks_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize GET document chunks as one ordinary python_mcp envelope."""

    return _serialize(
        _document_chunks_records(response, requested_id),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_entities_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize GET entity list as one ordinary python_mcp envelope."""

    return _serialize(
        _entities_records(response),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_entity_facts_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize GET entity facts as one ordinary python_mcp envelope."""

    return _serialize(
        _entity_facts_records(response, requested_id),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_extract_facts_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize extract-facts status as one ordinary python_mcp envelope."""

    return _serialize(
        _extract_facts_records(response, requested_id),
        budget,
        sensitive_fields=sensitive_fields,
    )


def serialize_raw_document_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize GET document detail as one raw python_mcp envelope."""

    return _serialize_raw(_document_records(response, requested_id), budget)


def serialize_raw_document_chunks_response(
    response: object,
    *,
    requested_id: object,
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> str:
    """Serialize GET document chunks as one raw python_mcp envelope."""

    return _serialize_raw(
        _document_chunks_records(response, requested_id),
        budget,
    )


def serialize_cli_query_response(
    response: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    prior_redaction: object = None,
    prior_omitted_items: object = 0,
    prior_omitted_characters: object = 0,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize a query body as one ordinary python_cli envelope."""

    return _serialize(
        _query_records(response),
        budget,
        origin=CLI_ORIGIN,
        prior_redaction=prior_redaction,
        prior_omitted_items=prior_omitted_items,
        prior_omitted_characters=prior_omitted_characters,
        sensitive_fields=sensitive_fields,
    )


def serialize_cli_records(
    records: object,
    *,
    budget: object = DEFAULT_OUTPUT_BUDGET,
    prior_redaction: object = None,
    prior_omitted_items: object = 0,
    prior_omitted_characters: object = 0,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize already-mapped records as one ordinary python_cli envelope."""

    return _serialize(
        records,
        budget,
        origin=CLI_ORIGIN,
        prior_redaction=prior_redaction,
        prior_omitted_items=prior_omitted_items,
        prior_omitted_characters=prior_omitted_characters,
        sensitive_fields=sensitive_fields,
    )


def serialize_hook_records(
    records: object,
    *,
    budget: object,
    prior_redaction: object = None,
    prior_omitted_items: object = 0,
    prior_omitted_characters: object = 0,
    sensitive_fields: object | None = None,
) -> str:
    """Serialize already-mapped records as one ordinary python_hook envelope."""

    return _serialize(
        records,
        budget,
        origin=HOOK_ORIGIN,
        prior_redaction=prior_redaction,
        prior_omitted_items=prior_omitted_items,
        prior_omitted_characters=prior_omitted_characters,
        sensitive_fields=sensitive_fields,
    )


def map_query_response(response: object) -> list[dict[str, object]]:
    """Return selected query owners without packing."""

    return _query_records(response)


def parse_ordinary_envelope(value: object) -> dict[str, object]:
    """Validate a closed ordinary child envelope and return it."""

    data = _require_mapping(value)
    if set(data) != _ORDINARY_ENVELOPE_FIELDS:
        raise RetrievalAdapterError(_ERROR)
    if data.get("policy_version") != _retrieval_policy.RETRIEVAL_ENVELOPE_VERSION:
        raise RetrievalAdapterError(_ERROR)
    if data.get("access_mode") != "ordinary":
        raise RetrievalAdapterError(_ERROR)
    if data.get("trust") != "untrusted_source":
        raise RetrievalAdapterError(_ERROR)
    origin = data.get("origin")
    if type(origin) is not str or origin not in _retrieval_policy.RETRIEVAL_ORIGINS:
        raise RetrievalAdapterError(_ERROR)
    records = _validated_child_records(data.get("records"))
    redaction = _closed_count_map(
        data.get("redaction"),
        ("fields", "values", "records"),
    )
    truncation = data.get("truncation")
    if type(truncation) is not dict:
        raise RetrievalAdapterError(_ERROR)
    if set(truncation) != {"truncated", "omitted_items", "omitted_characters"}:
        raise RetrievalAdapterError(_ERROR)
    truncated = truncation.get("truncated")
    omitted_items = truncation.get("omitted_items")
    omitted_characters = truncation.get("omitted_characters")
    if type(truncated) is not bool:
        raise RetrievalAdapterError(_ERROR)
    if type(omitted_items) is not int or omitted_items < 0:
        raise RetrievalAdapterError(_ERROR)
    if type(omitted_characters) is not int or omitted_characters < 0:
        raise RetrievalAdapterError(_ERROR)
    continuation = data.get("continuation")
    if truncated:
        if continuation != {"kind": "narrow_query"}:
            raise RetrievalAdapterError(_ERROR)
    elif continuation is not None or omitted_items != 0 or omitted_characters != 0:
        raise RetrievalAdapterError(_ERROR)
    return {
        "policy_version": _retrieval_policy.RETRIEVAL_ENVELOPE_VERSION,
        "access_mode": "ordinary",
        "trust": "untrusted_source",
        "origin": origin,
        "records": records,
        "redaction": redaction,
        "truncation": {
            "truncated": truncated,
            "omitted_items": omitted_items,
            "omitted_characters": omitted_characters,
        },
        "continuation": continuation,
    }


def _validated_child_records(value: object) -> list[dict[str, object]]:
    if type(value) not in {list, tuple}:
        raise RetrievalAdapterError(_ERROR)
    for item in value:
        _reject_malformed_child_owner(item)
    try:
        return _retrieval_policy._validated_records(value)
    except _retrieval_policy.RetrievalEnvelopeError:
        raise RetrievalAdapterError(_ERROR) from None


def _reject_malformed_child_owner(
    item: object,
    *,
    expected_kind: str | None = None,
) -> None:
    if type(item) is not dict:
        raise RetrievalAdapterError(_ERROR)
    kind = item.get("kind")
    allowed = _CHILD_OWNER_FIELDS.get(kind)
    required = _CHILD_OWNER_REQUIRED.get(kind)
    if allowed is None or required is None:
        raise RetrievalAdapterError(_ERROR)
    if expected_kind is not None and kind != expected_kind:
        raise RetrievalAdapterError(_ERROR)
    keys = set(item)
    if keys - allowed or required - keys:
        raise RetrievalAdapterError(_ERROR)
    roles = _CHILD_LOCATOR_ROLES.get(kind)
    if roles is not None:
        locators = item.get("locators")
        if type(locators) is not dict or set(locators) != roles:
            raise RetrievalAdapterError(_ERROR)
    if "chunks" in item:
        _reject_malformed_child_members(item["chunks"])
    if "facts" in item:
        if type(item["facts"]) not in {list, tuple}:
            raise RetrievalAdapterError(_ERROR)
        for fact in item["facts"]:
            _reject_malformed_child_owner(fact, expected_kind="fact")
    if "relationships" in item:
        _reject_malformed_child_members(item["relationships"])
    if "source_locators" in item:
        sources = item["source_locators"]
        if type(sources) not in {list, tuple}:
            raise RetrievalAdapterError(_ERROR)
        for source in sources:
            if type(source) is not dict or set(source) != {"source_document_id"}:
                raise RetrievalAdapterError(_ERROR)


def _reject_malformed_child_members(value: object) -> None:
    if type(value) not in {list, tuple}:
        raise RetrievalAdapterError(_ERROR)
    for item in value:
        if type(item) is not dict or set(item) != _CHILD_MEMBER_FIELDS:
            raise RetrievalAdapterError(_ERROR)
        locators = item.get("locators")
        if type(locators) is not dict or not locators:
            raise RetrievalAdapterError(_ERROR)


def _closed_count_map(
    value: object,
    keys: tuple[str, ...],
) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(keys):
        raise RetrievalAdapterError(_ERROR)
    counts: dict[str, int] = {}
    for key in keys:
        item = value[key]
        if type(item) is not int or item < 0:
            raise RetrievalAdapterError(_ERROR)
        counts[key] = item
    return counts


def _serialize(
    records: object,
    budget: object,
    *,
    origin: str = ORIGIN,
    prior_redaction: object = None,
    prior_omitted_items: object = 0,
    prior_omitted_characters: object = 0,
    sensitive_fields: object | None = None,
) -> str:
    try:
        extras = (
            _retrieval_policy.load_sensitive_fields()
            if sensitive_fields is None
            else sensitive_fields
        )
        envelope = _retrieval_policy.build_retrieval_envelope(
            records,
            origin=origin,
            sensitive_fields=list(extras),
            budget=budget,
            prior_redaction=prior_redaction,
            prior_omitted_items=prior_omitted_items,
            prior_omitted_characters=prior_omitted_characters,
        )
    except _retrieval_policy.RetrievalEnvelopeError:
        raise RetrievalAdapterError(_ERROR) from None
    return _dumps(envelope)


def _serialize_raw(records: list[dict[str, object]], budget: object) -> str:
    try:
        envelope = _retrieval_policy.build_raw_retrieval_envelope(
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
        _query_document_record(item) for item in _collection(data, "results")
    ]
    records.extend(
        _fact_record(item) for item in _optional_collection(data, "facts")
    )
    records.extend(_summarize_records(data))
    return records


def _search_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    return [
        _query_document_record(item) for item in _collection(data, "results")
    ]


def _query_document_record(item: dict[str, object]) -> dict[str, object]:
    if "document_id" not in item or "chunks" not in item:
        raise RetrievalAdapterError(_ERROR)
    _validate_selected_bounds(item)
    document_id = _canonical_uuid(item["document_id"])
    chunks = _query_chunk_records(item["chunks"], document_id)
    return {
        "kind": "document",
        "locators": {"document_id": document_id},
        "value": _mapping_without(item, _DOCUMENT_DROPPED),
        "chunks": chunks,
    }


def _query_chunk_records(
    value: object,
    document_id: str,
) -> list[dict[str, object]]:
    members = _object_list(value)
    chunks: list[dict[str, object]] = []
    for item in members:
        if "chunk_id" not in item or "document_id" not in item:
            raise RetrievalAdapterError(_ERROR)
        chunk_id = _canonical_uuid(item["chunk_id"])
        chunk_document_id = _canonical_uuid(item["document_id"])
        if chunk_document_id != document_id:
            raise RetrievalAdapterError(_ERROR)
        chunks.append(
            {
                "locators": {
                    "chunk_id": chunk_id,
                    "document_id": document_id,
                },
                "value": _mapping_without(item, _CHUNK_DROPPED),
            }
        )
    return chunks


def _document_records(
    response: object,
    requested_id: object,
) -> list[dict[str, object]]:
    data = _require_mapping(response)
    _validate_selected_bounds(data)
    document_id = _verified_id(data, "document_id", requested_id)
    return [
        {
            "kind": "document",
            "locators": {"document_id": document_id},
            "value": _mapping_without(data, _DOCUMENT_IDENTITY),
        }
    ]


def _document_chunks_records(
    response: object,
    requested_id: object,
) -> list[dict[str, object]]:
    data = _require_mapping(response)
    _validate_selected_bounds(data)
    document_id = _verified_id(data, "document_id", requested_id)
    if "chunks" not in data:
        raise RetrievalAdapterError(_ERROR)
    chunks_raw = data["chunks"]
    members = _object_list(chunks_raw)
    chunks: list[dict[str, object]] = []
    for item in members:
        if "chunk_id" not in item:
            raise RetrievalAdapterError(_ERROR)
        chunk_id = _canonical_uuid(item["chunk_id"])
        if "document_id" in item:
            child_id = item["document_id"]
            if child_id is None:
                raise RetrievalAdapterError(_ERROR)
            if _canonical_uuid(child_id) != document_id:
                raise RetrievalAdapterError(_ERROR)
        chunks.append(
            {
                "locators": {
                    "chunk_id": chunk_id,
                    "document_id": document_id,
                },
                "value": _mapping_without(item, _CHUNK_DROPPED),
            }
        )
    return [
        {
            "kind": "document",
            "locators": {"document_id": document_id},
            "value": _mapping_without(data, _DOCUMENT_DROPPED),
            "chunks": chunks,
        }
    ]


def _entities_records(response: object) -> list[dict[str, object]]:
    data = _require_mapping(response)
    return [_entity_record(item) for item in _collection(data, "entities")]


def _entity_record(item: dict[str, object]) -> dict[str, object]:
    if "id" not in item:
        raise RetrievalAdapterError(_ERROR)
    _validate_selected_bounds(item)
    entity_id = _canonical_uuid(item["id"])
    return {
        "kind": "entity",
        "locators": {"entity_id": entity_id},
        "value": _mapping_without(item, _ENTITY_DROPPED),
    }


def _entity_facts_records(
    response: object,
    requested_id: object,
) -> list[dict[str, object]]:
    data = _require_mapping(response)
    if "entity" not in data:
        raise RetrievalAdapterError(_ERROR)
    entity = data["entity"]
    if type(entity) is not dict:
        raise RetrievalAdapterError(_ERROR)
    if "id" not in entity:
        raise RetrievalAdapterError(_ERROR)
    entity_id = _canonical_uuid(entity["id"])
    requested = _canonical_uuid(requested_id)
    if entity_id != requested:
        raise RetrievalAdapterError(_ERROR)
    if "facts" not in data:
        raise RetrievalAdapterError(_ERROR)
    _validate_selected_bounds({"entity": entity, "facts": data["facts"]})
    facts = [_fact_record(item) for item in _object_list(data["facts"])]
    return [
        {
            "kind": "entity",
            "locators": {"entity_id": entity_id},
            "value": _mapping_without(entity, _ENTITY_DROPPED),
            "facts": facts,
        }
    ]


def _extract_facts_records(
    response: object,
    requested_id: object,
) -> list[dict[str, object]]:
    data = _require_mapping(response)
    _validate_selected_bounds(data)
    document_id = _verified_id(data, "document_id", requested_id)
    return [
        {
            "kind": "document",
            "locators": {"document_id": document_id},
            "value": _mapping_without(data, frozenset({"document_id"})),
        }
    ]


def _verified_id(
    data: dict[str, object],
    field: str,
    requested_id: object,
) -> str:
    if field not in data:
        raise RetrievalAdapterError(_ERROR)
    actual = _canonical_uuid(data[field])
    requested = _canonical_uuid(requested_id)
    if actual != requested:
        raise RetrievalAdapterError(_ERROR)
    return actual


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
    _validate_selected_bounds(item)
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


def _validate_selected_bounds(value: object) -> None:
    try:
        _retrieval_policy._scan(value, 1, set(), 0)
    except _retrieval_policy.RetrievalEnvelopeError:
        raise RetrievalAdapterError(_ERROR) from None


def _dumps(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=_JSON_SEPARATORS,
    )


__all__ = [
    "CLI_ORIGIN",
    "DEFAULT_OUTPUT_BUDGET",
    "HOOK_ORIGIN",
    "ORIGIN",
    "RetrievalAdapterError",
    "map_query_response",
    "parse_ordinary_envelope",
    "sensitive_fields_from_environment",
    "serialize_cli_query_response",
    "serialize_cli_records",
    "serialize_document_chunks_response",
    "serialize_document_response",
    "serialize_entities_response",
    "serialize_entity_facts_response",
    "serialize_extract_facts_response",
    "serialize_hook_records",
    "serialize_memory_query_response",
    "serialize_query_response",
    "serialize_raw_document_chunks_response",
    "serialize_raw_document_response",
    "serialize_search_response",
    "serialize_summarize_response",
]
