#!/usr/bin/env python3
"""Ordinary structured retrieval envelope: redact, then truncate, then serialize."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Callable

from memory_policy import (
    contains_explicit_secret,
    contains_secret,
    is_credential_field_name,
    is_off_record,
)

RETRIEVAL_ENVELOPE_VERSION = "retrieval-envelope-v1"
DEFAULT_OUTPUT_BUDGET = 50_000
REDACTION_MARKER = "[redacted]"
RETRIEVAL_ORIGINS = frozenset(
    {
        "python_hook",
        "python_cli",
        "python_mcp",
        "openclaw_tool",
        "openclaw_cli",
    }
)
RETRIEVAL_KINDS = frozenset(
    {
        "document",
        "chunk",
        "fact",
        "entity",
        "synthesis",
    }
)
_CONTINUATION = {"kind": "narrow_query"}
_MAX_DEPTH = 32
_MAX_NODES = 4096
_MAX_SENSITIVE_FIELDS = 64
_MAX_SENSITIVE_FIELD_LENGTH = 128
_ERROR_INVALID_ORIGIN = "invalid retrieval origin"
_ERROR_INVALID_BUDGET = "invalid retrieval budget"
_ERROR_BUDGET_TOO_SMALL = "retrieval budget below minimum envelope"
_ERROR_INVALID_RECORDS = "invalid retrieval records"
_ERROR_INVALID_SENSITIVE_FIELDS = "invalid sensitive fields"
_ERROR_UNSUPPORTED_VALUE = "unsupported retrieval value"
_ERROR_EXCEEDS_BOUNDS = "retrieval input exceeds bounds"
_JSON_SEPARATORS = (", ", ": ")


class RetrievalEnvelopeError(ValueError):
    """Fixed bounded validation failure for ordinary retrieval envelopes."""


class _Counts:
    __slots__ = ("fields", "values", "records")

    def __init__(self) -> None:
        self.fields = 0
        self.values = 0
        self.records = 0


def build_retrieval_envelope(
    records: object,
    *,
    origin: object,
    sensitive_fields: object = (),
    budget: object = DEFAULT_OUTPUT_BUDGET,
) -> dict[str, object]:
    """Return a closed ordinary-recall envelope for locally selected records.

    Path and generated-ID entropy exemptions from automatic capture do not
    apply to retrieved prose. Serialized JSON is never sliced.
    """

    if type(origin) is not str or origin not in RETRIEVAL_ORIGINS:
        raise RetrievalEnvelopeError(_ERROR_INVALID_ORIGIN)
    if type(budget) is not int or budget < 1:
        raise RetrievalEnvelopeError(_ERROR_INVALID_BUDGET)
    extras = _validated_sensitive_fields(sensitive_fields)
    items = _validated_records(records)
    redacted, counts = _redact_records(items, extras)
    redaction = {
        "fields": counts.fields,
        "values": counts.values,
        "records": counts.records,
    }
    return _pack(origin, redacted, redaction, budget)


def _validated_sensitive_fields(value: object) -> frozenset[str]:
    if value is None:
        value = ()
    if type(value) not in {list, tuple}:
        raise RetrievalEnvelopeError(_ERROR_INVALID_SENSITIVE_FIELDS)
    if len(value) > _MAX_SENSITIVE_FIELDS:
        raise RetrievalEnvelopeError(_ERROR_INVALID_SENSITIVE_FIELDS)
    extras: set[str] = set()
    for item in value:
        if type(item) is not str or not item.strip():
            raise RetrievalEnvelopeError(_ERROR_INVALID_SENSITIVE_FIELDS)
        if len(item) > _MAX_SENSITIVE_FIELD_LENGTH:
            raise RetrievalEnvelopeError(_ERROR_INVALID_SENSITIVE_FIELDS)
        extras.add(item.strip().lower().replace("-", "_"))
    return frozenset(extras)


def _validated_records(value: object) -> list[dict[str, object]]:
    if type(value) not in {list, tuple}:
        raise RetrievalEnvelopeError(_ERROR_INVALID_RECORDS)
    records: list[dict[str, object]] = []
    nodes = 0
    for item in value:
        if type(item) is not dict:
            raise RetrievalEnvelopeError(_ERROR_INVALID_RECORDS)
        kind = item.get("kind")
        if type(kind) is not str or kind not in RETRIEVAL_KINDS or "value" not in item:
            raise RetrievalEnvelopeError(_ERROR_INVALID_RECORDS)
        nodes = _scan(item["value"], 1, set(), nodes)
        records.append({"kind": kind, "value": item["value"]})
    return records


def _scan(
    value: object,
    depth: int,
    stack: set[int],
    nodes: int,
) -> int:
    if depth > _MAX_DEPTH:
        raise RetrievalEnvelopeError(_ERROR_EXCEEDS_BOUNDS)
    nodes += 1
    if nodes > _MAX_NODES:
        raise RetrievalEnvelopeError(_ERROR_EXCEEDS_BOUNDS)
    kind = type(value)
    if kind is str or kind is bool or value is None or kind is int:
        return nodes
    if kind is float:
        if not math.isfinite(value):
            raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)
        return nodes
    if kind is dict:
        ident = id(value)
        if ident in stack:
            raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)
        stack.add(ident)
        for key, item in value.items():
            if type(key) is not str:
                raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)
            nodes = _scan(key, depth + 1, stack, nodes)
            nodes = _scan(item, depth + 1, stack, nodes)
        stack.remove(ident)
        return nodes
    if kind is list:
        ident = id(value)
        if ident in stack:
            raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)
        stack.add(ident)
        for item in value:
            nodes = _scan(item, depth + 1, stack, nodes)
        stack.remove(ident)
        return nodes
    raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)


def _redact_records(
    records: list[dict[str, object]],
    extras: frozenset[str],
) -> tuple[list[dict[str, object]], _Counts]:
    counts = _Counts()
    kept: list[dict[str, object]] = []
    for record in records:
        value = record["value"]
        if _contains_off_record(value):
            counts.records += 1
            continue
        kept.append(
            {
                "kind": record["kind"],
                "value": _redact(value, extras, counts),
            }
        )
    return kept, counts


def _contains_off_record(value: object) -> bool:
    try:
        serialized = _dumps(value)
    except (TypeError, ValueError):
        raise RetrievalEnvelopeError(_ERROR_UNSUPPORTED_VALUE)
    if is_off_record(serialized):
        return True
    return _walk_off_record(value)


def _walk_off_record(value: object) -> bool:
    kind = type(value)
    if kind is str:
        return is_off_record(value)
    if kind is dict:
        for key, item in value.items():
            if is_off_record(key) or _walk_off_record(item):
                return True
        return False
    if kind is list:
        return any(_walk_off_record(item) for item in value)
    return False


def _redact(
    value: object,
    extras: frozenset[str],
    counts: _Counts,
) -> object:
    kind = type(value)
    if kind is str:
        if _secret_text(value):
            counts.values += 1
            return REDACTION_MARKER
        return value
    if kind is dict:
        out: dict[str, object] = {}
        for key, item in value.items():
            if _drop_key(key, extras) or _secret_text(key):
                counts.fields += 1
                continue
            out[key] = _redact(item, extras, counts)
        return out
    if kind is list:
        return [_redact(item, extras, counts) for item in value]
    return value


def _drop_key(key: str, extras: frozenset[str]) -> bool:
    if is_credential_field_name(key):
        return True
    return key.strip().lower().replace("-", "_") in extras


def _secret_text(text: str) -> bool:
    if contains_secret(text):
        return True
    return contains_explicit_secret(_dumps(text))


def _pack(
    origin: str,
    records: list[dict[str, object]],
    redaction: dict[str, int],
    budget: int,
) -> dict[str, object]:
    full = _envelope(
        origin,
        records,
        redaction,
        _truncation(False, 0, 0),
        None,
    )
    if _utf8_size(full) <= budget:
        return full
    kept: list[dict[str, object]] = []
    inner_counts: list[tuple[int, int]] = []
    omitted_items = 0
    omitted_characters = 0
    for record in records:
        kind = record["kind"]
        value = record["value"]
        trial = {"kind": kind, "value": value}
        if _fits(
            origin,
            kept + [trial],
            redaction,
            omitted_items,
            omitted_characters,
            budget,
        ):
            kept.append(trial)
            inner_counts.append((0, 0))
            continue

        def make_env(
            candidate: object,
            extra_oi: int,
            extra_oc: int,
            current_kind: str = kind,
            snapshot: list[dict[str, object]] = list(kept),
            base_oi: int = omitted_items,
            base_oc: int = omitted_characters,
        ) -> dict[str, object]:
            return _truncating_envelope(
                origin,
                snapshot + [{"kind": current_kind, "value": candidate}],
                redaction,
                base_oi + extra_oi,
                base_oc + extra_oc,
            )

        fitted, extra_oi, extra_oc = _fit_value(value, make_env, budget)
        if fitted is None:
            omitted_items += 1
            continue
        kept.append({"kind": kind, "value": fitted})
        inner_counts.append((extra_oi, extra_oc))
        omitted_items += extra_oi
        omitted_characters += extra_oc
    packed = _truncating_envelope(
        origin,
        kept,
        redaction,
        omitted_items,
        omitted_characters,
    )
    while kept and _utf8_size(packed) > budget:
        kept.pop()
        extra_oi, extra_oc = inner_counts.pop()
        omitted_items = omitted_items - extra_oi + 1
        omitted_characters -= extra_oc
        packed = _truncating_envelope(
            origin,
            kept,
            redaction,
            omitted_items,
            omitted_characters,
        )
    if _utf8_size(packed) > budget:
        raise RetrievalEnvelopeError(_ERROR_BUDGET_TOO_SMALL)
    return packed


def _fit_value(
    value: object,
    make_env: Callable[[object, int, int], dict[str, object]],
    budget: int,
) -> tuple[object | None, int, int]:
    if _utf8_size(make_env(value, 0, 0)) <= budget:
        return value, 0, 0
    kind = type(value)
    if kind is str:
        return _fit_string(value, make_env, budget)
    if kind is dict:
        return _fit_mapping(value, make_env, budget)
    if kind is list:
        return _fit_list(value, make_env, budget)
    return None, 0, 0


def _fit_string(
    text: str,
    make_env: Callable[[object, int, int], dict[str, object]],
    budget: int,
) -> tuple[object | None, int, int]:
    if _utf8_size(make_env("", 0, len(text))) > budget:
        return None, 0, 0
    lo = 0
    hi = len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        extra_oc = len(text) - mid
        if _utf8_size(make_env(text[:mid], 0, extra_oc)) <= budget:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo], 0, len(text) - lo


def _fit_mapping(
    value: Mapping[str, object],
    make_env: Callable[[object, int, int], dict[str, object]],
    budget: int,
) -> tuple[object | None, int, int]:
    if _utf8_size(make_env({}, 0, 0)) > budget:
        return None, 0, 0
    out: dict[str, object] = {}
    omitted_items = 0
    omitted_characters = 0
    for key, item in value.items():
        prefix = dict(out)
        trial = dict(prefix)
        trial[key] = item
        trial_size = _utf8_size(
            make_env(trial, omitted_items, omitted_characters)
        )
        if trial_size <= budget:
            out[key] = item
            continue

        def child_env(
            candidate: object,
            extra_oi: int,
            extra_oc: int,
            current_key: str = key,
            snapshot: dict[str, object] = prefix,
            base_oi: int = omitted_items,
            base_oc: int = omitted_characters,
        ) -> dict[str, object]:
            nested = dict(snapshot)
            nested[current_key] = candidate
            return make_env(nested, base_oi + extra_oi, base_oc + extra_oc)

        fitted, extra_oi, extra_oc = _fit_value(item, child_env, budget)
        if fitted is None:
            omitted_items += 1
            continue
        out[key] = fitted
        omitted_items += extra_oi
        omitted_characters += extra_oc
    return out, omitted_items, omitted_characters


def _fit_list(
    value: list[object],
    make_env: Callable[[object, int, int], dict[str, object]],
    budget: int,
) -> tuple[object | None, int, int]:
    if _utf8_size(make_env([], 0, 0)) > budget:
        return None, 0, 0
    out: list[object] = []
    omitted_items = 0
    omitted_characters = 0
    for item in value:
        snapshot = list(out)
        trial = snapshot + [item]
        trial_size = _utf8_size(
            make_env(trial, omitted_items, omitted_characters)
        )
        if trial_size <= budget:
            out.append(item)
            continue

        def child_env(
            candidate: object,
            extra_oi: int,
            extra_oc: int,
            prefix: list[object] = snapshot,
            base_oi: int = omitted_items,
            base_oc: int = omitted_characters,
        ) -> dict[str, object]:
            return make_env(
                prefix + [candidate],
                base_oi + extra_oi,
                base_oc + extra_oc,
            )

        fitted, extra_oi, extra_oc = _fit_value(item, child_env, budget)
        if fitted is None:
            omitted_items += 1
            continue
        out.append(fitted)
        omitted_items += extra_oi
        omitted_characters += extra_oc
    return out, omitted_items, omitted_characters


def _fits(
    origin: str,
    records: list[dict[str, object]],
    redaction: dict[str, int],
    omitted_items: int,
    omitted_characters: int,
    budget: int,
) -> bool:
    return (
        _utf8_size(
            _truncating_envelope(
                origin,
                records,
                redaction,
                omitted_items,
                omitted_characters,
            )
        )
        <= budget
    )


def _truncating_envelope(
    origin: str,
    records: list[dict[str, object]],
    redaction: dict[str, int],
    omitted_items: int,
    omitted_characters: int,
) -> dict[str, object]:
    return _envelope(
        origin,
        records,
        redaction,
        _truncation(True, omitted_items, omitted_characters),
        dict(_CONTINUATION),
    )


def _envelope(
    origin: str,
    records: list[dict[str, object]],
    redaction: dict[str, int],
    truncation: dict[str, object],
    continuation: object,
) -> dict[str, object]:
    return {
        "policy_version": RETRIEVAL_ENVELOPE_VERSION,
        "access_mode": "ordinary",
        "trust": "untrusted_source",
        "origin": origin,
        "records": records,
        "redaction": redaction,
        "truncation": truncation,
        "continuation": continuation,
    }


def _truncation(
    truncated: bool,
    omitted_items: int,
    omitted_characters: int,
) -> dict[str, object]:
    return {
        "truncated": truncated,
        "omitted_items": omitted_items,
        "omitted_characters": omitted_characters,
    }


def _dumps(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=_JSON_SEPARATORS,
    )


def _utf8_size(value: object) -> int:
    return len(_dumps(value).encode("utf-8"))


__all__ = [
    "DEFAULT_OUTPUT_BUDGET",
    "REDACTION_MARKER",
    "RETRIEVAL_ENVELOPE_VERSION",
    "RETRIEVAL_KINDS",
    "RETRIEVAL_ORIGINS",
    "RetrievalEnvelopeError",
    "build_retrieval_envelope",
]
