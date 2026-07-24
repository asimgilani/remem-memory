#!/usr/bin/env python3
"""Query Remem for session memory using the raw API (no MCP required)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PLUGIN_SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "remem-memory"
    / "scripts"
)
if str(_PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))

import remem_api  # noqa: E402

_MODE_CHOICES = ("fast", "rich")
_DEFAULT_API_URL = "https://api.remem.io"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return max(1, int(value))
    except ValueError:
        return default


def _read_query(args: argparse.Namespace) -> str:
    if args.query_file:
        return Path(args.query_file).read_text(encoding="utf-8").strip()
    if args.query:
        return args.query.strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def _parse_json_object(raw: str | None, *, flag: str) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{flag} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{flag} must decode to a JSON object.")
    return parsed


def build_filters(args: argparse.Namespace) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    if args.checkpoint_project:
        filters["checkpoint_project"] = args.checkpoint_project
    if args.checkpoint_session:
        filters["checkpoint_session"] = args.checkpoint_session
    if args.checkpoint_kind:
        filters["checkpoint_kinds"] = args.checkpoint_kind

    extra_filters = _parse_json_object(args.filters_json, flag="--filters-json")
    filters.update(extra_filters)
    return filters


def build_query_payload(args: argparse.Namespace) -> dict[str, Any]:
    query = _read_query(args)
    if not query:
        raise ValueError("query is required (pass --query, --query-file, or stdin).")
    if args.max_results < 1:
        raise ValueError("--max-results must be >= 1.")

    payload: dict[str, Any] = {"query": query, "mode": args.mode, "max_results": args.max_results}
    if args.synthesize:
        payload["synthesize"] = True

    filters = build_filters(args)
    if filters:
        payload["filters"] = filters
    if args.include_facts:
        payload["include_facts"] = True
    if args.entity:
        payload["entity"] = args.entity
    return payload


def query_remem(*, api_url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    api = remem_api.RememAPI(
        api_url,
        api_key,
        allow_local_dev=True,
    )
    return api.query_payload(
        payload,
        timeout=45.0,
    )


def append_recall_log(path: str, record: dict[str, Any]) -> None:
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        allow_abbrev=False,
    )
    parser.add_argument("--query", help="Query text.")
    parser.add_argument("--query-file", help="Read query text from file.")
    parser.add_argument("--mode", choices=_MODE_CHOICES, default=os.getenv("REMEM_DEFAULT_MODE", "fast"))
    parser.add_argument("--max-results", type=int, default=_int_env("REMEM_MAX_RESULTS", 10))
    parser.add_argument("--synthesize", action="store_true", help="Request LLM synthesis (rich mode only).")
    parser.add_argument("--checkpoint-project", action="append", default=[], help="Checkpoint project filter.")
    parser.add_argument("--checkpoint-session", action="append", default=[], help="Checkpoint session filter.")
    parser.add_argument("--checkpoint-kind", action="append", default=[], help="Checkpoint kind filter.")
    parser.add_argument("--filters-json", help="Additional filters as JSON object.")
    parser.add_argument("--include-facts", action="store_true", help="Include memory layer facts in results.")
    parser.add_argument("--entity", default=None, help="Scope facts to a specific entity name.")
    parser.add_argument(
        "--api-url",
        default=os.getenv("REMEM_API_URL", _DEFAULT_API_URL),
        help="Remem API base URL.",
    )
    parser.add_argument("--output", help="Write API response JSON to this file.")
    parser.add_argument("--log-file", default=".remem/session-recalls.ndjson", help="NDJSON recall log file.")
    parser.add_argument("--no-log", action="store_true", help="Skip writing local recall log entry.")
    parser.add_argument("--dry-run", action="store_true", help="Print payload and exit.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = list(argv or sys.argv[1:])
    if any(
        argument.split("=", 1)[0].startswith("--api-k")
        for argument in arguments
    ):
        print(
            "error: --api-key is not supported; use remem-memory auth",
            file=sys.stderr,
        )
        return 2
    args = parse_args(arguments)
    try:
        payload = build_query_payload(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    response: dict[str, Any] | None = None
    if args.dry_run:
        output = {"payload": payload, "response": None}
        print(json.dumps(output, indent=2, ensure_ascii=True))
        return 0

    try:
        api_url, api_key = remem_api.resolve_api_access(args.api_url)
    except Exception:
        print("error: invalid Remem API URL", file=sys.stderr)
        return 2
    if not api_key:
        print("error: Remem credential is not configured", file=sys.stderr)
        return 2

    try:
        response = query_remem(
            api_url=api_url,
            api_key=api_key,
            payload=payload,
        )
    except remem_api.RememAPIError:
        print("error: query failed", file=sys.stderr)
        return 1

    record = {"timestamp": _utc_now_iso(), "payload": payload, "response": response}
    if not args.no_log:
        append_recall_log(args.log_file, record)

    output = {"payload": payload, "response": response}
    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2, ensure_ascii=True), encoding="utf-8")
    print(json.dumps(output, indent=2, ensure_ascii=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
