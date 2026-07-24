#!/usr/bin/env python3
"""Roll up local checkpoint logs into a session summary and optionally ingest it."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict
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

try:
    from scripts.remem_checkpoint import (
        _consume_local_dev_capability,
        _consume_route_descriptor,
        _slug,
        append_checkpoint_log,
        ingest_checkpoint,
    )
except ModuleNotFoundError:
    import importlib.util

    # Resolve symlinked entrypoints (for ~/.local/bin installs) to locate sibling script reliably.
    _CHECKPOINT_PATH = Path(__file__).resolve().with_name("remem_checkpoint.py")
    _SPEC = importlib.util.spec_from_file_location("remem_checkpoint", _CHECKPOINT_PATH)
    _MODULE = importlib.util.module_from_spec(_SPEC)
    assert _SPEC and _SPEC.loader
    _SPEC.loader.exec_module(_MODULE)
    _consume_local_dev_capability = (
        _MODULE._consume_local_dev_capability
    )
    _consume_route_descriptor = _MODULE._consume_route_descriptor
    _slug = _MODULE._slug
    append_checkpoint_log = _MODULE.append_checkpoint_log
    ingest_checkpoint = _MODULE.ingest_checkpoint

_DEFAULT_API_URL = "https://api.remem.io"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_checkpoint_log(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    log_path = Path(path)
    if not log_path.exists():
        return records
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def _dedupe(items: list[str]) -> list[str]:
    return list(OrderedDict.fromkeys(item for item in items if item))


def filter_records(
    records: list[dict[str, Any]],
    *,
    project: str | None,
    session_id: str | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in records:
        payload = row.get("payload") or {}
        metadata = payload.get("metadata") or {}
        if project and metadata.get("project") != project:
            continue
        if session_id and metadata.get("session_id") != session_id:
            continue
        filtered.append(row)
    return filtered


def build_rollup_content(
    *,
    project: str,
    session_id: str,
    records: list[dict[str, Any]],
    summary: str,
) -> str:
    decisions: list[str] = []
    open_questions: list[str] = []
    next_actions: list[str] = []
    files_touched: list[str] = []
    checkpoints: list[str] = []

    for row in records:
        payload = row.get("payload") or {}
        title = str(payload.get("title") or "").strip()
        if title:
            checkpoints.append(title)
        metadata = payload.get("metadata") or {}
        decisions.extend(str(x) for x in (metadata.get("decisions") or []) if isinstance(x, str))
        open_questions.extend(str(x) for x in (metadata.get("open_questions") or []) if isinstance(x, str))
        next_actions.extend(str(x) for x in (metadata.get("next_actions") or []) if isinstance(x, str))
        files_touched.extend(str(x) for x in (metadata.get("files_touched") or []) if isinstance(x, str))

    lines = [
        "# Coding Session Rollup",
        f"- Project: {project}",
        f"- Session: {session_id}",
        f"- Generated: {_utc_now_iso()}",
        f"- Checkpoints summarized: {len(records)}",
        "",
        "## Summary",
        summary.strip() if summary.strip() else "Session rollup generated from checkpoint log.",
        "",
    ]

    if checkpoints:
        lines.extend(["## Included Checkpoints", *[f"- {item}" for item in _dedupe(checkpoints)], ""])
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in _dedupe(files_touched)], ""])
    if decisions:
        lines.extend(["## Decisions", *[f"- {item}" for item in _dedupe(decisions)], ""])
    if open_questions:
        lines.extend(["## Open Questions", *[f"- {item}" for item in _dedupe(open_questions)], ""])
    if next_actions:
        lines.extend(["## Next Actions", *[f"- {item}" for item in _dedupe(next_actions)], ""])

    return "\n".join(lines).strip()


def build_rollup_payload(args: argparse.Namespace, records: list[dict[str, Any]]) -> dict[str, Any]:
    if not args.project or not args.session_id:
        raise ValueError("--project and --session-id are required for rollups.")

    content = build_rollup_content(
        project=args.project,
        session_id=args.session_id,
        records=records,
        summary=args.summary or "",
    )

    project_slug = _slug(args.project)
    session_slug = _slug(args.session_id)
    timestamp = _utc_now_iso()
    source_id = (
        f"rollup:{project_slug}:{session_slug}:{timestamp.replace('-', '').replace(':', '').replace('+00:00', 'z')}"
    )[:200]

    metadata = {
        "project": args.project,
        "session_id": args.session_id,
        "checkpoint_kind": args.kind,
        "timestamp": timestamp,
        "tags": [
            "memory:checkpoint",
            "memory:rollup",
            f"project:{project_slug}",
            f"session:{session_slug}",
            f"checkpoint:{args.kind}",
        ],
    }
    return {
        "title": args.title or f"{args.project} | {args.session_id} | {args.kind} rollup",
        "content": content,
        "metadata": metadata,
        "source": args.source,
        "source_id": source_id,
        "source_path": args.source_path or os.getcwd(),
        "mime_type": "text/markdown",
        "return_id": bool(args.return_id),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        allow_abbrev=False,
    )
    parser.add_argument("--log-file", default=".remem/session-checkpoints.ndjson", help="Checkpoint log file.")
    parser.add_argument("--project", required=True, help="Project identifier.")
    parser.add_argument("--session-id", required=True, help="Session identifier.")
    parser.add_argument("--client", choices=("codex", "claude"), default="codex")
    parser.add_argument("--to", help=argparse.SUPPRESS)
    parser.add_argument("--summary", help="Optional rollup summary paragraph.")
    parser.add_argument("--kind", choices=("final", "milestone", "manual"), default="final")
    parser.add_argument("--title", help="Optional title override.")
    parser.add_argument("--source", choices=("api", "quick_capture", "folder_sync", "gmail"), default="quick_capture")
    parser.add_argument("--source-path", help="Optional source path override.")
    parser.add_argument("--return-id", action="store_true", help="Request immediate document_id in ingest response.")
    parser.add_argument("--output", help="Optional file path to write rendered rollup markdown.")
    parser.add_argument("--ingest", action="store_true", help="Send rollup to Remem API.")
    parser.add_argument(
        "--api-url",
        default=os.getenv("REMEM_API_URL", _DEFAULT_API_URL),
        help="Remem API base URL.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print payload only.")
    parser.add_argument("--no-log", action="store_true", help="Skip appending rollup event to checkpoint log.")
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
    records = filter_records(
        load_checkpoint_log(args.log_file),
        project=args.project,
        session_id=args.session_id,
    )
    payload = build_rollup_payload(args, records)

    if args.output:
        Path(args.output).write_text(payload["content"], encoding="utf-8")

    response: dict[str, Any] | None = None
    if args.ingest and not args.dry_run:
        if "REMEM_MEMORY_ROUTE_FD" in os.environ:
            try:
                route = _consume_route_descriptor(
                    os.environ,
                    expected_client=args.client,
                    expected_behavior="sessions",
                )
                allow_local_dev = _consume_local_dev_capability(
                    os.environ,
                    route,
                )
                api_url = remem_api.normalize_api_origin(
                    args.api_url,
                    allow_local_dev=allow_local_dev,
                )
                api_key = remem_api.consume_explicit_api_key(os.environ)
            except Exception:
                print("error: invalid route descriptor", file=sys.stderr)
                return 1
        elif "REMEM_MEMORY_LOCAL_DEV_FD" in os.environ:
            try:
                _consume_local_dev_capability(os.environ, {})
            except Exception:
                pass
            print("error: invalid route descriptor", file=sys.stderr)
            return 1
        else:
            try:
                api_url, api_key = remem_api.resolve_api_access(
                    args.api_url
                )
            except Exception:
                print("error: invalid Remem API URL", file=sys.stderr)
                return 2
            route = {"write_namespace": None}
        if not api_key:
            print(
                "error: Remem credential is not configured",
                file=sys.stderr,
            )
            return 1
        try:
            response = ingest_checkpoint(
                api_url=api_url,
                api_key=api_key,
                payload=payload,
                namespace=route["write_namespace"],
            )
        except remem_api.RememAPIError as error:
            print(
                f"error: ingest failed [{error.kind}]",
                file=sys.stderr,
            )
            return 1

    if not args.no_log:
        append_checkpoint_log(
            args.log_file,
            {
                "timestamp": _utc_now_iso(),
                "payload": payload,
                "event": "rollup",
            },
        )

    print(json.dumps({"payload": payload, "response": response, "records_used": len(records)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
