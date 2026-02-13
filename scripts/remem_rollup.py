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

try:
    from scripts.remem_checkpoint import _slug, append_checkpoint_log, ingest_checkpoint
except ModuleNotFoundError:
    import importlib.util

    _CHECKPOINT_PATH = Path(__file__).with_name("remem_checkpoint.py")
    _SPEC = importlib.util.spec_from_file_location("remem_checkpoint", _CHECKPOINT_PATH)
    _MODULE = importlib.util.module_from_spec(_SPEC)
    assert _SPEC and _SPEC.loader
    _SPEC.loader.exec_module(_MODULE)
    _slug = _MODULE._slug
    append_checkpoint_log = _MODULE.append_checkpoint_log
    ingest_checkpoint = _MODULE.ingest_checkpoint


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", default=".remem/session-checkpoints.ndjson", help="Checkpoint log file.")
    parser.add_argument("--project", required=True, help="Project identifier.")
    parser.add_argument("--session-id", required=True, help="Session identifier.")
    parser.add_argument("--summary", help="Optional rollup summary paragraph.")
    parser.add_argument("--kind", choices=("final", "milestone", "manual"), default="final")
    parser.add_argument("--title", help="Optional title override.")
    parser.add_argument("--source", choices=("api", "quick_capture", "folder_sync", "gmail"), default="quick_capture")
    parser.add_argument("--source-path", help="Optional source path override.")
    parser.add_argument("--return-id", action="store_true", help="Request immediate document_id in ingest response.")
    parser.add_argument("--output", help="Optional file path to write rendered rollup markdown.")
    parser.add_argument("--ingest", action="store_true", help="Send rollup to Remem API.")
    parser.add_argument("--api-url", default=os.getenv("REMEM_API_URL", ""), help="Remem API base URL.")
    parser.add_argument("--api-key", default=os.getenv("REMEM_API_KEY", ""), help="Remem API key.")
    parser.add_argument("--dry-run", action="store_true", help="Print payload only.")
    parser.add_argument("--no-log", action="store_true", help="Skip appending rollup event to checkpoint log.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
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
        if not args.api_url or not args.api_key:
            print("error: --ingest requires REMEM_API_URL and REMEM_API_KEY (or --api-url/--api-key)", file=sys.stderr)
            return 2
        response = ingest_checkpoint(api_url=args.api_url, api_key=args.api_key, payload=payload)

    if not args.no_log:
        append_checkpoint_log(
            args.log_file,
            {"timestamp": _utc_now_iso(), "payload": payload, "response": response, "event": "rollup"},
        )

    print(json.dumps({"payload": payload, "response": response, "records_used": len(records)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
