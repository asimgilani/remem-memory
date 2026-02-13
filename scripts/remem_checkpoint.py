#!/usr/bin/env python3
"""Create and optionally ingest a structured Remem coding-session checkpoint."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

_SOURCE_CHOICES = ("api", "quick_capture", "folder_sync", "gmail")
_KIND_CHOICES = ("interval", "milestone", "final", "manual")


def _slug(value: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "-" for ch in value.strip().lower())
    collapsed = "-".join(part for part in cleaned.split("-") if part)
    return collapsed[:120] or "unknown"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_branch(repo_root: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", repo_root, "branch", "--show-current"],
            stderr=subprocess.DEVNULL,
        )
        branch = out.decode("utf-8").strip()
        return branch or None
    except Exception:
        return None


def _read_summary(args: argparse.Namespace) -> str:
    if args.summary_file:
        return Path(args.summary_file).read_text(encoding="utf-8").strip()
    if args.summary:
        return args.summary.strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def build_checkpoint_content(
    *,
    project: str,
    session_id: str,
    kind: str,
    timestamp: str,
    summary: str,
    branch: str | None,
    repo_root: str,
    files_touched: list[str],
    decisions: list[str],
    open_questions: list[str],
    next_actions: list[str],
) -> str:
    lines = [
        "# Coding Session Checkpoint",
        f"- Project: {project}",
        f"- Session: {session_id}",
        f"- Kind: {kind}",
        f"- Timestamp: {timestamp}",
        f"- Branch: {branch or 'unknown'}",
        f"- Repo: {repo_root}",
        "",
    ]

    if summary:
        lines.extend(["## Summary", summary, ""])
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in files_touched], ""])
    if decisions:
        lines.extend(["## Decisions", *[f"- {item}" for item in decisions], ""])
    if open_questions:
        lines.extend(["## Open Questions", *[f"- {item}" for item in open_questions], ""])
    if next_actions:
        lines.extend(["## Next Actions", *[f"- {item}" for item in next_actions], ""])

    return "\n".join(lines).strip()


def build_checkpoint_payload(args: argparse.Namespace) -> dict[str, Any]:
    timestamp = _utc_now_iso()
    repo_root = os.path.abspath(args.repo_root or os.getcwd())
    branch = args.branch or _git_branch(repo_root)
    summary = _read_summary(args)

    project_slug = _slug(args.project)
    session_slug = _slug(args.session_id)
    checkpoint_kind = args.kind

    content = build_checkpoint_content(
        project=args.project,
        session_id=args.session_id,
        kind=checkpoint_kind,
        timestamp=timestamp,
        summary=summary,
        branch=branch,
        repo_root=repo_root,
        files_touched=args.file_touched,
        decisions=args.decision,
        open_questions=args.open_question,
        next_actions=args.next_action,
    )

    title = (
        args.title
        or f"{args.project} | {args.session_id} | {checkpoint_kind} checkpoint"
    )
    source_id = (
        f"checkpoint:{project_slug}:{session_slug}:{checkpoint_kind}:"
        f"{timestamp.replace('-', '').replace(':', '').replace('+00:00', 'z')}"
    )[:200]

    metadata: dict[str, Any] = {
        "project": args.project,
        "session_id": args.session_id,
        "checkpoint_kind": checkpoint_kind,
        "timestamp": timestamp,
        "branch": branch,
        "repo_root": repo_root,
        "files_touched": args.file_touched,
        "decisions": args.decision,
        "open_questions": args.open_question,
        "next_actions": args.next_action,
        "tags": [
            "memory:checkpoint",
            f"project:{project_slug}",
            f"session:{session_slug}",
            f"checkpoint:{checkpoint_kind}",
        ],
    }

    payload: dict[str, Any] = {
        "title": title,
        "content": content,
        "metadata": metadata,
        "source": args.source,
        "source_id": source_id,
        "source_path": args.source_path or repo_root,
        "mime_type": "text/markdown",
        "return_id": bool(args.return_id),
    }
    return payload


def ingest_checkpoint(
    *,
    api_url: str,
    api_key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(f"{api_url.rstrip('/')}/v1/documents/ingest", headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()


def append_checkpoint_log(log_file: str, record: dict[str, Any]) -> None:
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="Project identifier (for metadata and tags).")
    parser.add_argument("--session-id", required=True, help="Session identifier used to group checkpoints.")
    parser.add_argument("--kind", choices=_KIND_CHOICES, default="interval", help="Checkpoint type.")
    parser.add_argument("--title", help="Optional document title override.")
    parser.add_argument("--summary", help="Checkpoint summary text.")
    parser.add_argument("--summary-file", help="Read summary text from file.")
    parser.add_argument("--decision", action="append", default=[], help="Decision made during the session (repeatable).")
    parser.add_argument("--open-question", action="append", default=[], help="Open question to track (repeatable).")
    parser.add_argument("--next-action", action="append", default=[], help="Next action item (repeatable).")
    parser.add_argument("--file-touched", action="append", default=[], help="File touched in this segment (repeatable).")
    parser.add_argument("--repo-root", default=os.getcwd(), help="Repository root path (default: cwd).")
    parser.add_argument("--branch", help="Git branch override.")
    parser.add_argument("--source", choices=_SOURCE_CHOICES, default="quick_capture", help="Remem ingest source.")
    parser.add_argument("--source-path", help="Optional source path/URI override.")
    parser.add_argument("--return-id", action="store_true", help="Request immediate document_id in ingest response.")
    parser.add_argument("--ingest", action="store_true", help="Send payload to Remem API after building.")
    parser.add_argument("--api-url", default=os.getenv("REMEM_API_URL", ""), help="Remem API base URL.")
    parser.add_argument("--api-key", default=os.getenv("REMEM_API_KEY", ""), help="Remem API key.")
    parser.add_argument("--log-file", default=".remem/session-checkpoints.ndjson", help="Local NDJSON log file.")
    parser.add_argument("--no-log", action="store_true", help="Skip writing local log entry.")
    parser.add_argument("--dry-run", action="store_true", help="Print payload and exit without ingest.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    payload = build_checkpoint_payload(args)

    record: dict[str, Any] = {"timestamp": _utc_now_iso(), "payload": payload}
    response: dict[str, Any] | None = None

    if args.ingest and not args.dry_run:
        if not args.api_url or not args.api_key:
            print("error: --ingest requires REMEM_API_URL and REMEM_API_KEY (or --api-url/--api-key)", file=sys.stderr)
            return 2
        response = ingest_checkpoint(api_url=args.api_url, api_key=args.api_key, payload=payload)
        record["response"] = response

    if not args.no_log:
        append_checkpoint_log(args.log_file, record)

    output = {"payload": payload, "response": response}
    print(json.dumps(output, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
