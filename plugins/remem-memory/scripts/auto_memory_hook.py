#!/usr/bin/env python3
"""Claude hook automation for Remem session checkpoints and rollups."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore

_DEFAULT_INTERVAL_SECONDS = 20 * 60
_DEFAULT_MIN_EVENTS = 4
_DEFAULT_STATE_PATH = ".remem/auto-memory-state.json"
_DEFAULT_LOG_PATH = ".remem/session-checkpoints.ndjson"
_DEFAULT_API_URL = "https://api.remem.io"


@dataclass(frozen=True)
class Config:
    cwd: Path
    project: str
    session_id: str
    api_url: str
    api_key: str
    interval_seconds: int
    min_events: int
    state_path: Path
    log_path: Path
    enabled: bool
    rollup_on_session_end: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _slug(value: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in "._-") else "-" for ch in value.strip().lower())
    collapsed = "-".join(part for part in cleaned.split("-") if part)
    return collapsed[:120] or "unknown"


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return max(1, int(value))
    except ValueError:
        return default


def _resolve_path(cwd: Path, raw: str | None, default_rel: str) -> Path:
    if not raw:
        return cwd / default_rel
    path = Path(raw)
    if path.is_absolute():
        return path
    return cwd / path


def _read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _derive_session_id(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("session_id"), str) and payload["session_id"].strip():
        return payload["session_id"].strip()
    return f"session-{_utc_now().strftime('%Y%m%dT%H%M%S')}"


def _git_branch(cwd: Path) -> str | None:
    try:
        out = subprocess.check_output(["git", "-C", str(cwd), "branch", "--show-current"], stderr=subprocess.DEVNULL)
    except Exception:
        return None
    branch = out.decode("utf-8").strip()
    return branch or None


def _load_config(payload: dict[str, Any]) -> Config:
    cwd_raw = payload.get("cwd")
    cwd = Path(str(cwd_raw)).resolve() if isinstance(cwd_raw, str) and cwd_raw else Path.cwd().resolve()
    project = os.getenv("REMEM_MEMORY_PROJECT") or cwd.name or "unknown"
    session_id = os.getenv("REMEM_MEMORY_SESSION_ID") or _derive_session_id(payload)
    api_url = os.getenv("REMEM_API_URL", _DEFAULT_API_URL).strip() or _DEFAULT_API_URL
    api_key = os.getenv("REMEM_API_KEY", "").strip()
    state_path = _resolve_path(cwd, os.getenv("REMEM_MEMORY_STATE_FILE"), _DEFAULT_STATE_PATH)
    log_path = _resolve_path(cwd, os.getenv("REMEM_MEMORY_LOG_FILE"), _DEFAULT_LOG_PATH)
    return Config(
        cwd=cwd,
        project=project,
        session_id=session_id,
        api_url=api_url,
        api_key=api_key,
        interval_seconds=_int_env("REMEM_MEMORY_INTERVAL_SECONDS", _DEFAULT_INTERVAL_SECONDS),
        min_events=_int_env("REMEM_MEMORY_MIN_EVENTS", _DEFAULT_MIN_EVENTS),
        state_path=state_path,
        log_path=log_path,
        enabled=_bool_env("REMEM_MEMORY_AUTO_ENABLED", True),
        rollup_on_session_end=_bool_env("REMEM_MEMORY_ROLLUP_ON_SESSION_END", True),
    )


def _default_state(session_id: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "project": "",
        "last_checkpoint_epoch": 0.0,
        "events_since_checkpoint": 0,
        "recent_events": [],
        "checkpoints_created": 0,
        "last_rollup_epoch": 0.0,
    }


def _load_state(path: Path, session_id: str) -> dict[str, Any]:
    if not path.exists():
        return _default_state(session_id)
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_state(session_id)
    if not isinstance(parsed, dict):
        return _default_state(session_id)
    state = _default_state(session_id)
    state.update(parsed)
    if state.get("session_id") != session_id:
        state = _default_state(session_id)
    if not isinstance(state.get("recent_events"), list):
        state["recent_events"] = []
    return state


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _append_ndjson(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")


@contextmanager
def _state_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_fh:
        if fcntl is not None:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _extract_tool_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    tool_name = tool_name.strip()
    tool_input = payload.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}

    files: list[str] = []
    summary = tool_name
    if tool_name in {"Write", "Edit", "MultiEdit"}:
        file_path = tool_input.get("file_path") or tool_input.get("path")
        if isinstance(file_path, str) and file_path.strip():
            files = [file_path.strip()]
            summary = f"{tool_name} {file_path.strip()}"
    elif tool_name == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str):
            command = " ".join(command.strip().split())
            if len(command) > 180:
                command = command[:177] + "..."
            summary = f"Bash {command}" if command else "Bash"

    return {
        "timestamp": _utc_now_iso(),
        "tool": tool_name,
        "summary": summary,
        "files": files,
    }


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        key = item.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _build_checkpoint_payload(
    *,
    config: Config,
    kind: str,
    hook_event: str,
    recent_events: list[dict[str, Any]],
    events_since_checkpoint: int,
) -> dict[str, Any]:
    timestamp = _utc_now_iso()
    project_slug = _slug(config.project)
    session_slug = _slug(config.session_id)
    files_touched = _dedupe(
        [
            str(file_path)
            for event in recent_events
            for file_path in (event.get("files") or [])
            if isinstance(file_path, str)
        ]
    )
    recent_activity = _dedupe([str(event.get("summary", "")).strip() for event in recent_events])[:8]
    summary = (
        f"Automatic {kind} checkpoint after {events_since_checkpoint} tool events."
        f" Recent files: {', '.join(files_touched[:5]) if files_touched else 'none'}."
    )

    lines = [
        "# Coding Session Checkpoint (Auto)",
        f"- Project: {config.project}",
        f"- Session: {config.session_id}",
        f"- Kind: {kind}",
        f"- Timestamp: {timestamp}",
        f"- Branch: {_git_branch(config.cwd) or 'unknown'}",
        f"- Repo: {config.cwd}",
        f"- Trigger: {hook_event}",
        "",
        "## Summary",
        summary,
        "",
    ]
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in files_touched], ""])
    if recent_activity:
        lines.extend(["## Recent Activity", *[f"- {item}" for item in recent_activity], ""])

    source_id = f"auto-checkpoint:{project_slug}:{session_slug}:{kind}:{timestamp}".replace(":", "").replace("-", "")
    source_id = source_id[:200]

    return {
        "title": f"{config.project} | {config.session_id} | {kind} checkpoint (auto)",
        "content": "\n".join(lines).strip(),
        "metadata": {
            "project": config.project,
            "session_id": config.session_id,
            "checkpoint_kind": kind,
            "timestamp": timestamp,
            "repo_root": str(config.cwd),
            "files_touched": files_touched,
            "decisions": [],
            "open_questions": [],
            "next_actions": [],
            "tags": [
                "memory:checkpoint",
                "memory:auto",
                f"project:{project_slug}",
                f"session:{session_slug}",
                f"checkpoint:{kind}",
            ],
            "automation": "claude-hook",
            "hook_event": hook_event,
        },
        "source": "quick_capture",
        "source_id": source_id,
        "source_path": str(config.cwd),
        "mime_type": "text/markdown",
        "return_id": False,
    }


def _load_checkpoint_rows(log_path: Path, *, project: str, session_id: str) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        payload = row.get("payload")
        if not isinstance(payload, dict):
            continue
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if metadata.get("project") != project:
            continue
        if metadata.get("session_id") != session_id:
            continue
        rows.append(row)
    return rows


def _build_rollup_payload(config: Config, records: list[dict[str, Any]]) -> dict[str, Any]:
    timestamp = _utc_now_iso()
    project_slug = _slug(config.project)
    session_slug = _slug(config.session_id)
    files_touched: list[str] = []
    checkpoints: list[str] = []
    for row in records:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        title = payload.get("title")
        if isinstance(title, str) and title.strip():
            checkpoints.append(title.strip())
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        for value in metadata.get("files_touched") or []:
            if isinstance(value, str):
                files_touched.append(value)

    files_touched = _dedupe(files_touched)
    checkpoints = _dedupe(checkpoints)
    lines = [
        "# Coding Session Rollup (Auto)",
        f"- Project: {config.project}",
        f"- Session: {config.session_id}",
        f"- Generated: {timestamp}",
        f"- Checkpoints summarized: {len(records)}",
        "",
        "## Summary",
        "Automatic final rollup generated from checkpoint activity captured during this session.",
        "",
    ]
    if checkpoints:
        lines.extend(["## Included Checkpoints", *[f"- {item}" for item in checkpoints], ""])
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in files_touched], ""])

    source_id = f"auto-rollup:{project_slug}:{session_slug}:{timestamp}".replace(":", "").replace("-", "")
    source_id = source_id[:200]

    return {
        "title": f"{config.project} | {config.session_id} | final rollup (auto)",
        "content": "\n".join(lines).strip(),
        "metadata": {
            "project": config.project,
            "session_id": config.session_id,
            "checkpoint_kind": "final",
            "timestamp": timestamp,
            "tags": [
                "memory:checkpoint",
                "memory:rollup",
                "memory:auto",
                f"project:{project_slug}",
                f"session:{session_slug}",
                "checkpoint:final",
            ],
            "automation": "claude-hook",
            "hook_event": "SessionEnd",
        },
        "source": "quick_capture",
        "source_id": source_id,
        "source_path": str(config.cwd),
        "mime_type": "text/markdown",
        "return_id": False,
    }


def _ingest(config: Config, payload: dict[str, Any]) -> dict[str, Any] | None:
    if not config.api_key:
        return None
    url = f"{config.api_url.rstrip('/')}/v1/documents/ingest"
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urllib_request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib_request.urlopen(req, timeout=20) as resp:  # nosec B310
            data = resp.read().decode("utf-8")
            return json.loads(data) if data else {"ok": True}
    except urllib_error.HTTPError as exc:
        sys.stderr.write(f"[remem-memory] ingest HTTP {exc.code}\n")
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"[remem-memory] ingest failed: {exc}\n")
    return None


def _persist_checkpoint(
    *,
    config: Config,
    kind: str,
    hook_event: str,
    state: dict[str, Any],
) -> None:
    recent_events = state.get("recent_events")
    recent_events = recent_events if isinstance(recent_events, list) else []
    events_since = int(state.get("events_since_checkpoint") or 0)
    payload = _build_checkpoint_payload(
        config=config,
        kind=kind,
        hook_event=hook_event,
        recent_events=[event for event in recent_events if isinstance(event, dict)],
        events_since_checkpoint=events_since,
    )
    response = _ingest(config, payload)
    _append_ndjson(
        config.log_path,
        {"timestamp": _utc_now_iso(), "event": "auto_checkpoint", "payload": payload, "response": response},
    )


def _persist_rollup(config: Config) -> None:
    records = _load_checkpoint_rows(config.log_path, project=config.project, session_id=config.session_id)
    if not records:
        return
    payload = _build_rollup_payload(config, records)
    response = _ingest(config, payload)
    _append_ndjson(
        config.log_path,
        {"timestamp": _utc_now_iso(), "event": "auto_rollup", "payload": payload, "response": response},
    )


def _should_interval_checkpoint(state: dict[str, Any], config: Config) -> bool:
    events_since = int(state.get("events_since_checkpoint") or 0)
    if events_since < config.min_events:
        return False
    last_epoch = float(state.get("last_checkpoint_epoch") or 0.0)
    if last_epoch <= 0:
        return True
    elapsed = _utc_now().timestamp() - last_epoch
    return elapsed >= config.interval_seconds or events_since >= config.min_events * 2


def _handle_post_tool_use(config: Config, payload: dict[str, Any]) -> int:
    event = _extract_tool_event(payload)
    if event is None:
        return 0
    lock_path = config.state_path.with_suffix(config.state_path.suffix + ".lock")
    with _state_lock(lock_path):
        state = _load_state(config.state_path, config.session_id)
        state["project"] = config.project
        recent = state.get("recent_events")
        recent = recent if isinstance(recent, list) else []
        recent.append(event)
        state["recent_events"] = recent[-30:]
        state["events_since_checkpoint"] = int(state.get("events_since_checkpoint") or 0) + 1

        if _should_interval_checkpoint(state, config):
            _persist_checkpoint(
                config=config,
                kind="interval",
                hook_event=str(payload.get("hook_event_name") or "PostToolUse"),
                state=state,
            )
            state["last_checkpoint_epoch"] = _utc_now().timestamp()
            state["events_since_checkpoint"] = 0
            state["recent_events"] = []
            state["checkpoints_created"] = int(state.get("checkpoints_created") or 0) + 1
        _save_state(config.state_path, state)
    return 0


def _handle_task_completed(config: Config, payload: dict[str, Any]) -> int:
    lock_path = config.state_path.with_suffix(config.state_path.suffix + ".lock")
    with _state_lock(lock_path):
        state = _load_state(config.state_path, config.session_id)
        events_since = int(state.get("events_since_checkpoint") or 0)
        if events_since <= 0:
            _save_state(config.state_path, state)
            return 0
        _persist_checkpoint(
            config=config,
            kind="milestone",
            hook_event=str(payload.get("hook_event_name") or "TaskCompleted"),
            state=state,
        )
        state["last_checkpoint_epoch"] = _utc_now().timestamp()
        state["events_since_checkpoint"] = 0
        state["recent_events"] = []
        state["checkpoints_created"] = int(state.get("checkpoints_created") or 0) + 1
        _save_state(config.state_path, state)
    return 0


def _handle_session_end(config: Config, payload: dict[str, Any]) -> int:
    lock_path = config.state_path.with_suffix(config.state_path.suffix + ".lock")
    with _state_lock(lock_path):
        state = _load_state(config.state_path, config.session_id)
        events_since = int(state.get("events_since_checkpoint") or 0)
        if events_since > 0:
            _persist_checkpoint(
                config=config,
                kind="milestone",
                hook_event=str(payload.get("hook_event_name") or "SessionEnd"),
                state=state,
            )
            state["checkpoints_created"] = int(state.get("checkpoints_created") or 0) + 1
        if config.rollup_on_session_end:
            _persist_rollup(config)
            state["last_rollup_epoch"] = _utc_now().timestamp()
        state["last_checkpoint_epoch"] = _utc_now().timestamp()
        state["events_since_checkpoint"] = 0
        state["recent_events"] = []
        _save_state(config.state_path, state)
    return 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        required=True,
        choices=("post_tool_use", "task_completed", "session_end"),
        help="Hook mode to execute.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    payload = _read_stdin_json()
    config = _load_config(payload)
    if not config.enabled:
        return 0
    if args.mode == "post_tool_use":
        return _handle_post_tool_use(config, payload)
    if args.mode == "task_completed":
        return _handle_task_completed(config, payload)
    return _handle_session_end(config, payload)


if __name__ == "__main__":
    raise SystemExit(main())
