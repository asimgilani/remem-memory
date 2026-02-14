#!/usr/bin/env python3
"""Run Codex with automatic interval checkpoints and final rollups."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_INTERVAL_SECONDS = 20 * 60
_DEFAULT_MAX_FILES = 12
_DEFAULT_API_URL = "https://api.remem.io"
_DEFAULT_LOG_FILE = ".remem/session-checkpoints.ndjson"
_DEFAULT_STATE_FILE = ".remem/codex-wrapper-state.json"


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


def _resolve_helper_script(script_name: str) -> Path:
    return Path(__file__).resolve().with_name(script_name)


def _read_git_status_lines(cwd: Path) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(cwd), "status", "--porcelain", "--untracked-files=all"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return []
    return out.splitlines()


def parse_porcelain_paths(lines: list[str]) -> list[str]:
    """Parse paths from `git status --porcelain` output."""
    paths: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if len(line) < 4:
            continue
        raw = line[3:].strip()
        if not raw:
            continue
        if " -> " in raw:
            raw = raw.split(" -> ", 1)[1].strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            raw = raw[1:-1]
        if raw and raw not in seen:
            seen.add(raw)
            paths.append(raw)
    return paths


def _is_git_repo(cwd: Path) -> bool:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(cwd), "rev-parse", "--is-inside-work-tree"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return False
    return out == "true"


def _current_changed_files(cwd: Path) -> list[str]:
    return parse_porcelain_paths(_read_git_status_lines(cwd))


def _default_project(cwd: Path) -> str:
    return os.getenv("REMEM_MEMORY_PROJECT") or cwd.name or "unknown"


def _default_session_id() -> str:
    env_value = os.getenv("REMEM_MEMORY_SESSION_ID", "").strip()
    if env_value:
        return env_value
    return str(uuid.uuid4())


def build_checkpoint_summary(kind: str, reason: str, changed_files: list[str], max_files: int) -> str:
    if changed_files:
        shown = ", ".join(changed_files[:max_files])
        suffix = "" if len(changed_files) <= max_files else f" (+{len(changed_files) - max_files} more)"
        return (
            f"Automatic {kind} checkpoint from Codex wrapper ({reason}). "
            f"Detected {len(changed_files)} changed files: {shown}{suffix}."
        )
    return f"Automatic {kind} checkpoint from Codex wrapper ({reason}). No git-tracked changes detected."


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _run_helper(script_name: str, script_args: list[str], cwd: Path, env: dict[str, str]) -> int:
    script_path = _resolve_helper_script(script_name)
    if not script_path.exists():
        print(f"warning: helper script missing: {script_path}", file=sys.stderr)
        return 2
    result = subprocess.run(
        [sys.executable, str(script_path), *script_args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or "(no output)"
        print(f"warning: {script_name} failed: {detail}", file=sys.stderr)
    return int(result.returncode)


def _run_checkpoint(
    *,
    cwd: Path,
    env: dict[str, str],
    project: str,
    session_id: str,
    kind: str,
    summary: str,
    changed_files: list[str],
    max_files: int,
    log_file: str,
    ingest: bool,
    dry_run: bool,
) -> bool:
    args: list[str] = [
        "--project",
        project,
        "--session-id",
        session_id,
        "--kind",
        kind,
        "--summary",
        summary,
        "--repo-root",
        str(cwd),
        "--log-file",
        log_file,
    ]
    for rel_path in changed_files[:max_files]:
        args.extend(["--file-touched", str((cwd / rel_path).resolve())])
    if ingest:
        args.append("--ingest")
    if dry_run:
        args.append("--dry-run")
    return _run_helper("remem_checkpoint.py", args, cwd, env) == 0


def _run_rollup(
    *,
    cwd: Path,
    env: dict[str, str],
    project: str,
    session_id: str,
    summary: str,
    log_file: str,
    ingest: bool,
    dry_run: bool,
) -> bool:
    args: list[str] = [
        "--project",
        project,
        "--session-id",
        session_id,
        "--summary",
        summary,
        "--log-file",
        log_file,
    ]
    if ingest:
        args.append("--ingest")
    if dry_run:
        args.append("--dry-run")
    return _run_helper("remem_rollup.py", args, cwd, env) == 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="", help="Project key for checkpoint metadata.")
    parser.add_argument("--session-id", default="", help="Session ID for grouping checkpoints.")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=_int_env("REMEM_MEMORY_INTERVAL_SECONDS", _DEFAULT_INTERVAL_SECONDS),
        help="Interval for periodic checkpoints.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=_int_env("REMEM_MEMORY_MAX_FILES", _DEFAULT_MAX_FILES),
        help="Max files listed per checkpoint.",
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("REMEM_MEMORY_LOG_FILE", _DEFAULT_LOG_FILE),
        help="Checkpoint NDJSON log file path.",
    )
    parser.add_argument(
        "--state-file",
        default=os.getenv("REMEM_MEMORY_CODEX_STATE_FILE", _DEFAULT_STATE_FILE),
        help="Local wrapper state file path.",
    )
    parser.add_argument("--codex-bin", default=os.getenv("REMEM_CODEX_BIN", "codex"), help="Codex executable path.")
    parser.add_argument("--api-url", default=os.getenv("REMEM_API_URL", _DEFAULT_API_URL), help="Remem API URL.")
    parser.add_argument("--no-ingest", action="store_true", help="Disable API ingest, write local logs only.")
    parser.add_argument("--no-rollup", action="store_true", help="Disable final rollup on exit.")
    parser.add_argument("--dry-run", action="store_true", help="Build payloads only, skip API writes.")
    parser.add_argument(
        "--checkpoint-on-start",
        action="store_true",
        help="Emit one interval checkpoint immediately after launch.",
    )
    parser.add_argument(
        "--always-checkpoint",
        action="store_true",
        help="Emit checkpoints even when git status has not changed.",
    )
    parser.add_argument("codex_args", nargs=argparse.REMAINDER, help="Arguments forwarded to Codex.")
    ns = parser.parse_args(argv)
    ns.interval_seconds = max(1, int(ns.interval_seconds))
    ns.max_files = max(1, int(ns.max_files))
    forwarded = list(ns.codex_args)
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    ns.codex_args = forwarded
    return ns


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    cwd = Path.cwd().resolve()
    project = args.project.strip() or _default_project(cwd)
    session_id = args.session_id.strip() or _default_session_id()
    state_path = Path(args.state_file)
    if not state_path.is_absolute():
        state_path = cwd / state_path

    codex_bin = args.codex_bin.strip() or "codex"
    if not shutil.which(codex_bin):
        print(f"error: codex binary not found: {codex_bin}", file=sys.stderr)
        return 2

    api_key_present = bool(os.getenv("REMEM_API_KEY", "").strip())
    api_url_present = bool(args.api_url.strip())
    ingest = (not args.no_ingest) and api_key_present and api_url_present and (not args.dry_run)

    env = os.environ.copy()
    env["REMEM_API_URL"] = args.api_url
    env.setdefault("REMEM_MEMORY_PROJECT", project)
    env.setdefault("REMEM_MEMORY_SESSION_ID", session_id)

    in_git_repo = _is_git_repo(cwd)
    checkpoints_created = 0
    last_snapshot: list[str] = []
    lock = threading.Lock()
    started_at = _utc_now_iso()

    _write_state(
        state_path,
        {
            "project": project,
            "session_id": session_id,
            "started_at": started_at,
            "cwd": str(cwd),
            "interval_seconds": args.interval_seconds,
            "ingest_enabled": ingest,
            "in_git_repo": in_git_repo,
            "active": True,
        },
    )

    def maybe_checkpoint(*, kind: str, reason: str, force: bool) -> bool:
        nonlocal checkpoints_created, last_snapshot
        changed = _current_changed_files(cwd) if in_git_repo else []

        if not force and not args.always_checkpoint and in_git_repo:
            if not changed:
                return False
            if changed == last_snapshot:
                return False

        summary = build_checkpoint_summary(kind=kind, reason=reason, changed_files=changed, max_files=args.max_files)
        ok = _run_checkpoint(
            cwd=cwd,
            env=env,
            project=project,
            session_id=session_id,
            kind=kind,
            summary=summary,
            changed_files=changed,
            max_files=args.max_files,
            log_file=args.log_file,
            ingest=ingest,
            dry_run=args.dry_run,
        )
        if ok:
            with lock:
                checkpoints_created += 1
                last_snapshot = changed
        return ok

    cmd = [codex_bin, *args.codex_args]
    print(
        f"[remem-dev-sessions] launching codex with project={project} session_id={session_id}",
        file=sys.stderr,
    )
    child = subprocess.Popen(cmd, cwd=str(cwd), env=env)
    stop_event = threading.Event()

    def _forward(sig: int, _frame: Any) -> None:
        if child.poll() is None:
            child.send_signal(sig)

    signal.signal(signal.SIGINT, _forward)
    signal.signal(signal.SIGTERM, _forward)

    def _checkpoint_loop() -> None:
        while not stop_event.wait(args.interval_seconds):
            maybe_checkpoint(kind="interval", reason="interval", force=False)

    loop_thread = threading.Thread(target=_checkpoint_loop, daemon=True)
    if args.checkpoint_on_start:
        maybe_checkpoint(kind="interval", reason="start", force=False)
    loop_thread.start()

    exit_code = 1
    try:
        exit_code = int(child.wait())
    finally:
        stop_event.set()
        loop_thread.join(timeout=5.0)

    # Capture one last milestone checkpoint at shutdown if there are new changes.
    maybe_checkpoint(kind="milestone", reason="codex-exit", force=False)

    if not args.no_rollup and checkpoints_created > 0:
        rollup_summary = (
            f"Automatic final rollup from Codex wrapper. "
            f"Exit code: {exit_code}. Checkpoints created: {checkpoints_created}."
        )
        _run_rollup(
            cwd=cwd,
            env=env,
            project=project,
            session_id=session_id,
            summary=rollup_summary,
            log_file=args.log_file,
            ingest=ingest,
            dry_run=args.dry_run,
        )

    _write_state(
        state_path,
        {
            "project": project,
            "session_id": session_id,
            "started_at": started_at,
            "ended_at": _utc_now_iso(),
            "cwd": str(cwd),
            "interval_seconds": args.interval_seconds,
            "ingest_enabled": ingest,
            "in_git_repo": in_git_repo,
            "checkpoints_created": checkpoints_created,
            "codex_exit_code": exit_code,
            "active": False,
        },
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
