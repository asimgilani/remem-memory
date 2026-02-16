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
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_INTERVAL_SECONDS = 20 * 60
_DEFAULT_MAX_FILES = 12
_DEFAULT_API_URL = "https://api.remem.io"
_DEFAULT_LOG_FILE = ".remem/session-checkpoints.ndjson"
_DEFAULT_STATE_FILE = ".remem/codex-wrapper-state.json"
_DEFAULT_SUMMARY_MODEL_CODEX_CLI = "gpt-5.3-codex-spark"
_DEFAULT_SUMMARY_TIMEOUT_SECONDS = 15
_DEFAULT_SUMMARY_MAX_MESSAGES = 80
_DEFAULT_SUMMARY_MAX_CHARS = 12000
_DEFAULT_SUMMARY_SCAN_LIMIT = 240


@dataclass(frozen=True)
class StructuredSummary:
    summary: str
    decisions: list[str]
    open_questions: list[str]
    next_actions: list[str]
    model: str


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


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


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


def _codex_home() -> Path:
    return Path(os.getenv("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()


def _codex_auth_path() -> Path:
    return _codex_home() / "auth.json"


def _codex_sessions_dir() -> Path:
    override = os.getenv("REMEM_MEMORY_CODEX_SESSIONS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return _codex_home() / "sessions"


def _summary_model() -> str:
    override = os.getenv("REMEM_MEMORY_SUMMARY_MODEL", "").strip()
    if override:
        return override
    return _DEFAULT_SUMMARY_MODEL_CODEX_CLI


def _summary_enabled(codex_bin: str) -> bool:
    if not _bool_env("REMEM_MEMORY_SUMMARY_ENABLED", True):
        return False
    provider = os.getenv("REMEM_MEMORY_SUMMARY_PROVIDER", "").strip().lower()
    if provider and provider not in {"codex", "codex-cli", "codex_cli"}:
        return False
    if not shutil.which(codex_bin):
        return False
    return _codex_auth_path().exists()


def _session_meta_cwd(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                if idx > 60:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("type") != "session_meta":
                    continue
                payload = row.get("payload")
                payload = payload if isinstance(payload, dict) else {}
                cwd = payload.get("cwd")
                if isinstance(cwd, str) and cwd.strip():
                    return cwd.strip()
                return None
    except OSError:
        return None
    return None


def _discover_codex_transcript_path(cwd: Path, started_at_epoch: float, existing_path: str) -> str | None:
    if existing_path:
        existing = Path(existing_path)
        if existing.exists():
            return str(existing)

    sessions_dir = _codex_sessions_dir()
    if not sessions_dir.exists():
        return None

    max_scan = _int_env("REMEM_MEMORY_SUMMARY_SCAN_LIMIT", _DEFAULT_SUMMARY_SCAN_LIMIT)
    cutoff_epoch = started_at_epoch - 3600.0
    candidates: list[tuple[float, Path]] = []
    for path in sessions_dir.rglob("rollout-*.jsonl"):
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_mtime < cutoff_epoch:
            continue
        candidates.append((float(stat.st_mtime), path))
    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    cwd_resolved = cwd.resolve()
    for _, path in candidates[:max_scan]:
        meta_cwd = _session_meta_cwd(path)
        if not meta_cwd:
            continue
        try:
            resolved = Path(meta_cwd).resolve()
        except OSError:
            continue
        if resolved == cwd_resolved:
            return str(path)
    return None


def _extract_codex_message_text(content: Any, *, role: str) -> str:
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    allowed_types = {"input_text", "text"} if role == "user" else {"output_text", "text"}
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if isinstance(item_type, str) and item_type not in allowed_types:
            continue
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
    return "\n".join(parts).strip()


def _is_noise_user_text(text: str) -> bool:
    lowered = text.lower()
    if "# agents.md instructions for " in lowered:
        return True
    if "<environment_context>" in lowered:
        return True
    if "<permissions instructions>" in lowered:
        return True
    if "## superpowers system" in lowered and len(lowered) > 400:
        return True
    return False


def _read_codex_transcript_excerpt(
    transcript_path: str,
    *,
    max_messages: int | None = None,
    max_chars: int | None = None,
) -> str:
    if not transcript_path:
        return ""
    path = Path(transcript_path)
    if not path.exists():
        return ""

    message_limit = max_messages or _int_env("REMEM_MEMORY_SUMMARY_MAX_MESSAGES", _DEFAULT_SUMMARY_MAX_MESSAGES)
    char_limit = max_chars or _int_env("REMEM_MEMORY_SUMMARY_MAX_CHARS", _DEFAULT_SUMMARY_MAX_CHARS)
    message_limit = max(10, int(message_limit))
    char_limit = max(500, int(char_limit))

    turns: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("type") != "response_item":
                    continue
                payload = row.get("payload")
                payload = payload if isinstance(payload, dict) else {}
                payload_type = payload.get("type")

                if payload_type == "message":
                    role = payload.get("role")
                    if role not in {"user", "assistant"}:
                        continue
                    text = _extract_codex_message_text(payload.get("content"), role=role)
                    if not text:
                        continue
                    if role == "user" and _is_noise_user_text(text):
                        continue
                    prefix = "User" if role == "user" else "Assistant"
                    turns.append(f"{prefix}: {text}")
                elif payload_type == "function_call":
                    name = payload.get("name")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    snippet = name.strip()
                    arguments = payload.get("arguments")
                    if isinstance(arguments, str) and arguments.strip():
                        compact = " ".join(arguments.strip().split())
                        if len(compact) > 180:
                            compact = compact[:177] + "..."
                        snippet = f"{snippet} {compact}"
                    turns.append(f"[tool] {snippet}")

                if len(turns) > (message_limit * 3):
                    turns = turns[-(message_limit * 2) :]
    except OSError:
        return ""

    if not turns:
        return ""
    excerpt = "\n\n".join(turns[-message_limit:]).strip()
    if len(excerpt) > char_limit:
        excerpt = excerpt[-char_limit:]
        cut = excerpt.find("User: ")
        if cut > 0:
            excerpt = excerpt[cut:]
    return excerpt.strip()


def _extract_json_object(raw: str) -> dict[str, Any] | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end < 0 or end <= start:
            return None
        try:
            parsed = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            return None
    return parsed if isinstance(parsed, dict) else None


def _sanitize_items(items: Any, *, limit: int) -> list[str]:
    out: list[str] = []
    if not isinstance(items, list):
        return out
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        cleaned = " ".join(item.strip().split())
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _codex_summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["summary", "decisions", "open_questions", "next_actions"],
        "properties": {
            "summary": {"type": "string"},
            "decisions": {"type": "array", "items": {"type": "string"}},
            "open_questions": {"type": "array", "items": {"type": "string"}},
            "next_actions": {"type": "array", "items": {"type": "string"}},
        },
    }


def _call_codex_summary(prompt: str, *, codex_bin: str, model: str, timeout: int) -> str | None:
    if not shutil.which(codex_bin):
        return None

    auth_src = _codex_auth_path()
    if not auth_src.exists():
        return None

    with tempfile.TemporaryDirectory(prefix="remem-codex-wrapper-summary-") as tmpdir:
        codex_home = Path(tmpdir)
        try:
            shutil.copy2(auth_src, codex_home / "auth.json")
        except OSError:
            return None

        # Keep summary generation isolated from user-wide AGENTS/MCP workflows.
        (codex_home / "AGENTS.md").write_text(
            "You are a summarization engine.\n"
            "Do not run commands. Do not use tools. Do not read local files.\n"
            "Return only the structured JSON requested.\n",
            encoding="utf-8",
        )

        schema_path = codex_home / "output-schema.json"
        schema_path.write_text(json.dumps(_codex_summary_schema(), ensure_ascii=True), encoding="utf-8")
        out_path = codex_home / "last-message.txt"

        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        env.setdefault("NO_COLOR", "1")

        cmd = [
            codex_bin,
            "exec",
            "--ephemeral",
            "--skip-git-repo-check",
            "-s",
            "read-only",
            "-m",
            model,
            "--color",
            "never",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(out_path),
            "-",
        ]
        try:
            subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except Exception:
            return None

        if not out_path.exists():
            return None
        rendered = out_path.read_text(encoding="utf-8", errors="ignore").strip()
        return rendered or None


def _generate_structured_checkpoint_summary(
    *,
    codex_bin: str,
    project: str,
    session_id: str,
    kind: str,
    reason: str,
    changed_files: list[str],
    transcript_path: str,
) -> StructuredSummary | None:
    excerpt = _read_codex_transcript_excerpt(transcript_path)
    if not excerpt:
        return None

    files_block = "\n".join(f"- {path}" for path in changed_files[:15]) if changed_files else "- (none)"
    prompt = (
        "You are generating a coding-session checkpoint summary for future engineers.\n"
        "Return ONLY valid JSON (no markdown) with keys: summary, decisions, open_questions, next_actions.\n"
        "\n"
        "Rules:\n"
        "- summary: 2-5 sentences with concrete technical outcomes.\n"
        "- decisions/open_questions/next_actions: arrays of short strings.\n"
        "- Keep each bullet under 140 characters.\n"
        "- Redact secrets as [REDACTED].\n"
        "\n"
        f"Project: {project}\n"
        f"Session: {session_id}\n"
        f"Checkpoint kind: {kind}\n"
        f"Trigger reason: {reason}\n"
        "\n"
        "Changed files from git status:\n"
        f"{files_block}\n"
        "\n"
        "Conversation excerpt:\n"
        f"{excerpt}\n"
    )
    model = _summary_model()
    timeout = _int_env("REMEM_MEMORY_SUMMARY_TIMEOUT_SECONDS", _DEFAULT_SUMMARY_TIMEOUT_SECONDS)
    raw = _call_codex_summary(prompt, codex_bin=codex_bin, model=model, timeout=timeout)
    if not raw:
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    return StructuredSummary(
        summary=summary.strip(),
        decisions=_sanitize_items(parsed.get("decisions"), limit=12),
        open_questions=_sanitize_items(parsed.get("open_questions"), limit=12),
        next_actions=_sanitize_items(parsed.get("next_actions"), limit=12),
        model=model,
    )


def _load_checkpoint_records(path: Path, *, project: str, session_id: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                payload = row.get("payload")
                payload = payload if isinstance(payload, dict) else {}
                metadata = payload.get("metadata")
                metadata = metadata if isinstance(metadata, dict) else {}
                if metadata.get("project") != project or metadata.get("session_id") != session_id:
                    continue
                records.append(row)
    except OSError:
        return []
    return records


def _generate_rollup_summary(
    *,
    codex_bin: str,
    project: str,
    session_id: str,
    records: list[dict[str, Any]],
) -> str | None:
    checkpoint_summaries: list[str] = []
    decisions: list[str] = []
    open_questions: list[str] = []
    next_actions: list[str] = []
    for row in records:
        payload = row.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        metadata = payload.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        summary = metadata.get("summary")
        if isinstance(summary, str) and summary.strip():
            checkpoint_summaries.append(summary.strip())
        decisions.extend(item for item in (metadata.get("decisions") or []) if isinstance(item, str))
        open_questions.extend(item for item in (metadata.get("open_questions") or []) if isinstance(item, str))
        next_actions.extend(item for item in (metadata.get("next_actions") or []) if isinstance(item, str))

    if not checkpoint_summaries and not decisions and not open_questions and not next_actions:
        return None

    prompt = (
        "Synthesize these coding-session checkpoints into one final rollup summary.\n"
        "Return ONLY valid JSON with keys: summary, decisions, open_questions, next_actions.\n"
        "Keep output concise, technical, and concrete.\n"
        "\n"
        f"Project: {project}\n"
        f"Session: {session_id}\n"
        "\n"
        "Checkpoint summaries:\n"
        + ("\n".join(f"- {item}" for item in checkpoint_summaries[:40]) if checkpoint_summaries else "- (none)")
        + "\n\nDecisions:\n"
        + ("\n".join(f"- {item}" for item in decisions[:40]) if decisions else "- (none)")
        + "\n\nOpen questions:\n"
        + ("\n".join(f"- {item}" for item in open_questions[:40]) if open_questions else "- (none)")
        + "\n\nNext actions:\n"
        + ("\n".join(f"- {item}" for item in next_actions[:40]) if next_actions else "- (none)")
    )

    model = _summary_model()
    timeout = _int_env("REMEM_MEMORY_SUMMARY_TIMEOUT_SECONDS", _DEFAULT_SUMMARY_TIMEOUT_SECONDS)
    raw = _call_codex_summary(prompt, codex_bin=codex_bin, model=model, timeout=timeout)
    if not raw:
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    return summary.strip()


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
    decisions: list[str],
    open_questions: list[str],
    next_actions: list[str],
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
    for decision in decisions:
        args.extend(["--decision", decision])
    for open_question in open_questions:
        args.extend(["--open-question", open_question])
    for next_action in next_actions:
        args.extend(["--next-action", next_action])
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
    summary_enabled = _summary_enabled(codex_bin)
    transcript_path = os.getenv("REMEM_MEMORY_CODEX_TRANSCRIPT_PATH", "").strip()
    log_path = Path(args.log_file)
    if not log_path.is_absolute():
        log_path = cwd / log_path
    checkpoints_created = 0
    last_snapshot: list[str] = []
    lock = threading.Lock()
    started_at_dt = _utc_now()
    started_at = started_at_dt.isoformat()
    started_at_epoch = started_at_dt.timestamp()

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
            "summary_enabled": summary_enabled,
            "transcript_path": transcript_path,
            "active": True,
        },
    )

    def maybe_checkpoint(*, kind: str, reason: str, force: bool) -> bool:
        nonlocal checkpoints_created, last_snapshot, transcript_path
        changed = _current_changed_files(cwd) if in_git_repo else []

        if not force and not args.always_checkpoint and in_git_repo:
            if not changed:
                return False
            if changed == last_snapshot:
                return False

        summary = build_checkpoint_summary(kind=kind, reason=reason, changed_files=changed, max_files=args.max_files)
        decisions: list[str] = []
        open_questions: list[str] = []
        next_actions: list[str] = []

        if summary_enabled:
            transcript_path = _discover_codex_transcript_path(cwd, started_at_epoch, transcript_path) or ""
            if transcript_path:
                structured = _generate_structured_checkpoint_summary(
                    codex_bin=codex_bin,
                    project=project,
                    session_id=session_id,
                    kind=kind,
                    reason=reason,
                    changed_files=changed,
                    transcript_path=transcript_path,
                )
                if structured:
                    summary = structured.summary
                    decisions = structured.decisions
                    open_questions = structured.open_questions
                    next_actions = structured.next_actions

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
            decisions=decisions,
            open_questions=open_questions,
            next_actions=next_actions,
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
        if summary_enabled:
            records = _load_checkpoint_records(log_path, project=project, session_id=session_id)
            synthesized = _generate_rollup_summary(
                codex_bin=codex_bin,
                project=project,
                session_id=session_id,
                records=records,
            )
            if synthesized:
                rollup_summary = synthesized
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
            "summary_enabled": summary_enabled,
            "transcript_path": transcript_path,
            "checkpoints_created": checkpoints_created,
            "codex_exit_code": exit_code,
            "active": False,
        },
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
