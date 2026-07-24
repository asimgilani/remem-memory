#!/usr/bin/env python3
"""Claude hook automation for Remem session checkpoints and rollups."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from memory_policy import (
    contains_explicit_secret,
    contains_secret,
    is_off_record,
)
from remem_api import (
    RememAPI,
    _NoRedirectHandler,
    _system_tls_context,
    normalize_api_origin_for_environment,
)

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore

_DEFAULT_INTERVAL_SECONDS = 20 * 60
_DEFAULT_MIN_EVENTS = 4
_DEFAULT_STATE_PATH = ".remem/auto-memory-state.json"
_DEFAULT_LOG_PATH = ".remem/session-checkpoints.ndjson"
_DEFAULT_API_URL = "https://api.remem.io"
_DEFAULT_SUMMARY_MAX_MESSAGES = 80
_DEFAULT_SUMMARY_HEAD_LINES = 120
_DEFAULT_SUMMARY_TAIL_LINES = 600
_DEFAULT_SUMMARY_MAX_CHARS = 12000
_DEFAULT_SUMMARY_MAX_TOKENS = 700
_DEFAULT_SUMMARY_MODEL_CLAUDE_CLI = "haiku"
_DEFAULT_SUMMARY_MODEL_CODEX_CLI = "gpt-5.3-codex-spark"
_DEFAULT_SUMMARY_MODEL_ANTHROPIC = "claude-3-5-haiku-20241022"
_DEFAULT_SUMMARY_MODEL_OPENAI = "gpt-4.1-nano"
_MAX_APPLY_PATCH_CHARS = 8_192
_MAX_APPLY_PATCH_PATHS = 32
_MAX_TOOL_PATH_CHARS = 2_000
_APPLY_PATCH_PATH_PREFIXES = (
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
)
_CODEX_DISABLED_SUMMARY_FEATURES = (
    "shell_tool",
    "unified_exec",
    "shell_snapshot",
    "code_mode",
    "code_mode_host",
    "code_mode_only",
    "workspace_dependencies",
    "plugins",
    "apps",
    "multi_agent",
    "multi_agent_v2",
    "computer_use",
    "browser_use",
    "browser_use_external",
    "in_app_browser",
    "skill_mcp_dependency_install",
    "memories",
    "hooks",
)
_BASE_CHILD_ENVIRONMENT_KEYS = (
    "HOME",
    "PATH",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)
_CLAUDE_CHILD_ENVIRONMENT_KEYS = (
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
)


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
    engineering_namespace: str | None = None
    allow_local_dev: bool = False


@dataclass(frozen=True)
class StructuredSummary:
    summary: str
    decisions: list[str]
    open_questions: list[str]
    next_actions: list[str]
    provider: str
    model: str


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


def _payload_contains_secret(
    payload: object,
    *,
    trusted_fragments: tuple[str, ...] = (),
) -> bool:
    try:
        serialized = json.dumps(payload, ensure_ascii=True)
    except (TypeError, ValueError):
        return True
    for fragment in sorted(
        (item for item in trusted_fragments if item),
        key=len,
        reverse=True,
    ):
        encoded_fragment = json.dumps(
            fragment,
            ensure_ascii=True,
        )[1:-1]
        serialized = serialized.replace(
            encoded_fragment,
            "[trusted-local-path]",
        )
    return contains_secret(serialized)


def _safe_path(value: object, *, limit: int = 2000) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = value.strip()[:limit]
    if not cleaned or contains_secret(cleaned):
        return ""
    return cleaned


def _safe_cwd_path(value: object, *, limit: int = 2000) -> str:
    """Accept local path entropy but reject explicit credential-bearing paths."""

    if not isinstance(value, str):
        return ""
    cleaned = value.strip()[:limit]
    if (
        not cleaned
        or any(ord(character) < 32 for character in cleaned)
        or contains_explicit_secret(cleaned)
    ):
        return ""
    return cleaned


def _safe_event_name(payload: dict[str, Any], default: str) -> str:
    value = payload.get("hook_event_name")
    if not isinstance(value, str):
        return default
    cleaned = value.strip()[:100]
    return cleaned if cleaned and not contains_secret(cleaned) else default


def _allowlisted_child_environment(
    *extra_keys: str,
) -> dict[str, str]:
    """Build a fresh child environment from an explicit, narrow allowlist."""

    allowed = (*_BASE_CHILD_ENVIRONMENT_KEYS, *extra_keys)
    return {
        name: os.environ[name]
        for name in allowed
        if isinstance(os.environ.get(name), str)
    }


def _resolved_executable(name: str) -> str | None:
    """Resolve one executable before spawning so PATH is not re-evaluated."""

    try:
        candidate = shutil.which(name, path=os.environ.get("PATH"))
        if not candidate:
            return None
        resolved = Path(candidate).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            return None
        return str(resolved)
    except (OSError, RuntimeError):
        return None


def _git_branch(cwd: Path) -> str | None:
    executable = _resolved_executable("git")
    if executable is None:
        return None
    try:
        out = subprocess.check_output(
            [executable, "-C", str(cwd), "branch", "--show-current"],
            stderr=subprocess.DEVNULL,
            env=_allowlisted_child_environment(),
        )
    except Exception:
        return None
    branch = out.decode("utf-8").strip()
    return branch or None


def _load_config(payload: dict[str, Any]) -> Config:
    cwd_raw = payload.get("cwd")
    safe_cwd = _safe_cwd_path(cwd_raw)
    cwd_candidate = (
        Path(safe_cwd).resolve() if safe_cwd else Path.cwd().resolve()
    )
    cwd = (
        cwd_candidate
        if not contains_explicit_secret(str(cwd_candidate))
        else Path("/")
    )
    configured_project = os.getenv("REMEM_MEMORY_PROJECT", "").strip()
    fallback_project = cwd.name or "unknown"
    if contains_secret(fallback_project):
        fallback_project = "unknown"
    project = (
        configured_project
        if configured_project and not contains_secret(configured_project)
        else fallback_project
    )
    configured_session = (
        os.getenv("REMEM_MEMORY_SESSION_ID", "").strip()
        or _derive_session_id(payload)
    )
    session_id = (
        configured_session[:200]
        if not contains_secret(configured_session)
        else f"session-{_utc_now().strftime('%Y%m%dT%H%M%S')}"
    )
    raw_api_url = (
        os.getenv("REMEM_API_URL", _DEFAULT_API_URL).strip()
        or _DEFAULT_API_URL
    )
    api_url = normalize_api_origin_for_environment(
        raw_api_url,
        os.environ,
    )
    api_key = os.getenv("REMEM_API_KEY", "").strip()
    engineering_namespace = os.getenv(
        "REMEM_MEMORY_ENGINEERING_NAMESPACE", ""
    ).strip() or None
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
        engineering_namespace=engineering_namespace,
        allow_local_dev=api_url != _DEFAULT_API_URL,
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
        "transcript_path": "",
    }


def _sanitize_state(
    value: dict[str, Any],
    fallback_session_id: str,
) -> dict[str, Any]:
    state = _default_state(fallback_session_id)
    session_id = value.get("session_id")
    if (
        isinstance(session_id, str)
        and session_id.strip()
        and not contains_secret(session_id)
    ):
        state["session_id"] = session_id.strip()[:200]
    project = value.get("project")
    if (
        isinstance(project, str)
        and project.strip()
        and not contains_secret(project)
    ):
        state["project"] = project.strip()[:200]
    for name in (
        "last_checkpoint_epoch",
        "events_since_checkpoint",
        "checkpoints_created",
        "last_rollup_epoch",
    ):
        candidate = value.get(name)
        if isinstance(candidate, (int, float)) and not isinstance(
            candidate, bool
        ):
            state[name] = candidate
    recent_events = value.get("recent_events")
    state["recent_events"] = (
        [
            event
            for event in recent_events
            if isinstance(event, dict)
            and not _payload_contains_secret(event)
        ][-30:]
        if isinstance(recent_events, list)
        else []
    )
    state["transcript_path"] = _safe_path(value.get("transcript_path"))
    return state


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
    return _sanitize_state(state, session_id)


def _prepare_storage_parent(path: Path) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise OSError("unsafe memory storage path")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        parent_status = os.lstat(parent)
    except OSError:
        raise OSError("unsafe memory storage path") from None
    if not stat.S_ISDIR(parent_status.st_mode):
        raise OSError("unsafe memory storage path")


def _require_regular_or_absent(path: Path) -> None:
    try:
        target_status = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(target_status.st_mode):
        raise OSError("unsafe memory storage path")


def _open_regular_file(
    path: Path,
    flags: int,
    mode: int = 0o600,
) -> int:
    _prepare_storage_parent(path)
    _require_regular_or_absent(path)
    protected_flags = flags | getattr(os, "O_CLOEXEC", 0)
    protected_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, protected_flags, mode)
    try:
        opened_status = os.fstat(descriptor)
        current_status = os.lstat(path)
        if (
            not stat.S_ISREG(opened_status.st_mode)
            or not stat.S_ISREG(current_status.st_mode)
            or opened_status.st_dev != current_status.st_dev
            or opened_status.st_ino != current_status.st_ino
        ):
            raise OSError("unsafe memory storage path")
        os.fchmod(descriptor, mode)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _save_state(path: Path, state: dict[str, Any]) -> None:
    session_id = state.get("session_id")
    fallback_session_id = (
        session_id.strip()[:200]
        if isinstance(session_id, str)
        and session_id.strip()
        and not contains_secret(session_id)
        else "session-unknown"
    )
    safe_state = _sanitize_state(state, fallback_session_id)
    _prepare_storage_parent(path)
    _require_regular_or_absent(path)
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(
                safe_state,
                stream,
                ensure_ascii=True,
                indent=2,
            )
            stream.flush()
            os.fsync(stream.fileno())
        _require_regular_or_absent(path)
        os.replace(temporary, path)
        temporary = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass


def _append_ndjson(
    path: Path,
    record: dict[str, Any],
    *,
    trusted_fragments: tuple[str, ...] = (),
) -> None:
    if _payload_contains_secret(
        record,
        trusted_fragments=trusted_fragments,
    ):
        return
    descriptor = _open_regular_file(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
    )
    with os.fdopen(descriptor, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


@contextmanager
def _state_lock(lock_path: Path):
    descriptor = _open_regular_file(
        lock_path,
        os.O_RDWR | os.O_APPEND | os.O_CREAT,
    )
    with os.fdopen(descriptor, "a+", encoding="utf-8") as lock_fh:
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
    if contains_secret(tool_name):
        return None
    tool_input = payload.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}

    files: list[str] = []
    summary = tool_name
    if tool_name in {"Write", "Edit", "MultiEdit"}:
        file_path = tool_input.get("file_path") or tool_input.get("path")
        if isinstance(file_path, str) and file_path.strip():
            if contains_secret(file_path):
                return None
            files = [file_path.strip()]
            summary = f"{tool_name} {file_path.strip()}"
    elif tool_name == "apply_patch":
        patch = tool_input.get("patch") or tool_input.get("command")
        if isinstance(patch, str):
            extracted = _extract_apply_patch_paths(patch)
            if extracted is None:
                return None
            files = extracted
            if files:
                label = "file" if len(files) == 1 else "files"
                summary = f"apply_patch {len(files)} {label}"
    elif tool_name == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str):
            if contains_secret(command):
                return None
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


def _extract_apply_patch_paths(patch: str) -> list[str] | None:
    files: list[str] = []
    seen: set[str] = set()
    bounded = patch[:_MAX_APPLY_PATCH_CHARS]
    if len(patch) > len(bounded) and not bounded.endswith(("\n", "\r")):
        bounded = bounded.rpartition("\n")[0]
    in_envelope = False
    for line in bounded.splitlines():
        if line == "*** Begin Patch":
            in_envelope = True
            continue
        if line == "*** End Patch":
            break
        if not in_envelope:
            continue
        prefix = next(
            (
                candidate
                for candidate in _APPLY_PATCH_PATH_PREFIXES
                if line.startswith(candidate)
            ),
            None,
        )
        if prefix is None:
            continue
        path = line[len(prefix) :].strip()
        if (
            not path
            or len(path) > _MAX_TOOL_PATH_CHARS
            or any(ord(character) < 32 for character in path)
            or contains_secret(path)
        ):
            return None
        if path not in seen:
            seen.add(path)
            files.append(path)
        if len(files) >= _MAX_APPLY_PATCH_PATHS:
            break
    return files


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


def _sanitize_items(items: Any, *, limit: int) -> list[str]:
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, str):
            continue
        cleaned = " ".join(item.strip().split())
        if not cleaned:
            continue
        out.append(cleaned)
        if len(out) >= limit:
            break
    return _dedupe(out)


def _llm_enabled() -> bool:
    if not _bool_env("REMEM_MEMORY_SUMMARY_ENABLED", True):
        return False
    return _select_llm_provider() is not None


def _normalize_provider(value: str) -> str | None:
    raw = value.strip().lower()
    if not raw:
        return None
    mapping = {
        "claude": "claude_cli",
        "claude-cli": "claude_cli",
        "claude_cli": "claude_cli",
        "codex": "codex_cli",
        "codex-cli": "codex_cli",
        "codex_cli": "codex_cli",
    }
    raw = mapping.get(raw, raw)
    if raw in {"claude_cli", "codex_cli", "anthropic", "openai"}:
        return raw
    return None


def _provider_available(provider: str) -> bool:
    if provider == "claude_cli":
        return shutil.which("claude") is not None
    if provider == "codex_cli":
        return shutil.which("codex") is not None
    if provider == "anthropic":
        return bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    if provider == "openai":
        return bool(os.getenv("OPENAI_API_KEY", "").strip())
    return False


def _select_llm_provider() -> str | None:
    forced_raw = os.getenv("REMEM_MEMORY_SUMMARY_PROVIDER", "")
    forced = _normalize_provider(forced_raw)
    if forced is not None:
        return forced if _provider_available(forced) else None

    harness = os.getenv("REMEM_MEMORY_HARNESS", "").strip().lower()
    provider = {
        "claude": "claude_cli",
        "codex": "codex_cli",
    }.get(harness)
    if provider is None:
        return None
    return provider if _provider_available(provider) else None


def _llm_model_for(provider: str) -> str:
    override = os.getenv("REMEM_MEMORY_SUMMARY_MODEL", "").strip()
    if override:
        return override
    if provider == "claude_cli":
        return _DEFAULT_SUMMARY_MODEL_CLAUDE_CLI
    if provider == "codex_cli":
        return _DEFAULT_SUMMARY_MODEL_CODEX_CLI
    if provider == "openai":
        return _DEFAULT_SUMMARY_MODEL_OPENAI
    return _DEFAULT_SUMMARY_MODEL_ANTHROPIC


def _extract_text_from_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if (
                item.get("type") in {"text", "input_text", "output_text"}
                and isinstance(item.get("text"), str)
            ):
                text = item["text"].strip()
                if text:
                    parts.append(text)
        return "\n".join(parts).strip()
    if isinstance(content, dict):
        if (
            content.get("type") in {"text", "input_text", "output_text"}
            and isinstance(content.get("text"), str)
        ):
            return content["text"].strip()
    return ""


def _summarize_tool_use_items(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != "tool_use":
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        tool_input = item.get("input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        snippet = name.strip()
        if name == "Bash":
            cmd = tool_input.get("command")
            if isinstance(cmd, str) and cmd.strip():
                if contains_secret(cmd):
                    continue
                cmd = " ".join(cmd.strip().split())
                snippet = f"Bash {cmd[:180]}{'...' if len(cmd) > 180 else ''}"
        else:
            path = tool_input.get("file_path") or tool_input.get("path")
            if isinstance(path, str) and path.strip():
                if contains_secret(path):
                    continue
                snippet = f"{name} {path.strip()}"
        out.append(snippet)
    return out


def _claude_transcript_turn(
    row: dict[str, Any],
) -> tuple[str, str] | None:
    row_type = row.get("type")
    if row_type not in {"user", "assistant"}:
        return None
    message = row.get("message")
    if not isinstance(message, dict):
        return None
    role = message.get("role")
    if row_type == "assistant" and role != "assistant":
        return None
    if row_type == "user" and role != "user":
        return None

    content = message.get("content")
    text = _extract_text_from_content(content)

    # Drop bulky tool_result payloads from user pseudo-messages.
    if isinstance(content, list) and any(
        isinstance(item, dict) and item.get("type") == "tool_result"
        for item in content
    ):
        text = ""

    if row_type == "assistant" and isinstance(content, list):
        tool_summaries = _summarize_tool_use_items(content)
        if tool_summaries:
            tool_text = "\n".join(
                f"[tool] {summary}"
                for summary in tool_summaries[:3]
            )
            text = f"{text}\n{tool_text}".strip()

    if not text:
        return None
    speaker = "User" if row_type == "user" else "Assistant"
    return speaker, text


def _codex_function_call_summary(
    payload: dict[str, Any],
) -> str | None:
    name = payload.get("name")
    if (
        not isinstance(name, str)
        or not name.strip()
        or contains_secret(name)
    ):
        return None
    name = name.strip()
    arguments = payload.get("arguments")
    if isinstance(arguments, str):
        if contains_secret(arguments):
            return None
        try:
            decoded = json.loads(arguments)
        except json.JSONDecodeError:
            decoded = (
                {"command": arguments}
                if name == "apply_patch"
                else {}
            )
    else:
        decoded = arguments
    tool_input = decoded if isinstance(decoded, dict) else {}
    if _payload_contains_secret(tool_input):
        return None
    event = _extract_tool_event(
        {
            "tool_name": name,
            "tool_input": tool_input,
        }
    )
    if event is None:
        return None
    summary = event.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    return f"[tool] {summary.strip()}"


def _codex_transcript_turn(
    row: dict[str, Any],
) -> tuple[str, str] | None:
    if row.get("type") != "response_item":
        return None
    payload = row.get("payload")
    if not isinstance(payload, dict):
        return None
    payload_type = payload.get("type")
    if payload_type == "function_call":
        summary = _codex_function_call_summary(payload)
        return ("Assistant", summary) if summary else None
    if payload_type != "message":
        # In particular, never include function_call_output/tool-result rows.
        return None
    role = payload.get("role")
    if role not in {"user", "assistant"}:
        return None
    content = payload.get("content")
    if isinstance(content, list) and any(
        isinstance(item, dict)
        and item.get("type") in {"tool_result", "function_call_output"}
        for item in content
    ):
        return None
    text = _extract_text_from_content(content)
    if not text:
        return None
    speaker = "User" if role == "user" else "Assistant"
    return speaker, text


def _read_transcript_excerpt(
    transcript_path: str,
    *,
    source_harness: str | None = None,
) -> str:
    path = Path(transcript_path)
    if not transcript_path or not path.exists():
        return ""

    head_lines = _int_env("REMEM_MEMORY_SUMMARY_HEAD_LINES", _DEFAULT_SUMMARY_HEAD_LINES)
    tail_lines = _int_env("REMEM_MEMORY_SUMMARY_TAIL_LINES", _DEFAULT_SUMMARY_TAIL_LINES)
    max_messages = _int_env("REMEM_MEMORY_SUMMARY_MAX_MESSAGES", _DEFAULT_SUMMARY_MAX_MESSAGES)
    max_chars = _int_env("REMEM_MEMORY_SUMMARY_MAX_CHARS", _DEFAULT_SUMMARY_MAX_CHARS)

    head_lines = max(0, int(head_lines))
    tail_lines = max(0, int(tail_lines))
    max_messages = max(1, int(max_messages))
    max_chars = max(500, int(max_chars))

    selected_harness = (
        source_harness
        if source_harness is not None
        else os.getenv("REMEM_MEMORY_HARNESS", "")
    ).strip().lower()
    if selected_harness == "codex":
        parsers = (_codex_transcript_turn,)
    elif selected_harness == "claude":
        parsers = (_claude_transcript_turn,)
    else:
        # Auto-detect only for legacy/manual callers without harness metadata.
        parsers = (
            _claude_transcript_turn,
            _codex_transcript_turn,
        )

    suppress_turn = False

    def filtered_turn(raw: str) -> str | None:
        nonlocal suppress_turn
        if not raw.strip():
            return None
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(row, dict):
            return None
        turn = next(
            (
                parsed
                for parser in parsers
                if (parsed := parser(row)) is not None
            ),
            None,
        )
        if turn is None:
            # Tool-result pseudo-messages do not start a new user turn.
            return None
        speaker, text = turn
        lowered = text.lower()
        if (
            "<local-command-caveat>" in lowered
            or "<local-command-stdout>" in lowered
        ):
            # Local command envelopes are not user-turn boundaries.
            return None

        if speaker == "User":
            if is_off_record(text) or contains_secret(text):
                # Suppress the complete turn, including later assistant and
                # tool-call rows, until the next safe user message.
                suppress_turn = True
                return None
            suppress_turn = False
        elif suppress_turn:
            return None

        if contains_secret(text):
            return None
        return f"{speaker}: {text}"

    head: list[tuple[int, str | None]] = []
    tail: deque[tuple[int, str | None]] = deque(
        maxlen=max(1, tail_lines or 1)
    )
    total_lines = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for total_lines, line in enumerate(fh, start=1):
                rendered = filtered_turn(line.rstrip("\n"))
                record = (total_lines, rendered)
                if head_lines and total_lines <= head_lines:
                    head.append(record)
                if tail_lines:
                    tail.append(record)
    except OSError:
        return ""

    if total_lines <= 0:
        return ""

    tail_list = list(tail) if tail_lines else []
    if not tail_list or total_lines <= head_lines:
        combined = head
    else:
        combined = head + [
            record
            for record in tail_list
            if record[0] > head_lines
        ]

    turns = [
        rendered
        for _, rendered in combined
        if rendered is not None
    ]

    turns = turns[-max_messages:]
    excerpt = "\n\n".join(turns).strip()
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
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


def _summary_https_opener():
    return urllib_request.build_opener(
        urllib_request.ProxyHandler({}),
        urllib_request.HTTPSHandler(
            context=_system_tls_context(),
        ),
        _NoRedirectHandler(),
    )


def _call_anthropic(prompt: str, *, model: str, max_tokens: int, timeout: int) -> str | None:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    req = urllib_request.Request(
        url="https://api.anthropic.com/v1/messages",
        data=json.dumps(
            {
                "model": model,
                "max_tokens": max(64, int(max_tokens)),
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}],
            },
            ensure_ascii=True,
        ).encode("utf-8"),
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with _summary_https_opener().open(
            req,
            timeout=timeout,
        ) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
        content = data.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and isinstance(first.get("text"), str):
                return first["text"]
    except Exception:
        return None
    return None


def _call_openai(prompt: str, *, model: str, max_tokens: int, timeout: int) -> str | None:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    req = urllib_request.Request(
        url="https://api.openai.com/v1/chat/completions",
        data=json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max(64, int(max_tokens)),
                "temperature": 0.2,
            },
            ensure_ascii=True,
        ).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
    )
    try:
        with _summary_https_opener().open(
            req,
            timeout=timeout,
        ) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0] if isinstance(choices[0], dict) else {}
            msg = first.get("message") if isinstance(first, dict) else {}
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
    except Exception:
        return None
    return None


def _call_claude_cli(prompt: str, *, model: str, timeout: int) -> str | None:
    executable = _resolved_executable("claude")
    if executable is None:
        return None

    # Prevent nested Claude invocations from recursively triggering this plugin's hooks.
    env = _allowlisted_child_environment(
        *_CLAUDE_CHILD_ENVIRONMENT_KEYS
    )
    env["REMEM_MEMORY_AUTO_ENABLED"] = "0"
    env["REMEM_MEMORY_SUMMARY_ENABLED"] = "0"
    env.setdefault("NO_COLOR", "1")

    cmd = [
        executable,
        "-p",
        "--model",
        model,
        "--output-format",
        "text",
        "--no-session-persistence",
        "--tools",
        "",
        "--disable-slash-commands",
        "--safe-mode",
        "--permission-mode",
        "bypassPermissions",
    ]
    with tempfile.TemporaryDirectory(
        prefix="remem-claude-summary-"
    ) as workspace:
        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except Exception:
            return None
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


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


def _call_codex_cli(prompt: str, *, model: str, timeout: int) -> str | None:
    executable = _resolved_executable("codex")
    if executable is None:
        return None

    base_home = Path(os.getenv("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
    auth_src = base_home / "auth.json"
    if not auth_src.exists():
        return None

    with tempfile.TemporaryDirectory(prefix="remem-codex-summary-") as tmpdir:
        isolated_root = Path(tmpdir)
        codex_home = isolated_root / "home"
        workspace = isolated_root / "workspace"
        codex_home.mkdir(mode=0o700)
        workspace.mkdir(mode=0o700)
        try:
            shutil.copy2(auth_src, codex_home / "auth.json")
        except OSError:
            return None

        # Use a minimal AGENTS.md to avoid executing user-wide agent workflows.
        (codex_home / "AGENTS.md").write_text(
            "You are a summarization engine.\n"
            "Do not run commands. Do not use tools. Do not read local files.\n"
            "Return only the structured JSON requested.\n",
            encoding="utf-8",
        )

        schema_path = codex_home / "output-schema.json"
        schema_path.write_text(json.dumps(_codex_summary_schema(), ensure_ascii=True), encoding="utf-8")
        out_path = codex_home / "last-message.txt"

        env = _allowlisted_child_environment()
        env["CODEX_HOME"] = str(codex_home)
        env.setdefault("NO_COLOR", "1")

        cmd = [
            executable,
            "exec",
            "--strict-config",
            "--ephemeral",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "-C",
            str(workspace),
            "-s",
            "read-only",
            "-c",
            'web_search="disabled"',
            "-c",
            "skills.bundled.enabled=false",
            "-c",
            "skills.include_instructions=false",
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            "include_environment_context=false",
            "-c",
            "include_apps_instructions=false",
            "-c",
            "include_collaboration_mode_instructions=false",
            "-c",
            "include_permissions_instructions=false",
            "-m",
            model,
        ]
        for feature in _CODEX_DISABLED_SUMMARY_FEATURES:
            cmd.extend(("--disable", feature))
        cmd.extend(
            [
                "--color",
                "never",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(out_path),
                "-",
            ]
        )
        try:
            subprocess.run(
                cmd,
                input=prompt,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except Exception:
            return None

        if not out_path.exists():
            return None
        rendered = out_path.read_text(encoding="utf-8", errors="ignore").strip()
        return rendered or None


def _prompt_llm(prompt: str) -> tuple[str | None, str | None, str | None]:
    provider = _select_llm_provider()
    if not provider:
        return None, None, None
    model = _llm_model_for(provider)
    timeout = _int_env("REMEM_MEMORY_SUMMARY_TIMEOUT_SECONDS", 15)
    max_tokens = _int_env("REMEM_MEMORY_SUMMARY_MAX_TOKENS", _DEFAULT_SUMMARY_MAX_TOKENS)
    if provider == "claude_cli":
        return _call_claude_cli(prompt, model=model, timeout=timeout), provider, model
    if provider == "codex_cli":
        return _call_codex_cli(prompt, model=model, timeout=timeout), provider, model
    if provider == "openai":
        return _call_openai(prompt, model=model, max_tokens=max_tokens, timeout=timeout), provider, model
    return _call_anthropic(prompt, model=model, max_tokens=max_tokens, timeout=timeout), provider, model


def _generate_checkpoint_structured_summary(
    *,
    config: Config,
    kind: str,
    hook_event: str,
    files_touched: list[str],
    recent_activity: list[str],
    transcript_path: str | None,
) -> StructuredSummary | None:
    if not _llm_enabled() or not transcript_path:
        return None
    excerpt = _read_transcript_excerpt(
        transcript_path,
        source_harness=os.getenv("REMEM_MEMORY_HARNESS", ""),
    )
    if not excerpt:
        return None

    files_block = "\n".join(f"- {p}" for p in files_touched[:12]) if files_touched else "- (none)"
    activity_block = "\n".join(f"- {a}" for a in recent_activity[:12]) if recent_activity else "- (none)"
    prompt = (
        "You are generating a coding-session checkpoint for future engineers/agents.\n"
        "Return ONLY valid JSON (no markdown) with keys: summary, decisions, open_questions, next_actions.\n"
        "\n"
        "Rules:\n"
        "- summary: 2-5 sentences, concrete technical details, mention outcomes.\n"
        "- decisions/open_questions/next_actions: arrays of strings, 0-10 items each.\n"
        "- Keep each bullet under 140 characters.\n"
        "- Do not include secrets or API keys; redact as [REDACTED] if needed.\n"
        "\n"
        f"Project: {config.project}\n"
        f"Session: {config.session_id}\n"
        f"Checkpoint kind: {kind}\n"
        f"Trigger: {hook_event}\n"
        "\n"
        "Files touched (from tool activity):\n"
        f"{files_block}\n"
        "\n"
        "Recent tool activity (high level):\n"
        f"{activity_block}\n"
        "\n"
        "Conversation excerpt:\n"
        f"{excerpt}\n"
    )
    raw, provider, model = _prompt_llm(prompt)
    if not raw or not provider or not model:
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    decisions = _sanitize_items(parsed.get("decisions"), limit=10)
    open_questions = _sanitize_items(parsed.get("open_questions"), limit=10)
    next_actions = _sanitize_items(parsed.get("next_actions"), limit=10)
    return StructuredSummary(
        summary=summary.strip(),
        decisions=decisions,
        open_questions=open_questions,
        next_actions=next_actions,
        provider=provider,
        model=model,
    )


def _extract_summary_from_markdown(content: str) -> str:
    if not content or "## Summary" not in content:
        return ""
    after = content.split("## Summary", 1)[1].lstrip("\n")
    lines: list[str] = []
    for line in after.splitlines():
        if line.startswith("## "):
            break
        if line.strip():
            lines.append(line.strip())
        if len(lines) >= 6:
            break
    return " ".join(lines).strip()


def _generate_rollup_structured_summary(
    *,
    config: Config,
    checkpoint_summaries: list[str],
    decisions: list[str],
    open_questions: list[str],
    next_actions: list[str],
) -> StructuredSummary | None:
    if not _llm_enabled():
        return None
    if not checkpoint_summaries and not decisions and not open_questions and not next_actions:
        return None

    summaries_block = "\n".join(f"- {s}" for s in checkpoint_summaries[:40]) if checkpoint_summaries else "- (none)"
    decisions_block = "\n".join(f"- {s}" for s in decisions[:40]) if decisions else "- (none)"
    open_block = "\n".join(f"- {s}" for s in open_questions[:40]) if open_questions else "- (none)"
    next_block = "\n".join(f"- {s}" for s in next_actions[:40]) if next_actions else "- (none)"

    prompt = (
        "You are synthesizing a coding-session rollup from checkpoint notes.\n"
        "Return ONLY valid JSON (no markdown) with keys: summary, decisions, open_questions, next_actions.\n"
        "\n"
        "Rules:\n"
        "- summary: 1-3 short paragraphs. Mention major outcomes, failures, and next steps.\n"
        "- Consolidate duplicates and keep the most important items.\n"
        "- Keep each bullet under 140 characters.\n"
        "\n"
        f"Project: {config.project}\n"
        f"Session: {config.session_id}\n"
        "\n"
        "Checkpoint summaries:\n"
        f"{summaries_block}\n"
        "\n"
        "Decisions (raw):\n"
        f"{decisions_block}\n"
        "\n"
        "Open questions (raw):\n"
        f"{open_block}\n"
        "\n"
        "Next actions (raw):\n"
        f"{next_block}\n"
    )
    raw, provider, model = _prompt_llm(prompt)
    if not raw or not provider or not model:
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    return StructuredSummary(
        summary=summary.strip(),
        decisions=_sanitize_items(parsed.get("decisions"), limit=18),
        open_questions=_sanitize_items(parsed.get("open_questions"), limit=18),
        next_actions=_sanitize_items(parsed.get("next_actions"), limit=18),
        provider=provider,
        model=model,
    )


def _build_checkpoint_payload(
    *,
    config: Config,
    kind: str,
    hook_event: str,
    recent_events: list[dict[str, Any]],
    events_since_checkpoint: int,
    transcript_path: str | None,
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
    if events_since_checkpoint > 0:
        summary = (
            f"Automatic {kind} checkpoint after {events_since_checkpoint} tool events."
            f" Recent files: {', '.join(files_touched[:5]) if files_touched else 'none'}."
        )
    else:
        summary = (
            f"Automatic {kind} checkpoint triggered by {hook_event}."
            f" Recent files: {', '.join(files_touched[:5]) if files_touched else 'none'}."
        )

    structured = _generate_checkpoint_structured_summary(
        config=config,
        kind=kind,
        hook_event=hook_event,
        files_touched=files_touched,
        recent_activity=recent_activity,
        transcript_path=transcript_path,
    )
    summary_text = structured.summary if structured else summary
    decisions = structured.decisions if structured else []
    open_questions = structured.open_questions if structured else []
    next_actions = structured.next_actions if structured else []
    llm_meta: dict[str, Any] = {}
    if structured:
        llm_meta = {
            "llm_summary_provider": structured.provider,
            "llm_summary_model": structured.model,
        }

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
        summary_text,
        "",
    ]
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in files_touched], ""])
    if recent_activity:
        lines.extend(["## Recent Activity", *[f"- {item}" for item in recent_activity], ""])
    if decisions:
        lines.extend(["## Decisions", *[f"- {item}" for item in decisions], ""])
    if open_questions:
        lines.extend(["## Open Questions", *[f"- {item}" for item in open_questions], ""])
    if next_actions:
        lines.extend(["## Next Actions", *[f"- {item}" for item in next_actions], ""])

    source_id = (
        f"auto-checkpoint:{project_slug}:{session_slug}:{kind}:{timestamp}"
    )
    source_id = source_id[:200]

    result = {
        "title": f"{config.project} | {config.session_id} | {kind} checkpoint (auto)",
        "content": "\n".join(lines).strip(),
        "metadata": {
            "project": config.project,
            "session_id": config.session_id,
            "checkpoint_kind": kind,
            "timestamp": timestamp,
            "repo_root": str(config.cwd),
            "files_touched": files_touched,
            "summary": summary_text,
            "decisions": decisions,
            "open_questions": open_questions,
            "next_actions": next_actions,
            "tags": [
                "memory:checkpoint",
                "memory:auto",
                f"project:{project_slug}",
                f"session:{session_slug}",
                f"checkpoint:{kind}",
            ],
            "automation": "remem-memory-hook",
            "source_harness": (
                os.getenv("REMEM_MEMORY_HARNESS", "").strip()
                or "unknown"
            ),
            "hook_event": hook_event,
            **llm_meta,
        },
        "source": "quick_capture",
        "source_id": source_id,
        "source_path": str(config.cwd),
        "mime_type": "text/markdown",
        "return_id": False,
    }
    if config.engineering_namespace is not None:
        result["namespace"] = config.engineering_namespace
    return result


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
        if row.get("event") != "auto_checkpoint":
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
    rolling = (
        os.getenv("REMEM_MEMORY_HARNESS", "").strip().lower()
        == "codex"
    )
    rollup_trigger = os.getenv(
        "REMEM_MEMORY_ROLLUP_TRIGGER",
        "SessionEnd",
    ).strip()
    if rollup_trigger not in {"PreCompact", "SessionEnd"}:
        rollup_trigger = "SessionEnd"
    files_touched: list[str] = []
    checkpoints: list[str] = []
    checkpoint_summaries: list[str] = []
    decisions: list[str] = []
    open_questions: list[str] = []
    next_actions: list[str] = []
    for row in records:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        title = payload.get("title")
        if isinstance(title, str) and title.strip():
            checkpoints.append(title.strip())
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        summary_text = metadata.get("summary")
        if isinstance(summary_text, str) and summary_text.strip():
            checkpoint_summaries.append(summary_text.strip())
        else:
            content = payload.get("content")
            if isinstance(content, str):
                extracted = _extract_summary_from_markdown(content)
                if extracted:
                    checkpoint_summaries.append(extracted)

        for value in metadata.get("decisions") or []:
            if isinstance(value, str) and value.strip():
                decisions.append(value.strip())
        for value in metadata.get("open_questions") or []:
            if isinstance(value, str) and value.strip():
                open_questions.append(value.strip())
        for value in metadata.get("next_actions") or []:
            if isinstance(value, str) and value.strip():
                next_actions.append(value.strip())
        for value in metadata.get("files_touched") or []:
            if isinstance(value, str):
                files_touched.append(value)

    files_touched = _dedupe(files_touched)
    checkpoints = _dedupe(checkpoints)
    checkpoint_summaries = _dedupe(checkpoint_summaries)
    decisions = _dedupe(decisions)
    open_questions = _dedupe(open_questions)
    next_actions = _dedupe(next_actions)

    structured = _generate_rollup_structured_summary(
        config=config,
        checkpoint_summaries=checkpoint_summaries,
        decisions=decisions,
        open_questions=open_questions,
        next_actions=next_actions,
    )
    rollup_summary = (
        structured.summary
        if structured and structured.summary
        else (
            "Automatic rolling rollup generated from checkpoint activity "
            "captured during this session."
            if rolling
            else "Automatic final rollup generated from checkpoint activity "
            "captured during this session."
        )
    )
    if structured:
        decisions = structured.decisions or decisions
        open_questions = structured.open_questions or open_questions
        next_actions = structured.next_actions or next_actions

    lines = [
        (
            "# Coding Session Rolling Rollup (Auto)"
            if rolling
            else "# Coding Session Rollup (Auto)"
        ),
        f"- Project: {config.project}",
        f"- Session: {config.session_id}",
        f"- Generated: {timestamp}",
        f"- Checkpoints summarized: {len(records)}",
        "",
        "## Summary",
        rollup_summary,
        "",
    ]
    if checkpoints:
        lines.extend(["## Included Checkpoints", *[f"- {item}" for item in checkpoints], ""])
    if files_touched:
        lines.extend(["## Files Touched", *[f"- {item}" for item in files_touched], ""])
    if decisions:
        lines.extend(["## Decisions", *[f"- {item}" for item in decisions], ""])
    if open_questions:
        lines.extend(["## Open Questions", *[f"- {item}" for item in open_questions], ""])
    if next_actions:
        lines.extend(["## Next Actions", *[f"- {item}" for item in next_actions], ""])

    source_id = f"auto-rollup:{project_slug}:{session_slug}:{timestamp}"
    source_id = source_id[:200]

    llm_meta: dict[str, Any] = {}
    if structured:
        llm_meta = {
            "llm_summary_provider": structured.provider,
            "llm_summary_model": structured.model,
        }

    result = {
        "title": (
            f"{config.project} | {config.session_id} | "
            f"{'rolling' if rolling else 'final'} rollup (auto)"
        ),
        "content": "\n".join(lines).strip(),
        "metadata": {
            "project": config.project,
            "session_id": config.session_id,
            "checkpoint_kind": "final",
            "timestamp": timestamp,
            "summary": rollup_summary,
            "decisions": decisions,
            "open_questions": open_questions,
            "next_actions": next_actions,
            "tags": [
                "memory:checkpoint",
                "memory:rollup",
                "memory:auto",
                f"project:{project_slug}",
                f"session:{session_slug}",
                "checkpoint:final",
            ],
            "automation": "remem-memory-hook",
            "source_harness": (
                os.getenv("REMEM_MEMORY_HARNESS", "").strip()
                or "unknown"
            ),
            "hook_event": rollup_trigger,
            **llm_meta,
        },
        "source": "quick_capture",
        "source_id": source_id,
        "source_path": str(config.cwd),
        "mime_type": "text/markdown",
        "return_id": False,
    }
    if config.engineering_namespace is not None:
        result["namespace"] = config.engineering_namespace
    return result


def _ingest(config: Config, payload: dict[str, Any]) -> dict[str, Any] | None:
    if (
        _payload_contains_secret(
            payload,
            trusted_fragments=(str(config.cwd),),
        )
        or not config.api_key
    ):
        return None
    try:
        api = RememAPI(
            api_url=config.api_url,
            api_key=config.api_key,
            allow_local_dev=config.allow_local_dev,
        )
        return api.ingest(payload, None, timeout=20)
    except Exception:  # pragma: no cover
        sys.stderr.write("[remem-memory] ingest failed\n")
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
    transcript_path = state.get("transcript_path")
    transcript_path = transcript_path if isinstance(transcript_path, str) and transcript_path.strip() else None
    payload = _build_checkpoint_payload(
        config=config,
        kind=kind,
        hook_event=hook_event,
        recent_events=[event for event in recent_events if isinstance(event, dict)],
        events_since_checkpoint=events_since,
        transcript_path=transcript_path,
    )
    response = _ingest(config, payload)
    _append_ndjson(
        config.log_path,
        {"timestamp": _utc_now_iso(), "event": "auto_checkpoint", "payload": payload, "response": response},
        trusted_fragments=(str(config.cwd),),
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
        trusted_fragments=(str(config.cwd),),
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
        transcript_path = _safe_path(payload.get("transcript_path"))
        if transcript_path:
            state["transcript_path"] = transcript_path
        recent = state.get("recent_events")
        recent = recent if isinstance(recent, list) else []
        recent.append(event)
        state["recent_events"] = recent[-30:]
        state["events_since_checkpoint"] = int(state.get("events_since_checkpoint") or 0) + 1

        if _should_interval_checkpoint(state, config):
            _persist_checkpoint(
                config=config,
                kind="interval",
                hook_event=_safe_event_name(payload, "PostToolUse"),
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
        transcript_path = _safe_path(payload.get("transcript_path"))
        if transcript_path:
            state["transcript_path"] = transcript_path
        events_since = int(state.get("events_since_checkpoint") or 0)
        if events_since <= 0:
            _save_state(config.state_path, state)
            return 0
        _persist_checkpoint(
            config=config,
            kind="milestone",
            hook_event=_safe_event_name(payload, "TaskCompleted"),
            state=state,
        )
        state["last_checkpoint_epoch"] = _utc_now().timestamp()
        state["events_since_checkpoint"] = 0
        state["recent_events"] = []
        state["checkpoints_created"] = int(state.get("checkpoints_created") or 0) + 1
        _save_state(config.state_path, state)
    return 0


def _handle_pre_compact(config: Config, payload: dict[str, Any]) -> int:
    lock_path = config.state_path.with_suffix(config.state_path.suffix + ".lock")
    with _state_lock(lock_path):
        state = _load_state(config.state_path, config.session_id)
        state["project"] = config.project
        transcript_path = _safe_path(payload.get("transcript_path"))
        if transcript_path:
            state["transcript_path"] = transcript_path

        # Avoid spamming duplicate checkpoints if PreCompact fires repeatedly without new activity.
        last_epoch = float(state.get("last_checkpoint_epoch") or 0.0)
        events_since = int(state.get("events_since_checkpoint") or 0)
        if last_epoch > 0 and events_since <= 0 and (_utc_now().timestamp() - last_epoch) < 30:
            _save_state(config.state_path, state)
            return 0

        _persist_checkpoint(
            config=config,
            kind="milestone",
            hook_event=_safe_event_name(payload, "PreCompact"),
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
        transcript_path = _safe_path(payload.get("transcript_path"))
        if transcript_path:
            state["transcript_path"] = transcript_path
        events_since = int(state.get("events_since_checkpoint") or 0)
        if events_since > 0:
            _persist_checkpoint(
                config=config,
                kind="milestone",
                hook_event=_safe_event_name(payload, "SessionEnd"),
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
        choices=("post_tool_use", "task_completed", "pre_compact", "session_end"),
        help="Hook mode to execute.",
    )
    return parser.parse_args(argv)


def handle_payload(mode: str, payload: dict[str, Any]) -> int:
    """Run one existing engineering hook mode for an already-parsed payload."""

    config = _load_config(payload)
    if not config.enabled:
        return 0
    if mode == "post_tool_use":
        return _handle_post_tool_use(config, payload)
    if mode == "task_completed":
        return _handle_task_completed(config, payload)
    if mode == "pre_compact":
        return _handle_pre_compact(config, payload)
    if mode == "session_end":
        return _handle_session_end(config, payload)
    raise ValueError(f"unsupported mode: {mode}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    payload = _read_stdin_json()
    return handle_payload(args.mode, payload)


if __name__ == "__main__":
    raise SystemExit(main())
