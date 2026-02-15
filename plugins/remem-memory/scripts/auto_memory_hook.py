#!/usr/bin/env python3
"""Claude hook automation for Remem session checkpoints and rollups."""

from __future__ import annotations

import argparse
import json
import os
import shutil
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
        "transcript_path": "",
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

    for candidate in ("claude_cli", "codex_cli", "anthropic", "openai"):
        if _provider_available(candidate):
            return candidate
    return None


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
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                text = item["text"].strip()
                if text:
                    parts.append(text)
        return "\n".join(parts).strip()
    if isinstance(content, dict):
        if content.get("type") == "text" and isinstance(content.get("text"), str):
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
                cmd = " ".join(cmd.strip().split())
                snippet = f"Bash {cmd[:180]}{'...' if len(cmd) > 180 else ''}"
        else:
            path = tool_input.get("file_path") or tool_input.get("path")
            if isinstance(path, str) and path.strip():
                snippet = f"{name} {path.strip()}"
        out.append(snippet)
    return out


def _read_transcript_excerpt(transcript_path: str) -> str:
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

    head: list[str] = []
    tail: deque[str] = deque(maxlen=max(1, tail_lines or 1))
    total_lines = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for total_lines, line in enumerate(fh, start=1):
                line = line.rstrip("\n")
                if head_lines and total_lines <= head_lines:
                    head.append(line)
                if tail_lines:
                    tail.append(line)
    except OSError:
        return ""

    if total_lines <= 0:
        return ""

    tail_list = list(tail) if tail_lines else []
    if not tail_list or total_lines <= head_lines:
        combined = head
    else:
        tail_start_idx = max(0, total_lines - tail_lines)
        overlap = max(0, head_lines - tail_start_idx)
        combined = head + tail_list[overlap:]

    turns: list[str] = []
    for raw in combined:
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        row_type = row.get("type")
        if row_type not in {"user", "assistant"}:
            continue
        message = row.get("message")
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if row_type == "assistant" and role != "assistant":
            continue
        if row_type == "user" and role != "user":
            continue

        content = message.get("content")
        text = _extract_text_from_content(content)

        # Drop bulky tool_result payloads from user pseudo-messages.
        if isinstance(content, list) and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in content):
            text = ""

        if row_type == "assistant" and isinstance(content, list):
            if not text:
                tool_summaries = _summarize_tool_use_items(content)
                if tool_summaries:
                    text = "\n".join(f"[tool] {s}" for s in tool_summaries[:3]).strip()
            else:
                tool_summaries = _summarize_tool_use_items(content)
                if tool_summaries:
                    text = f"{text}\n[tool] {tool_summaries[0]}".strip()

        if not text:
            continue

        lowered = text.lower()
        if "<local-command-caveat>" in lowered or "<local-command-stdout>" in lowered:
            continue

        speaker = "User" if row_type == "user" else "Assistant"
        turns.append(f"{speaker}: {text}")

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
        with urllib_request.urlopen(req, timeout=timeout) as resp:  # nosec B310
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
        with urllib_request.urlopen(req, timeout=timeout) as resp:  # nosec B310
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
    if shutil.which("claude") is None:
        return None

    # Prevent nested Claude invocations from recursively triggering this plugin's hooks.
    env = os.environ.copy()
    env["REMEM_MEMORY_AUTO_ENABLED"] = "0"
    env["REMEM_MEMORY_SUMMARY_ENABLED"] = "0"
    env.setdefault("NO_COLOR", "1")

    cmd = [
        "claude",
        "-p",
        "--model",
        model,
        "--output-format",
        "text",
        "--no-session-persistence",
        "--tools",
        "",
        "--disable-slash-commands",
        "--setting-sources",
        "user",
        "--permission-mode",
        "bypassPermissions",
        prompt,
    ]
    try:
        result = subprocess.run(
            cmd,
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
    if shutil.which("codex") is None:
        return None

    base_home = Path(os.getenv("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
    auth_src = base_home / "auth.json"
    if not auth_src.exists():
        return None

    with tempfile.TemporaryDirectory(prefix="remem-codex-summary-") as tmpdir:
        codex_home = Path(tmpdir)
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

        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        env.setdefault("NO_COLOR", "1")

        cmd = [
            "codex",
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
    excerpt = _read_transcript_excerpt(transcript_path)
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
            "automation": "claude-hook",
            "hook_event": hook_event,
            **llm_meta,
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
        else "Automatic final rollup generated from checkpoint activity captured during this session."
    )
    if structured:
        decisions = structured.decisions or decisions
        open_questions = structured.open_questions or open_questions
        next_actions = structured.next_actions or next_actions

    lines = [
        "# Coding Session Rollup (Auto)",
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

    source_id = f"auto-rollup:{project_slug}:{session_slug}:{timestamp}".replace(":", "").replace("-", "")
    source_id = source_id[:200]

    llm_meta: dict[str, Any] = {}
    if structured:
        llm_meta = {
            "llm_summary_provider": structured.provider,
            "llm_summary_model": structured.model,
        }

    return {
        "title": f"{config.project} | {config.session_id} | final rollup (auto)",
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
            "automation": "claude-hook",
            "hook_event": "SessionEnd",
            **llm_meta,
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
        transcript_path = payload.get("transcript_path")
        if isinstance(transcript_path, str) and transcript_path.strip():
            state["transcript_path"] = transcript_path.strip()
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
        transcript_path = payload.get("transcript_path")
        if isinstance(transcript_path, str) and transcript_path.strip():
            state["transcript_path"] = transcript_path.strip()
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


def _handle_pre_compact(config: Config, payload: dict[str, Any]) -> int:
    lock_path = config.state_path.with_suffix(config.state_path.suffix + ".lock")
    with _state_lock(lock_path):
        state = _load_state(config.state_path, config.session_id)
        state["project"] = config.project
        transcript_path = payload.get("transcript_path")
        if isinstance(transcript_path, str) and transcript_path.strip():
            state["transcript_path"] = transcript_path.strip()

        # Avoid spamming duplicate checkpoints if PreCompact fires repeatedly without new activity.
        last_epoch = float(state.get("last_checkpoint_epoch") or 0.0)
        events_since = int(state.get("events_since_checkpoint") or 0)
        if last_epoch > 0 and events_since <= 0 and (_utc_now().timestamp() - last_epoch) < 30:
            _save_state(config.state_path, state)
            return 0

        _persist_checkpoint(
            config=config,
            kind="milestone",
            hook_event=str(payload.get("hook_event_name") or "PreCompact"),
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
        transcript_path = payload.get("transcript_path")
        if isinstance(transcript_path, str) and transcript_path.strip():
            state["transcript_path"] = transcript_path.strip()
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
        choices=("post_tool_use", "task_completed", "pre_compact", "session_end"),
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
    if args.mode == "pre_compact":
        return _handle_pre_compact(config, payload)
    return _handle_session_end(config, payload)


if __name__ == "__main__":
    raise SystemExit(main())
