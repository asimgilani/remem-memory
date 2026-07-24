#!/usr/bin/env python3
"""Run Codex with automatic interval checkpoints and final rollups."""

from __future__ import annotations

import argparse
import hmac
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_PLUGIN_SCRIPTS = (
    Path(__file__).resolve().parents[1]
    / "plugins"
    / "remem-memory"
    / "scripts"
)
if str(_PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))

import remem_api  # noqa: E402
import remem_memory_hook  # noqa: E402
import remem_routing  # noqa: E402
from memory_policy import (  # noqa: E402
    contains_explicit_secret,
    contains_secret,
    is_off_record,
)

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
_RUNTIME_ENV_FD = "REMEM_MEMORY_RUNTIME_ENV_FD"
_MAX_RUNTIME_ENV_BYTES = 8 * 1024
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
_STRICT_CHILD_ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
)


@dataclass(frozen=True)
class StructuredSummary:
    summary: str
    decisions: list[str]
    open_questions: list[str]
    next_actions: list[str]
    model: str


@dataclass(frozen=True)
class EngineeringControl:
    mode_auto: bool
    off_record: bool
    off_record_seen: bool
    state_available: bool

    @property
    def writes_allowed(self) -> bool:
        return (
            self.mode_auto
            and self.state_available
            and not self.off_record
        )


@dataclass(frozen=True)
class TranscriptPrivacy:
    off_record_turns: int
    current_off_record: bool


@dataclass(frozen=True)
class EngineeringGate:
    writes_allowed: bool
    summaries_allowed: bool
    privacy_suppressed: bool


@dataclass(frozen=True)
class SessionsRouteSnapshot:
    route_revision: int
    connection_id: str
    write_namespace: str | None
    credential: str

    @property
    def identity(self) -> tuple[int, str, str | None]:
        return (
            self.route_revision,
            self.connection_id,
            self.write_namespace,
        )


def _is_process_injection_variable(name: str) -> bool:
    return (
        name.startswith("PYTHON")
        or name.startswith("DYLD_")
        or name.startswith("LD_")
        or name == "__PYVENV_LAUNCHER__"
    )


def _sanitized_runtime_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not _is_process_injection_variable(name)
    }


def _strict_child_environment(
    source: dict[str, str],
    *,
    include_remem: bool,
) -> dict[str, str]:
    environment = {
        name: source[name]
        for name in _STRICT_CHILD_ENVIRONMENT_KEYS
        if name in source
    }
    if include_remem:
        environment.update(
            {
                name: value
                for name, value in source.items()
                if name.startswith("REMEM_")
                and name
                not in {
                    "REMEM_API_KEY",
                    "REMEM_API_KEY_FD",
                    _RUNTIME_ENV_FD,
                }
            }
        )
    return environment


def _consume_runtime_environment(
    environment: dict[str, str],
) -> dict[str, str]:
    raw_descriptor = environment.pop(_RUNTIME_ENV_FD, "")
    if not raw_descriptor.isdigit():
        return {}
    descriptor = int(raw_descriptor)
    if descriptor < 3:
        return {}
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= _MAX_RUNTIME_ENV_BYTES:
            chunk = os.read(
                descriptor,
                min(4096, _MAX_RUNTIME_ENV_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return {}
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    raw = b"".join(chunks)
    if not raw or len(raw) > _MAX_RUNTIME_ENV_BYTES:
        return {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        name: value
        for name, value in parsed.items()
        if (
            isinstance(name, str)
            and isinstance(value, str)
            and _is_process_injection_variable(name)
        )
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


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


def _engineering_control(session_id: str) -> EngineeringControl:
    try:
        settings = remem_memory_hook.load_settings()
    except Exception:
        return EngineeringControl(
            mode_auto=False,
            off_record=False,
            off_record_seen=False,
            state_available=False,
        )
    if settings.mode != "auto":
        return EngineeringControl(
            mode_auto=False,
            off_record=False,
            off_record_seen=False,
            state_available=True,
        )
    try:
        store = remem_memory_hook.StateStore()
        with store.locked(session_id):
            state = store.load(session_id)
    except Exception:
        return EngineeringControl(
            mode_auto=True,
            off_record=False,
            off_record_seen=False,
            state_available=False,
        )
    return EngineeringControl(
        mode_auto=True,
        off_record=state.get("off_record") is True,
        off_record_seen=state.get("off_record_seen") is True,
        state_available=True,
    )


def _resolve_live_sessions_route(
    environment: dict[str, str] | None = None,
    *,
    primary_override: str | None = None,
    api_url: str = _DEFAULT_API_URL,
) -> SessionsRouteSnapshot | None:
    """Resolve one current Codex sessions destination and credential."""

    selected = os.environ if environment is None else environment
    configured_dir = selected.get("REMEM_MEMORY_DATA_DIR", "").strip()
    data_dir = (
        Path(configured_dir).expanduser()
        if configured_dir
        else Path.home() / ".config" / "remem-memory"
    )
    try:
        config = remem_routing.load_or_initialize_routing(
            data_dir,
            selected,
        )
        targets = remem_routing.resolve_routes(
            config,
            behavior="sessions",
            client="codex",
        )
        if len(targets) != 1:
            return None
        target = targets[0]
        connection = next(
            item
            for item in config.connections
            if item.id == target.connection_id
        )
        credential_environment = dict(selected)
        credential_environment.pop("REMEM_API_KEY", None)
        credential_environment.pop("REMEM_API_KEY_FD", None)
        selected_override = (
            primary_override.strip()
            if (
                connection.id == "primary"
                and isinstance(primary_override, str)
            )
            else ""
        )
        if selected_override:
            credential_environment["REMEM_API_KEY"] = selected_override
        allow_local_dev = bool(
            selected_override
            and credential_environment.get(
                "REMEM_MEMORY_ALLOW_LOCAL_DEV",
                "",
            ).strip().lower()
            in {"1", "true", "yes", "on"}
        )
        remem_api.normalize_api_origin(
            api_url,
            allow_local_dev=allow_local_dev,
        )
        credential = remem_api.resolve_connection_api_key(
            connection,
            environment=credential_environment,
        )
    except Exception:
        return None
    if not credential:
        return None
    return SessionsRouteSnapshot(
        route_revision=config.revision,
        connection_id=target.connection_id,
        write_namespace=(
            None if target.namespace == "@default" else target.namespace
        ),
        credential=credential,
    )


def _same_sessions_route(
    first: SessionsRouteSnapshot | Any,
    second: SessionsRouteSnapshot | Any,
) -> bool:
    try:
        same_identity = (
            first.route_revision,
            first.connection_id,
            first.write_namespace,
        ) == (
            second.route_revision,
            second.connection_id,
            second.write_namespace,
        )
        first_credential = first.credential
        second_credential = second.credential
        return bool(
            same_identity
            and isinstance(first_credential, str)
            and isinstance(second_credential, str)
            and hmac.compare_digest(
                first_credential.encode("utf-8"),
                second_credential.encode("utf-8"),
            )
        )
    except Exception:
        return False


def _value_contains_secret(
    value: Any,
    *,
    trusted_fragments: tuple[str, ...] = (),
) -> bool:
    if isinstance(value, str):
        inspected = value
        for fragment in sorted(
            (item for item in trusted_fragments if item),
            key=len,
            reverse=True,
        ):
            inspected = inspected.replace(fragment, "[trusted-local-path]")
        return contains_secret(inspected)
    if isinstance(value, dict):
        return any(
            _value_contains_secret(
                key,
                trusted_fragments=trusted_fragments,
            )
            or _value_contains_secret(
                item,
                trusted_fragments=trusted_fragments,
            )
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(
            _value_contains_secret(
                item,
                trusted_fragments=trusted_fragments,
            )
            for item in value
        )
    return False


def _resolve_helper_script(script_name: str) -> Path:
    return Path(__file__).resolve().with_name(script_name)


def _read_git_status_lines(
    cwd: Path,
    environment: dict[str, str],
) -> list[str]:
    git = shutil.which("git", path=environment.get("PATH"))
    if not git:
        return []
    try:
        out = subprocess.check_output(
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(cwd),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            env=_strict_child_environment(
                environment,
                include_remem=False,
            ),
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
    suppress_turn = False
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
                    if role == "user":
                        if _is_noise_user_text(text):
                            continue
                        suppress_turn = is_off_record(text)
                        if suppress_turn:
                            continue
                    elif suppress_turn:
                        continue
                    if contains_secret(text):
                        continue
                    prefix = "User" if role == "user" else "Assistant"
                    turns.append(f"{prefix}: {text}")
                elif payload_type == "function_call":
                    if suppress_turn:
                        continue
                    name = payload.get("name")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    snippet = name.strip()
                    if contains_secret(snippet):
                        continue
                    arguments = payload.get("arguments")
                    if isinstance(arguments, str) and arguments.strip():
                        compact = " ".join(arguments.strip().split())
                        if contains_secret(compact):
                            continue
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
    excerpt = excerpt.strip()
    return "" if contains_secret(excerpt) else excerpt


def _codex_transcript_privacy_state(
    transcript_path: str,
) -> TranscriptPrivacy:
    if not transcript_path:
        return TranscriptPrivacy(0, False)
    path = Path(transcript_path)
    if not path.exists():
        return TranscriptPrivacy(0, False)

    off_record_turns = 0
    current_off_record = False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    not isinstance(row, dict)
                    or row.get("type") != "response_item"
                ):
                    continue
                payload = row.get("payload")
                if not isinstance(payload, dict):
                    continue
                if (
                    payload.get("type") != "message"
                    or payload.get("role") != "user"
                ):
                    continue
                text = _extract_codex_message_text(
                    payload.get("content"),
                    role="user",
                )
                if not text or _is_noise_user_text(text):
                    continue
                current_off_record = is_off_record(text)
                if current_off_record:
                    off_record_turns += 1
    except OSError:
        return TranscriptPrivacy(0, False)
    return TranscriptPrivacy(
        off_record_turns=off_record_turns,
        current_off_record=current_off_record,
    )


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
        if (
            not cleaned
            or cleaned in seen
            or contains_secret(cleaned)
        ):
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
    resolved_codex = shutil.which(codex_bin)
    if not resolved_codex:
        return None

    auth_src = _codex_auth_path()
    if not auth_src.exists():
        return None

    with tempfile.TemporaryDirectory(prefix="remem-codex-wrapper-summary-") as tmpdir:
        isolated_root = Path(tmpdir)
        codex_home = isolated_root / "home"
        workspace = isolated_root / "workspace"
        codex_home.mkdir(mode=0o700)
        workspace.mkdir(mode=0o700)
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

        env = _strict_child_environment(
            _sanitized_runtime_environment(),
            include_remem=False,
        )
        env["CODEX_HOME"] = str(codex_home)
        env.setdefault("NO_COLOR", "1")

        cmd = [
            resolved_codex,
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
                check=False,
                env=env,
            )
        except Exception:
            return None

        if not out_path.exists():
            return None
        rendered = out_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not rendered or contains_secret(rendered):
            return None
        return rendered


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
    if _value_contains_secret(
        {
            "project": project,
            "session_id": session_id,
            "kind": kind,
            "reason": reason,
        }
    ):
        return None

    safe_changed_files = [
        path
        for path in changed_files[:15]
        if not contains_secret(path)
    ]
    files_block = (
        "\n".join(f"- {path}" for path in safe_changed_files)
        if safe_changed_files
        else "- (none)"
    )
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
    if not raw or contains_secret(raw):
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if (
        not isinstance(summary, str)
        or not summary.strip()
        or contains_secret(summary)
    ):
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
        if (
            isinstance(summary, str)
            and summary.strip()
            and not contains_secret(summary)
        ):
            checkpoint_summaries.append(summary.strip())
        decisions.extend(
            item
            for item in (metadata.get("decisions") or [])
            if isinstance(item, str) and not contains_secret(item)
        )
        open_questions.extend(
            item
            for item in (metadata.get("open_questions") or [])
            if isinstance(item, str) and not contains_secret(item)
        )
        next_actions.extend(
            item
            for item in (metadata.get("next_actions") or [])
            if isinstance(item, str) and not contains_secret(item)
        )

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
    if not raw or contains_secret(raw):
        return None
    parsed = _extract_json_object(raw)
    if not parsed:
        return None
    summary = parsed.get("summary")
    if (
        not isinstance(summary, str)
        or not summary.strip()
        or contains_secret(summary)
    ):
        return None
    return summary.strip()


def _is_git_repo(cwd: Path, environment: dict[str, str]) -> bool:
    git = shutil.which("git", path=environment.get("PATH"))
    if not git:
        return False
    try:
        out = subprocess.check_output(
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(cwd),
                "rev-parse",
                "--is-inside-work-tree",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            env=_strict_child_environment(
                environment,
                include_remem=False,
            ),
        ).strip()
    except Exception:
        return False
    return out == "true"


def _current_changed_files(
    cwd: Path,
    environment: dict[str, str],
) -> list[str]:
    return parse_porcelain_paths(
        _read_git_status_lines(cwd, environment)
    )


def _current_branch(
    cwd: Path,
    environment: dict[str, str],
) -> str | None:
    git = shutil.which("git", path=environment.get("PATH"))
    if not git:
        return None
    try:
        out = subprocess.check_output(
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(cwd),
                "branch",
                "--show-current",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            env=_strict_child_environment(
                environment,
                include_remem=False,
            ),
        ).strip()
    except Exception:
        return None
    return out or None


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


def _write_state(path: Path, payload: dict[str, Any]) -> bool:
    """Write private wrapper state atomically without following project links."""

    descriptor = -1
    temporary = ""
    try:
        parent = path.parent
        if parent.is_symlink():
            return False
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_status = os.lstat(parent)
        if not stat.S_ISDIR(parent_status.st_mode):
            return False
        try:
            target_status = os.lstat(path)
        except FileNotFoundError:
            target_status = None
        if (
            target_status is not None
            and not stat.S_ISREG(target_status.st_mode)
        ):
            return False

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(parent),
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(payload, stream, ensure_ascii=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

        try:
            target_status = os.lstat(path)
        except FileNotFoundError:
            target_status = None
        if (
            target_status is not None
            and not stat.S_ISREG(target_status.st_mode)
        ):
            return False
        os.replace(temporary, path)
        temporary = ""
        os.chmod(path, 0o600)
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass


def _load_helper_module(script_name: str) -> Any:
    script_path = _resolve_helper_script(script_name)
    if not script_path.exists():
        raise FileNotFoundError
    module_name = (
        "_remem_memory_wrapper_"
        + script_path.stem.replace("-", "_")
    )
    spec = importlib.util.spec_from_file_location(
        module_name,
        script_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _safe_checkpoint_inputs(
    *,
    project: str,
    session_id: str,
    summary: str,
    changed_files: list[str],
    decisions: list[str],
    open_questions: list[str],
    next_actions: list[str],
) -> bool:
    return not _value_contains_secret(
        {
            "project": project,
            "session_id": session_id,
            "summary": summary,
            "changed_files": changed_files,
            "decisions": decisions,
            "open_questions": open_questions,
            "next_actions": next_actions,
        }
    )


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
    credential: str | None = None,
    namespace: str | None = None,
    pre_ingest_check: Callable[[], bool] | None = None,
) -> bool:
    if contains_explicit_secret(str(cwd)):
        return False
    bounded_files = changed_files[:max_files]
    if not _safe_checkpoint_inputs(
        project=project,
        session_id=session_id,
        summary=summary,
        changed_files=bounded_files,
        decisions=decisions,
        open_questions=open_questions,
        next_actions=next_actions,
    ):
        return False
    try:
        helper = _load_helper_module("remem_checkpoint.py")
        branch = _current_branch(cwd, env)
        args = argparse.Namespace(
            project=project,
            session_id=session_id,
            kind=kind,
            title=None,
            summary=summary,
            summary_file=None,
            decision=list(decisions),
            open_question=list(open_questions),
            next_action=list(next_actions),
            file_touched=[
                str((cwd / rel_path).resolve())
                for rel_path in bounded_files
            ],
            repo_root=str(cwd),
            branch=branch or "unknown",
            source="quick_capture",
            source_path=None,
            return_id=False,
            ingest=ingest,
            api_url=env.get("REMEM_API_URL", _DEFAULT_API_URL),
            log_file=log_file,
            no_log=False,
            dry_run=dry_run,
        )
        payload = helper.build_checkpoint_payload(args)
        if branch is None:
            metadata = payload.get("metadata")
            if isinstance(metadata, dict):
                metadata["branch"] = None
        if _value_contains_secret(
            payload,
            trusted_fragments=(str(cwd),),
        ):
            return False

        response = None
        if ingest and not dry_run:
            if not credential:
                return False
            ingest_options = {
                "api_url": args.api_url,
                "api_key": credential,
                "payload": payload,
            }
            if namespace is not None:
                ingest_options["namespace"] = namespace
            if (
                pre_ingest_check is not None
                and not pre_ingest_check()
            ):
                return False
            response = helper.ingest_checkpoint(**ingest_options)
        record: dict[str, Any] = {
            "timestamp": helper._utc_now_iso(),
            "payload": payload,
        }
        helper.append_checkpoint_log(log_file, record)
        return True
    except Exception:
        print("warning: remem_checkpoint.py failed", file=sys.stderr)
        return False


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
    credential: str | None = None,
    namespace: str | None = None,
    pre_ingest_check: Callable[[], bool] | None = None,
) -> bool:
    if contains_explicit_secret(str(cwd)):
        return False
    if _value_contains_secret(
        {
            "project": project,
            "session_id": session_id,
            "summary": summary,
        }
    ):
        return False
    try:
        helper = _load_helper_module("remem_rollup.py")
        records = helper.filter_records(
            helper.load_checkpoint_log(log_file),
            project=project,
            session_id=session_id,
        )
        args = argparse.Namespace(
            log_file=log_file,
            project=project,
            session_id=session_id,
            summary=summary,
            kind="final",
            title=None,
            source="quick_capture",
            source_path=str(cwd),
            return_id=False,
            output=None,
            ingest=ingest,
            api_url=env.get("REMEM_API_URL", _DEFAULT_API_URL),
            dry_run=dry_run,
            no_log=False,
        )
        payload = helper.build_rollup_payload(args, records)
        if _value_contains_secret(
            payload,
            trusted_fragments=(str(cwd),),
        ):
            return False

        response = None
        if ingest and not dry_run:
            if not credential:
                return False
            ingest_options = {
                "api_url": args.api_url,
                "api_key": credential,
                "payload": payload,
            }
            if namespace is not None:
                ingest_options["namespace"] = namespace
            if (
                pre_ingest_check is not None
                and not pre_ingest_check()
            ):
                return False
            response = helper.ingest_checkpoint(**ingest_options)
        helper.append_checkpoint_log(
            log_file,
            {
                "timestamp": helper._utc_now_iso(),
                "payload": payload,
                "event": "rollup",
            },
        )
        return True
    except Exception:
        print("warning: remem_rollup.py failed", file=sys.stderr)
        return False


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        allow_abbrev=False,
    )
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
    startup_environment = dict(os.environ)
    primary_override = remem_api.consume_explicit_api_key(os.environ)
    startup_environment.pop("REMEM_API_KEY", None)
    startup_environment.pop("REMEM_API_KEY_FD", None)
    transported_runtime = _consume_runtime_environment(os.environ)
    direct_runtime = {
        name: value
        for name, value in startup_environment.items()
        if _is_process_injection_variable(name)
    }
    for name in direct_runtime:
        os.environ.pop(name, None)
    args = parse_args(argv or sys.argv[1:])
    cwd = Path.cwd().resolve()
    project = args.project.strip() or _default_project(cwd)
    session_id = args.session_id.strip() or _default_session_id()
    state_path = Path(args.state_file)
    if not state_path.is_absolute():
        state_path = cwd / state_path

    codex_bin = args.codex_bin.strip() or "codex"
    resolved_codex = shutil.which(codex_bin)
    if not resolved_codex:
        print(f"error: codex binary not found: {codex_bin}", file=sys.stderr)
        return 2

    ingest_requested = not args.no_ingest and not args.dry_run
    api_url = args.api_url
    credential_environment: dict[str, str] = {}
    if ingest_requested:
        credential_environment = {
            "REMEM_MEMORY_ALLOW_LOCAL_DEV": os.getenv(
                "REMEM_MEMORY_ALLOW_LOCAL_DEV",
                "",
            )
        }
        if primary_override:
            credential_environment["REMEM_API_KEY"] = primary_override
        try:
            api_url = remem_api.normalize_api_origin_for_environment(
                api_url,
                credential_environment,
            )
        except Exception:
            print("error: invalid Remem API URL", file=sys.stderr)
            return 2
    credential_environment.clear()
    ingest = ingest_requested

    safe_environment = _sanitized_runtime_environment()
    runtime_env = dict(safe_environment)
    runtime_env.update(direct_runtime)
    runtime_env.update(transported_runtime)
    runtime_env.pop("REMEM_API_KEY", None)
    runtime_env.pop("REMEM_API_KEY_FD", None)
    runtime_env.pop(_RUNTIME_ENV_FD, None)
    runtime_env["REMEM_API_URL"] = api_url
    runtime_env.setdefault("REMEM_MEMORY_PROJECT", project)
    runtime_env.setdefault("REMEM_MEMORY_SESSION_ID", session_id)
    runtime_env["REMEM_MEMORY_WRAPPER_SESSION_ID"] = session_id
    runtime_env["REMEM_MEMORY_ENGINEERING_ENABLED"] = "0"
    memory_env = _strict_child_environment(
        safe_environment,
        include_remem=True,
    )
    memory_env["REMEM_API_URL"] = api_url
    memory_env.setdefault("REMEM_MEMORY_PROJECT", project)
    memory_env.setdefault("REMEM_MEMORY_SESSION_ID", session_id)

    def resolve_live_route() -> SessionsRouteSnapshot | None:
        return _resolve_live_sessions_route(
            startup_environment,
            primary_override=primary_override,
            api_url=api_url,
        )

    def live_ingest_validator(
        expected: SessionsRouteSnapshot,
    ) -> Callable[[], bool]:
        def validate() -> bool:
            gate = refresh_engineering_gate()
            if not gate.writes_allowed:
                return False
            live = resolve_live_route()
            return bool(
                live is not None
                and _same_sessions_route(expected, live)
            )

        return validate

    in_git_repo = _is_git_repo(cwd, safe_environment)
    summary_enabled = _summary_enabled(resolved_codex)
    transcript_path = os.getenv("REMEM_MEMORY_CODEX_TRANSCRIPT_PATH", "").strip()
    log_path = Path(args.log_file)
    if not log_path.is_absolute():
        log_path = cwd / log_path
    checkpoints_created = 0
    last_snapshot: list[str] = []
    off_record_seen = False
    off_record_turns_by_path: dict[str, int] = {}
    privacy_boundary_pending = False
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

    def refresh_engineering_gate() -> EngineeringGate:
        nonlocal transcript_path
        nonlocal off_record_seen
        nonlocal privacy_boundary_pending
        discovered = _discover_codex_transcript_path(
            cwd,
            started_at_epoch,
            transcript_path,
        )
        if discovered:
            transcript_path = discovered
        privacy = _codex_transcript_privacy_state(transcript_path)
        control = _engineering_control(session_id)

        with lock:
            previous_turns = off_record_turns_by_path.get(
                transcript_path,
                0,
            )
            new_transcript_marker = (
                privacy.off_record_turns > previous_turns
            )
            if transcript_path:
                off_record_turns_by_path[transcript_path] = max(
                    previous_turns,
                    privacy.off_record_turns,
                )
            new_shared_marker = (
                control.off_record_seen and not off_record_seen
            )
            off_record_seen = bool(
                off_record_seen
                or control.off_record_seen
                or privacy.off_record_turns
            )
            privacy_suppressed = bool(
                control.off_record
                or privacy.current_off_record
                or new_shared_marker
                or new_transcript_marker
            )
            if privacy_suppressed:
                privacy_boundary_pending = True
            summaries_allowed = (
                summary_enabled and not off_record_seen
            )

        return EngineeringGate(
            writes_allowed=(
                control.writes_allowed and not privacy_suppressed
            ),
            summaries_allowed=summaries_allowed,
            privacy_suppressed=privacy_suppressed,
        )

    def maybe_checkpoint(*, kind: str, reason: str, force: bool) -> bool:
        nonlocal checkpoints_created
        nonlocal last_snapshot
        nonlocal transcript_path
        nonlocal privacy_boundary_pending
        changed = (
            _current_changed_files(cwd, safe_environment)
            if in_git_repo
            else []
        )
        gate = refresh_engineering_gate()
        if not gate.writes_allowed:
            with lock:
                last_snapshot = changed
            return False
        route_before = (
            resolve_live_route()
            if ingest
            else None
        )
        if ingest and route_before is None:
            with lock:
                last_snapshot = changed
            return False

        if not force and not args.always_checkpoint and in_git_repo:
            if not changed:
                return False
            if changed == last_snapshot:
                return False

        summary = build_checkpoint_summary(kind=kind, reason=reason, changed_files=changed, max_files=args.max_files)
        decisions: list[str] = []
        open_questions: list[str] = []
        next_actions: list[str] = []

        if gate.summaries_allowed:
            if transcript_path:
                structured = _generate_structured_checkpoint_summary(
                    codex_bin=resolved_codex,
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

        gate = refresh_engineering_gate()
        if not gate.writes_allowed:
            with lock:
                last_snapshot = changed
            return False
        route_after = (
            resolve_live_route()
            if ingest
            else None
        )
        if ingest and (
            route_after is None
            or not _same_sessions_route(route_before, route_after)
        ):
            with lock:
                last_snapshot = changed
            return False
        final_gate = refresh_engineering_gate()
        if not final_gate.writes_allowed:
            with lock:
                last_snapshot = changed
            return False
        route_final = (
            resolve_live_route()
            if ingest
            else None
        )
        if ingest and (
            route_final is None
            or not _same_sessions_route(route_after, route_final)
        ):
            with lock:
                last_snapshot = changed
            return False
        ok = _run_checkpoint(
            cwd=cwd,
            env=memory_env,
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
            credential=(
                route_final.credential
                if route_final is not None
                else None
            ),
            namespace=(
                route_final.write_namespace
                if route_final is not None
                else None
            ),
            pre_ingest_check=(
                live_ingest_validator(route_final)
                if route_final is not None
                else None
            ),
        )
        if ok:
            with lock:
                checkpoints_created += 1
                last_snapshot = changed
                privacy_boundary_pending = False
        return ok

    cmd = [resolved_codex, *args.codex_args]
    print(
        f"[remem-memory] launching codex with project={project} session_id={session_id}",
        file=sys.stderr,
    )
    child = subprocess.Popen(cmd, cwd=str(cwd), env=runtime_env)
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

    rollup_gate = refresh_engineering_gate()
    with lock:
        rollup_privacy_pending = privacy_boundary_pending
    if (
        not args.no_rollup
        and checkpoints_created > 0
        and rollup_gate.writes_allowed
        and not rollup_privacy_pending
    ):
        rollup_route_before = (
            resolve_live_route()
            if ingest
            else None
        )
        rollup_summary = (
            f"Automatic final rollup from Codex wrapper. "
            f"Exit code: {exit_code}. Checkpoints created: {checkpoints_created}."
        )
        if rollup_gate.summaries_allowed:
            records = _load_checkpoint_records(log_path, project=project, session_id=session_id)
            synthesized = _generate_rollup_summary(
                codex_bin=resolved_codex,
                project=project,
                session_id=session_id,
                records=records,
            )
            if synthesized:
                rollup_summary = synthesized
        rollup_gate = refresh_engineering_gate()
        with lock:
            rollup_privacy_pending = privacy_boundary_pending
        if (
            rollup_gate.writes_allowed
            and not rollup_privacy_pending
        ):
            rollup_route_after = (
                resolve_live_route()
                if ingest
                else None
            )
            final_rollup_gate = refresh_engineering_gate()
            rollup_route_final = (
                resolve_live_route()
                if (
                    ingest
                    and final_rollup_gate.writes_allowed
                    and not final_rollup_gate.privacy_suppressed
                )
                else None
            )
            if (
                final_rollup_gate.writes_allowed
                and not final_rollup_gate.privacy_suppressed
                and (
                    not ingest
                    or (
                        rollup_route_before is not None
                        and rollup_route_after is not None
                        and _same_sessions_route(
                            rollup_route_before,
                            rollup_route_after,
                        )
                        and rollup_route_final is not None
                        and _same_sessions_route(
                            rollup_route_after,
                            rollup_route_final,
                        )
                    )
                )
            ):
                _run_rollup(
                    cwd=cwd,
                    env=memory_env,
                    project=project,
                    session_id=session_id,
                    summary=rollup_summary,
                    log_file=args.log_file,
                    ingest=ingest,
                    dry_run=args.dry_run,
                    credential=(
                        rollup_route_final.credential
                        if rollup_route_final is not None
                        else None
                    ),
                    namespace=(
                        rollup_route_final.write_namespace
                        if rollup_route_final is not None
                        else None
                    ),
                    pre_ingest_check=(
                        live_ingest_validator(rollup_route_final)
                        if rollup_route_final is not None
                        else None
                    ),
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
            "off_record_seen": off_record_seen,
            "checkpoints_created": checkpoints_created,
            "codex_exit_code": exit_code,
            "active": False,
        },
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
