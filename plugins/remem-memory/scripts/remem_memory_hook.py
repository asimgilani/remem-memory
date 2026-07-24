#!/usr/bin/env python3
"""Fail-open automatic recall, capture, and engineering hook adapter."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memory_policy import (
    RecallSource,
    contains_secret,
    is_off_record,
    merge_recall_items,
    render_untrusted_context,
    sanitize_query,
    should_capture,
    should_recall,
)
from remem_api import (
    RememAPI,
    RememAPIError,
    normalize_api_origin_for_environment,
    resolve_api_key,
    resolve_connection_api_key,
)
from remem_routing import (
    Connection,
    RouteHealthRecord,
    RouteTarget,
    RoutingConfig,
    load_or_initialize_routing,
    record_route_health,
    resolve_routes,
)

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover - unavailable on Windows
    fcntl = None  # type: ignore

_DEFAULT_DATA_DIR = ".config/remem-memory"
_DEFAULT_MODE = "auto"
_DEFAULT_SENSITIVITY = "balanced"
_VALID_MODES = {"auto", "recall-only", "off"}
_VALID_SENSITIVITIES = {"conservative", "balanced", "aggressive"}
_RECALL_TIMEOUT = 2.0
_INGEST_TIMEOUT = 2.0
_MAX_COMPLETED_TURNS = 100
_MAX_BACKGROUND_QUEUE = 128
_MAX_CREDENTIAL_BYTES = 8192
_DEFAULT_API_URL = "https://api.remem.io"
_BASE_WORKER_ENVIRONMENT_KEYS = (
    "HOME",
    "PATH",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)
_WORKER_ENVIRONMENT_KEYS = (
    "REMEM_API_URL",
    "REMEM_MEMORY_ALLOW_LOCAL_DEV",
    "REMEM_MEMORY_DATA_DIR",
    "REMEM_MEMORY_AUTO_ENABLED",
    "REMEM_MEMORY_PERSONAL_NAMESPACE",
    "REMEM_MEMORY_PROJECT",
    "REMEM_MEMORY_SESSION_ID",
    "REMEM_MEMORY_WRAPPER_SESSION_ID",
    "REMEM_MEMORY_ENGINEERING_ENABLED",
    "REMEM_MEMORY_ENGINEERING_NAMESPACE",
    "REMEM_MEMORY_STATE_FILE",
    "REMEM_MEMORY_LOG_FILE",
    "REMEM_MEMORY_INTERVAL_SECONDS",
    "REMEM_MEMORY_MIN_EVENTS",
    "REMEM_MEMORY_ROLLUP_ON_SESSION_END",
    "REMEM_MEMORY_SUMMARY_ENABLED",
    "REMEM_MEMORY_SUMMARY_PROVIDER",
    "REMEM_MEMORY_SUMMARY_MODEL",
    "REMEM_MEMORY_SUMMARY_HEAD_LINES",
    "REMEM_MEMORY_SUMMARY_TAIL_LINES",
    "REMEM_MEMORY_SUMMARY_MAX_MESSAGES",
    "REMEM_MEMORY_SUMMARY_MAX_CHARS",
    "REMEM_MEMORY_SUMMARY_TIMEOUT_SECONDS",
    "REMEM_MEMORY_SUMMARY_MAX_TOKENS",
)
_SUMMARY_PROVIDER_CREDENTIAL_KEYS = {
    "claude_cli": (
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    ),
    "codex_cli": ("CODEX_HOME",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
}
_WORKER_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "runpy.run_path(sys.argv.pop(1),run_name='__main__')"
)
_BACKGROUND_MODES = {
    "post_tool_use": "worker_post_tool_use",
    "stop": "worker_stop",
    "pre_compact": "worker_pre_compact",
    "session_end": "worker_session_end",
}
_WORKER_DRAIN_MODE = "worker_drain"
_WORKER_CREDENTIAL_MODES = {
    *_BACKGROUND_MODES.values(),
    _WORKER_DRAIN_MODE,
}
_WRITE_MODE_ORIGINS = {
    **{mode: mode for mode in _BACKGROUND_MODES},
    **{worker: mode for mode, worker in _BACKGROUND_MODES.items()},
    "engineering_session_end": "session_end",
}


@dataclass(frozen=True)
class Settings:
    mode: str = _DEFAULT_MODE
    sensitivity: str = _DEFAULT_SENSITIVITY


@dataclass(frozen=True)
class Dependencies:
    """Narrow injection points for deterministic hook tests."""

    api: object | None = None
    state_dir: Path | None = None
    engineering_handler: Callable[[str, dict[str, Any]], int] | None = None
    settings: Settings | None = None
    credential_resolver: Callable[[], str | None] | None = None
    background_writes: bool = False
    routing_resolver: (
        Callable[
            [str, str],
            tuple[RoutingConfig, tuple[RouteTarget, ...]],
        ]
        | None
    ) = None
    connection_credential_resolver: (
        Callable[[Connection], str | None] | None
    ) = None
    api_factory: Callable[[Connection, str], object] | None = None
    health_recorder: Callable[[RouteHealthRecord], None] | None = None


def default_data_dir() -> Path:
    configured = os.getenv("REMEM_MEMORY_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / _DEFAULT_DATA_DIR


def load_settings(data_dir: Path | None = None) -> Settings:
    """Load the bounded user controls, safely defaulting on any invalid data."""

    path = (data_dir or default_data_dir()) / "settings.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Settings()
    if not isinstance(parsed, dict):
        return Settings()
    mode = parsed.get("mode")
    sensitivity = parsed.get("sensitivity")
    return Settings(
        mode=mode if mode in _VALID_MODES else _DEFAULT_MODE,
        sensitivity=(
            sensitivity
            if sensitivity in _VALID_SENSITIVITIES
            else _DEFAULT_SENSITIVITY
        ),
    )


def _default_state() -> dict[str, Any]:
    return {
        "current_prompt": "",
        "turn_id": "",
        "off_record": False,
        "off_record_seen": False,
        "completed_turn_ids": [],
        "metrics": {"hits": 0, "misses": 0},
    }


def _counter(value: object) -> int:
    return value if type(value) is int and 0 <= value <= 1_000_000_000 else 0


def _normalize_state(value: object) -> dict[str, Any]:
    default = _default_state()
    if not isinstance(value, dict):
        return default
    prompt = value.get("current_prompt")
    turn_id = value.get("turn_id")
    completed = value.get("completed_turn_ids")
    metrics = value.get("metrics")
    return {
        "current_prompt": (
            prompt[:4000] if isinstance(prompt, str) else default["current_prompt"]
        ),
        "turn_id": (
            turn_id[:200] if isinstance(turn_id, str) else default["turn_id"]
        ),
        "off_record": (
            value.get("off_record")
            if type(value.get("off_record")) is bool
            else default["off_record"]
        ),
        "off_record_seen": (
            value.get("off_record_seen")
            if type(value.get("off_record_seen")) is bool
            else default["off_record_seen"]
        ),
        "completed_turn_ids": (
            [
                item[:200]
                for item in completed
                if isinstance(item, str) and item
            ][-_MAX_COMPLETED_TURNS:]
            if isinstance(completed, list)
            else default["completed_turn_ids"]
        ),
        "metrics": {
            "hits": _counter(metrics.get("hits"))
            if isinstance(metrics, dict)
            else 0,
            "misses": _counter(metrics.get("misses"))
            if isinstance(metrics, dict)
            else 0,
        },
    }


class StateStore:
    """Private, atomic, session-hashed prompt state."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = Path(data_dir or default_data_dir())
        self.sessions_dir = self.data_dir / "sessions"

    def path_for(self, session_id: str) -> Path:
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        return self.sessions_dir / f"{digest}.json"

    def load(self, session_id: str) -> dict[str, Any]:
        path = self.path_for(session_id)
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _default_state()
        except (OSError, json.JSONDecodeError):
            raise RuntimeError("memory state unavailable") from None
        if not isinstance(parsed, dict):
            raise RuntimeError("memory state unavailable")
        return _normalize_state(parsed)

    def save(self, session_id: str, state: dict[str, Any]) -> None:
        self._ensure_directories()
        path = self.path_for(session_id)
        descriptor = -1
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{path.stem}.",
                suffix=".tmp",
                dir=str(self.sessions_dir),
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(
                    _normalize_state(state),
                    stream,
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass

    def _ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.sessions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.data_dir, 0o700)
        os.chmod(self.sessions_dir, 0o700)

    @contextmanager
    def locked(self, session_id: str):
        self._ensure_directories()
        lock_path = self.path_for(session_id).with_suffix(".lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


class BackgroundQueueStore:
    """Private per-session FIFO for detached hook work."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = Path(data_dir or default_data_dir())
        self.queues_dir = self.data_dir / "queues"

    def path_for(self, session_id: str) -> Path:
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        return self.queues_dir / f"{digest}.json"

    def load(self, session_id: str) -> list[dict[str, Any]]:
        path = self.path_for(session_id)
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, json.JSONDecodeError):
            raise RuntimeError("background queue unavailable") from None
        events = parsed.get("events") if isinstance(parsed, dict) else None
        if not isinstance(events, list):
            raise RuntimeError("background queue unavailable")
        return _normalize_background_queue(events)

    def save(
        self,
        session_id: str,
        events: list[dict[str, Any]],
    ) -> None:
        self._ensure_directories()
        path = self.path_for(session_id)
        descriptor = -1
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{path.stem}.",
                suffix=".tmp",
                dir=str(self.queues_dir),
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(
                    {"events": _normalize_background_queue(events)},
                    stream,
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass

    def _ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.queues_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.data_dir, 0o700)
        os.chmod(self.queues_dir, 0o700)

    @contextmanager
    def locked(self, session_id: str):
        with self._file_lock(
            self.path_for(session_id).with_suffix(".lock")
        ):
            yield

    @contextmanager
    def worker_locked(self, session_id: str):
        with self._file_lock(
            self.path_for(session_id).with_suffix(".worker.lock")
        ):
            yield

    @contextmanager
    def _file_lock(self, path: Path):
        self._ensure_directories()
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _session_id(payload: dict[str, Any]) -> str:
    wrapper_value = os.getenv(
        "REMEM_MEMORY_WRAPPER_SESSION_ID",
        "",
    ).strip()
    if wrapper_value:
        return wrapper_value
    value = payload.get("session_id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    cwd = payload.get("cwd")
    return f"unknown:{cwd}" if isinstance(cwd, str) and cwd else "unknown"


def _turn_id(payload: dict[str, Any], current: str = "") -> str:
    value = payload.get("turn_id")
    if isinstance(value, str) and value.strip():
        return value.strip()[:200]
    if current:
        return current
    return f"turn-{uuid4().hex}"


def _settings(dependencies: Dependencies) -> Settings:
    legacy_enabled = os.getenv("REMEM_MEMORY_AUTO_ENABLED")
    if (
        legacy_enabled is not None
        and legacy_enabled.strip().lower() in {"0", "false", "no", "off", ""}
    ):
        return Settings(mode="off", sensitivity=_DEFAULT_SENSITIVITY)
    if dependencies.settings is not None:
        value = dependencies.settings
        return Settings(
            mode=value.mode if value.mode in _VALID_MODES else _DEFAULT_MODE,
            sensitivity=(
                value.sensitivity
                if value.sensitivity in _VALID_SENSITIVITIES
                else _DEFAULT_SENSITIVITY
            ),
        )
    return load_settings(dependencies.state_dir)


def _engineering_enabled() -> bool:
    value = os.getenv("REMEM_MEMORY_ENGINEERING_ENABLED")
    if value is None:
        return True
    return value.strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
        "",
    }


def _api(dependencies: Dependencies) -> object:
    return dependencies.api if dependencies.api is not None else RememAPI()


def _resolved_route(
    dependencies: Dependencies,
    *,
    behavior: str,
    harness: str,
) -> tuple[RoutingConfig, tuple[RouteTarget, ...]]:
    resolver = dependencies.routing_resolver
    if resolver is not None:
        return resolver(behavior, harness)
    config = load_or_initialize_routing(dependencies.state_dir)
    return (
        config,
        resolve_routes(
            config,
            behavior=behavior,  # type: ignore[arg-type]
            client=harness,  # type: ignore[arg-type]
        ),
    )


def _connection_for(
    config: RoutingConfig,
    connection_id: str,
) -> Connection | None:
    return next(
        (
            connection
            for connection in config.connections
            if connection.id == connection_id
        ),
        None,
    )


def _connection_credential(
    dependencies: Dependencies,
    connection: Connection,
) -> str | None:
    resolver = (
        dependencies.connection_credential_resolver
        or resolve_connection_api_key
    )
    try:
        credential = resolver(connection)
    except Exception:
        return None
    return (
        credential.strip()
        if isinstance(credential, str) and credential.strip()
        else None
    )


def _default_routed_api(
    connection: Connection,
    credential: str,
) -> object:
    del connection
    raw_url = os.environ.get("REMEM_API_URL", _DEFAULT_API_URL)
    policy_environment = {"REMEM_API_KEY": credential}
    allow_local = os.environ.get("REMEM_MEMORY_ALLOW_LOCAL_DEV")
    if allow_local is not None:
        policy_environment["REMEM_MEMORY_ALLOW_LOCAL_DEV"] = allow_local
    normalized_url = normalize_api_origin_for_environment(
        raw_url,
        policy_environment,
    )
    return RememAPI(
        normalized_url,
        credential,
        allow_local_dev=normalized_url != _DEFAULT_API_URL,
    )


def _routed_api(
    dependencies: Dependencies,
    connection: Connection,
) -> object | None:
    injected_without_credentials = (
        dependencies.api is not None
        and dependencies.connection_credential_resolver is None
        and dependencies.api_factory is None
    )
    if injected_without_credentials:
        return dependencies.api
    credential = _connection_credential(dependencies, connection)
    if credential is None:
        return None
    if dependencies.api_factory is not None:
        return dependencies.api_factory(connection, credential)
    if dependencies.api is not None:
        return dependencies.api
    return _default_routed_api(connection, credential)


def _health_failure(error: Exception) -> tuple[str, str]:
    kind = error.kind if isinstance(error, RememAPIError) else "transient"
    return {
        "auth": ("auth_error", "request_auth"),
        "permission": ("permission_error", "request_permission"),
        "namespace": ("namespace_error", "request_namespace"),
        "request": ("transient_error", "request_invalid"),
        "transient": ("transient_error", "request_transient"),
    }.get(kind, ("transient_error", "request_transient"))


def _record_health(
    dependencies: Dependencies,
    *,
    harness: str,
    behavior: str,
    target: RouteTarget,
    status: str,
    detail_code: str,
) -> None:
    observed_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    record = RouteHealthRecord(
        client=harness,
        behavior=behavior,
        connection_id=target.connection_id,
        namespace=target.namespace,
        status=status,
        detail_code=detail_code,
        observed_at=observed_at,
    )
    try:
        if dependencies.health_recorder is not None:
            dependencies.health_recorder(record)
        else:
            record_route_health(record, dependencies.state_dir)
    except Exception:
        pass


def _record_target_failure(
    dependencies: Dependencies,
    *,
    harness: str,
    behavior: str,
    targets: list[RouteTarget] | tuple[RouteTarget, ...],
    error: Exception | None,
) -> None:
    if error is None:
        status, detail_code = (
            "credential_error",
            "credential_unavailable",
        )
    else:
        status, detail_code = _health_failure(error)
    for target in targets:
        _record_health(
            dependencies,
            harness=harness,
            behavior=behavior,
            target=target,
            status=status,
            detail_code=detail_code,
        )


def _record_target_success(
    dependencies: Dependencies,
    *,
    harness: str,
    behavior: str,
    targets: list[RouteTarget] | tuple[RouteTarget, ...],
) -> None:
    detail_code = "read_ok" if behavior == "recall" else "write_ok"
    for target in targets:
        _record_health(
            dependencies,
            harness=harness,
            behavior=behavior,
            target=target,
            status="ok",
            detail_code=detail_code,
        )


def _default_engineering_handler(
    mode: str, payload: dict[str, Any]
) -> int:
    import auto_memory_hook

    return auto_memory_hook.handle_payload(mode, payload)


def _invoke_engineering(
    dependencies: Dependencies,
    mode: str,
    payload: dict[str, Any],
    harness: str,
    *,
    summaries_allowed: bool = True,
) -> None:
    if not _engineering_enabled():
        return
    handler = dependencies.engineering_handler or _default_engineering_handler
    previous_key = os.environ.get("REMEM_API_KEY")
    previous_harness = os.environ.get("REMEM_MEMORY_HARNESS")
    previous_rollup_trigger = os.environ.get(
        "REMEM_MEMORY_ROLLUP_TRIGGER"
    )
    previous_summary_enabled = os.environ.get(
        "REMEM_MEMORY_SUMMARY_ENABLED"
    )
    os.environ["REMEM_MEMORY_HARNESS"] = harness
    if not summaries_allowed:
        os.environ["REMEM_MEMORY_SUMMARY_ENABLED"] = "0"
    if mode == "session_end":
        trigger = payload.get("hook_event_name")
        if isinstance(trigger, str) and trigger in {
            "PreCompact",
            "SessionEnd",
        }:
            os.environ["REMEM_MEMORY_ROLLUP_TRIGGER"] = trigger
    if not (previous_key or "").strip():
        resolver = dependencies.credential_resolver
        if resolver is None and dependencies.engineering_handler is None:
            resolver = resolve_api_key
        if resolver is not None:
            try:
                credential = resolver()
            except Exception:
                credential = None
            if credential:
                os.environ["REMEM_API_KEY"] = credential
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.redirect_stderr(io.StringIO()):
                handler(mode, payload)
    except Exception:
        pass
    finally:
        if previous_key is None:
            os.environ.pop("REMEM_API_KEY", None)
        else:
            os.environ["REMEM_API_KEY"] = previous_key
        if previous_harness is None:
            os.environ.pop("REMEM_MEMORY_HARNESS", None)
        else:
            os.environ["REMEM_MEMORY_HARNESS"] = previous_harness
        if previous_rollup_trigger is None:
            os.environ.pop("REMEM_MEMORY_ROLLUP_TRIGGER", None)
        else:
            os.environ["REMEM_MEMORY_ROLLUP_TRIGGER"] = (
                previous_rollup_trigger
            )
        if previous_summary_enabled is None:
            os.environ.pop("REMEM_MEMORY_SUMMARY_ENABLED", None)
        else:
            os.environ["REMEM_MEMORY_SUMMARY_ENABLED"] = (
                previous_summary_enabled
            )


def _read_current_state(
    store: StateStore, session_id: str
) -> dict[str, Any] | None:
    try:
        return store.load(session_id)
    except Exception:
        return None


def _handle_user_prompt(
    payload: dict[str, Any],
    harness: str,
    dependencies: Dependencies,
    settings: Settings,
) -> dict[str, Any]:
    if settings.mode == "off":
        return {}

    prompt = payload.get("prompt")
    prompt = prompt if isinstance(prompt, str) else ""
    session_id = _session_id(payload)
    store = StateStore(dependencies.state_dir)
    safe_prompt = sanitize_query(prompt)
    suppressed = safe_prompt is None
    state = _default_state()
    first_prompt = True

    if settings.mode == "auto":
        with store.locked(session_id):
            state = store.load(session_id)
            first_prompt = not bool(state["turn_id"])
            state["current_prompt"] = safe_prompt or ""
            state["turn_id"] = _turn_id(payload)
            state["off_record"] = suppressed
            state["off_record_seen"] = bool(
                state["off_record_seen"]
                or is_off_record(prompt)
            )
            store.save(session_id, state)
    if suppressed:
        return {}

    recall_metrics = dict(state.get("metrics") or {})
    recall_metrics["first_prompt"] = first_prompt
    decision = should_recall(safe_prompt, recall_metrics)
    if not decision.allowed:
        return {}

    try:
        config, targets = _resolved_route(
            dependencies,
            behavior="recall",
            harness=harness,
        )
    except Exception:
        return {}
    if not targets:
        return {}

    connection_order = {
        connection.id: position
        for position, connection in enumerate(config.connections)
    }
    grouped: dict[str, list[tuple[int, RouteTarget]]] = {}
    for namespace_order, target in enumerate(targets):
        grouped.setdefault(target.connection_id, []).append(
            (namespace_order, target)
        )

    sources: list[RecallSource] = []
    for connection_id, selected in sorted(
        grouped.items(),
        key=lambda item: connection_order.get(item[0], len(connection_order)),
    ):
        connection = _connection_for(config, connection_id)
        selected_targets = [target for _order, target in selected]
        if connection is None:
            continue
        try:
            api = _routed_api(dependencies, connection)
        except Exception as error:
            _record_target_failure(
                dependencies,
                harness=harness,
                behavior="recall",
                targets=selected_targets,
                error=error,
            )
            continue
        if api is None:
            _record_target_failure(
                dependencies,
                harness=harness,
                behavior="recall",
                targets=selected_targets,
                error=None,
            )
            continue
        if any(target.namespace == "@readable" for target in selected_targets):
            namespaces = None
        else:
            namespaces = list(
                dict.fromkeys(target.namespace for target in selected_targets)
            )
        try:
            response = api.query(
                safe_prompt,
                namespaces,
                timeout=_RECALL_TIMEOUT,
            )
        except Exception as error:
            _record_target_failure(
                dependencies,
                harness=harness,
                behavior="recall",
                targets=selected_targets,
                error=error,
            )
            continue
        _record_target_success(
            dependencies,
            harness=harness,
            behavior="recall",
            targets=selected_targets,
        )
        sources.append(
            RecallSource(
                response=response,
                connection_order=connection_order.get(
                    connection_id,
                    len(connection_order),
                ),
                namespace_order=tuple(
                    (target.namespace, order)
                    for order, target in selected
                ),
            )
        )

    context = render_untrusted_context(merge_recall_items(sources))
    if settings.mode == "auto":
        with store.locked(session_id):
            latest = store.load(session_id)
            if latest["turn_id"] == state["turn_id"]:
                metrics = latest["metrics"]
                key = "hits" if context else "misses"
                metrics[key] = min(
                    1_000_000_000,
                    _counter(metrics.get(key)) + 1,
                )
                store.save(session_id, latest)
    if not context:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    }


def _capture_payload(
    prompt: str,
    assistant: str,
    session_id: str,
    turn_id: str,
    cwd: str,
    harness: str,
) -> dict[str, Any]:
    safe_prompt = sanitize_query(prompt) or ""
    safe_assistant = sanitize_query(assistant) or ""
    session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:24]
    turn_hash = hashlib.sha256(turn_id.encode("utf-8")).hexdigest()[:24]
    return {
        "title": "Durable conversation context",
        "content": f"User: {safe_prompt}\n\nAssistant: {safe_assistant}",
        "metadata": {
            "memory_kind": "conversation_turn",
            "session_hash": session_hash,
            "turn_hash": turn_hash,
            "source_harness": harness,
        },
        "source": "quick_capture",
        "source_id": f"remem-memory-turn:{session_hash}:{turn_hash}",
        "source_path": cwd,
        "mime_type": "text/markdown",
        "return_id": False,
    }


def _handle_stop(
    payload: dict[str, Any],
    harness: str,
    dependencies: Dependencies,
    settings: Settings,
    turn_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output = {"continue": True} if harness == "codex" else {}
    if settings.mode != "auto":
        return output

    session_id = _session_id(payload)
    store = StateStore(dependencies.state_dir)
    if turn_state is None:
        try:
            with store.locked(session_id):
                current = store.load(session_id)
        except Exception:
            current = None
    else:
        current = _normalize_turn_state(turn_state)
    if current is None or current["off_record"]:
        return output

    _invoke_engineering(
        dependencies,
        "task_completed",
        payload,
        harness,
        summaries_allowed=not current["off_record_seen"],
    )

    assistant = payload.get("last_assistant_message")
    assistant = assistant if isinstance(assistant, str) else ""
    payload_turn_id = _turn_id(payload, current["turn_id"])
    if (
        not current["current_prompt"]
        or not current["turn_id"]
        or payload_turn_id != current["turn_id"]
        or not should_capture(
            current["current_prompt"],
            assistant,
            settings.sensitivity,
        )
    ):
        return output

    try:
        config, targets = _resolved_route(
            dependencies,
            behavior="memory",
            harness=harness,
        )
    except Exception:
        return output
    if len(targets) != 1:
        return output
    target = targets[0]
    connection = _connection_for(config, target.connection_id)
    if connection is None:
        return output
    try:
        api = _routed_api(dependencies, connection)
    except Exception as error:
        _record_target_failure(
            dependencies,
            harness=harness,
            behavior="memory",
            targets=targets,
            error=error,
        )
        return output
    if api is None:
        _record_target_failure(
            dependencies,
            harness=harness,
            behavior="memory",
            targets=targets,
            error=None,
        )
        return output
    namespace = None if target.namespace == "@default" else target.namespace

    try:
        with store.locked(session_id):
            state = store.load(session_id)
            completed = state["completed_turn_ids"]
            if payload_turn_id in completed:
                return output
            memory = _capture_payload(
                current["current_prompt"],
                assistant,
                session_id,
                payload_turn_id,
                str(payload.get("cwd") or ""),
                harness,
            )
            api.ingest(
                memory,
                namespace,
                timeout=_INGEST_TIMEOUT,
            )
            completed.append(payload_turn_id)
            state["completed_turn_ids"] = completed[-_MAX_COMPLETED_TURNS:]
            store.save(session_id, state)
    except Exception as error:
        _record_target_failure(
            dependencies,
            harness=harness,
            behavior="memory",
            targets=targets,
            error=error,
        )
        return output
    _record_target_success(
        dependencies,
        harness=harness,
        behavior="memory",
        targets=targets,
    )
    return output


def _handle_engineering(
    payload: dict[str, Any],
    harness: str,
    dependencies: Dependencies,
    settings: Settings,
    mode: str,
) -> dict[str, Any]:
    if settings.mode != "auto":
        return {}
    store = StateStore(dependencies.state_dir)
    current = _read_current_state(store, _session_id(payload))
    if current is None or current["off_record"]:
        return {}
    _invoke_engineering(
        dependencies,
        mode,
        payload,
        harness,
        summaries_allowed=not current["off_record_seen"],
    )
    return {}


def _bounded_field(payload: dict[str, Any], name: str, limit: int) -> str:
    value = payload.get(name)
    return value[:limit] if isinstance(value, str) else ""


def _background_payload(
    payload: dict[str, Any],
    mode: str,
) -> dict[str, Any] | None:
    """Copy only bounded fields required by the one-shot worker."""

    minimized: dict[str, Any] = {}
    for name, limit in (
        ("hook_event_name", 64),
        ("session_id", 200),
        ("cwd", 2000),
        ("transcript_path", 2000),
    ):
        value = _bounded_field(payload, name, limit)
        if not value:
            continue
        if contains_secret(value):
            continue
        minimized[name] = value
    if mode == "post_tool_use":
        tool_name = _bounded_field(payload, "tool_name", 100)
        if tool_name:
            if contains_secret(tool_name):
                return None
            minimized["tool_name"] = tool_name
        tool_input = payload.get("tool_input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        safe_input: dict[str, str] = {}
        command_limit = 8192 if tool_name == "apply_patch" else 512
        for name, limit in (
            ("command", command_limit),
            ("file_path", 2000),
            ("path", 2000),
            ("patch", 8192),
        ):
            value = tool_input.get(name)
            if not isinstance(value, str) or not value:
                continue
            bounded = value[:limit]
            if contains_secret(bounded):
                return None
            safe_input[name] = bounded
        if safe_input:
            minimized["tool_input"] = safe_input
    elif mode == "stop":
        turn_id = _bounded_field(payload, "turn_id", 200)
        if turn_id:
            if contains_secret(turn_id):
                return None
            minimized["turn_id"] = turn_id
        assistant = _bounded_field(payload, "last_assistant_message", 2000)
        if assistant and not contains_secret(assistant):
            minimized["last_assistant_message"] = assistant
    return minimized


def _normalize_turn_state(value: object) -> dict[str, Any]:
    normalized = _normalize_state(value)
    raw_prompt = normalized["current_prompt"]
    prompt = sanitize_query(raw_prompt) if raw_prompt else ""
    unsafe_prompt = bool(raw_prompt and prompt is None)
    turn_id = normalized["turn_id"]
    unsafe_turn_id = bool(turn_id and contains_secret(turn_id))
    return {
        "current_prompt": prompt or "",
        "turn_id": "" if unsafe_turn_id else turn_id,
        "off_record": bool(
            normalized["off_record"]
            or unsafe_prompt
            or unsafe_turn_id
        ),
        "off_record_seen": bool(normalized["off_record_seen"]),
    }


def _normalize_background_queue(
    value: object,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in value[:_MAX_BACKGROUND_QUEUE]:
        if not isinstance(item, dict):
            continue
        event_id = item.get("id")
        mode = item.get("mode")
        harness = item.get("harness")
        payload = item.get("payload")
        turn_state = item.get("turn_state")
        off_record_seen = item.get("off_record_seen")
        if (
            not isinstance(event_id, str)
            or not event_id
            or len(event_id) > 64
            or mode not in _BACKGROUND_MODES
            or harness not in {"codex", "claude"}
            or not isinstance(payload, dict)
        ):
            continue
        safe_payload = _background_payload(payload, mode)
        if safe_payload is None or not isinstance(
            safe_payload.get("session_id"),
            str,
        ):
            continue
        normalized.append(
            {
                "id": event_id,
                "mode": mode,
                "harness": harness,
                "payload": safe_payload,
                "off_record_seen": (
                    off_record_seen
                    if type(off_record_seen) is bool
                    else False
                ),
                **(
                    {"turn_state": _normalize_turn_state(turn_state)}
                    if mode == "stop"
                    and isinstance(turn_state, dict)
                    else {}
                ),
            }
        )
    return normalized


def _enqueue_background(
    store: BackgroundQueueStore,
    session_id: str,
    mode: str,
    harness: str,
    payload: dict[str, Any],
    turn_state: dict[str, Any] | None = None,
    append_rollup_snapshot: bool = False,
    off_record_seen: bool = False,
) -> bool:
    with store.locked(session_id):
        events = store.load(session_id)
        required = 2 if append_rollup_snapshot else 1
        if len(events) + required > _MAX_BACKGROUND_QUEUE:
            return False
        events.append(
            {
                "id": uuid4().hex,
                "mode": mode,
                "harness": harness,
                "payload": payload,
                "off_record_seen": bool(off_record_seen),
                **(
                    {"turn_state": turn_state}
                    if turn_state is not None
                    else {}
                ),
            }
        )
        if append_rollup_snapshot:
            rollup_payload = _background_payload(payload, "session_end")
            if rollup_payload is None:
                return False
            events.append(
                {
                    "id": uuid4().hex,
                    "mode": "session_end",
                    "harness": harness,
                    "payload": rollup_payload,
                    "off_record_seen": bool(off_record_seen),
                }
            )
        store.save(session_id, events)
    return True


def _worker_environment(
    state_dir: Path | None,
    harness: str,
    *,
    summaries_allowed: bool = True,
) -> dict[str, str]:
    allowed = (*_BASE_WORKER_ENVIRONMENT_KEYS, *_WORKER_ENVIRONMENT_KEYS)
    environment = {
        name: os.environ[name]
        for name in allowed
        if isinstance(os.environ.get(name), str)
    }
    if not summaries_allowed:
        environment["REMEM_MEMORY_SUMMARY_ENABLED"] = "0"
        environment.pop("REMEM_MEMORY_SUMMARY_PROVIDER", None)
    provider = (
        _selected_worker_summary_provider(harness)
        if summaries_allowed
        else None
    )
    if provider is not None:
        environment["REMEM_MEMORY_SUMMARY_PROVIDER"] = provider
        for name in _SUMMARY_PROVIDER_CREDENTIAL_KEYS[provider]:
            value = os.environ.get(name)
            if isinstance(value, str):
                environment[name] = value
    if state_dir is not None:
        environment["REMEM_MEMORY_DATA_DIR"] = str(state_dir)
    return environment


def _selected_worker_summary_provider(harness: str) -> str | None:
    enabled = os.environ.get("REMEM_MEMORY_SUMMARY_ENABLED")
    if (
        isinstance(enabled, str)
        and enabled.strip().lower() in {"0", "false", "no", "off", ""}
    ):
        return None

    raw = os.environ.get("REMEM_MEMORY_SUMMARY_PROVIDER", "")
    aliases = {
        "claude": "claude_cli",
        "claude-cli": "claude_cli",
        "claude_cli": "claude_cli",
        "codex": "codex_cli",
        "codex-cli": "codex_cli",
        "codex_cli": "codex_cli",
        "anthropic": "anthropic",
        "openai": "openai",
    }
    configured = aliases.get(raw.strip().lower())
    if configured is not None:
        return configured

    default_provider = {
        "claude": ("claude", "claude_cli"),
        "codex": ("codex", "codex_cli"),
    }.get(harness)
    if (
        default_provider is not None
        and shutil.which(
            default_provider[0],
            path=os.environ.get("PATH"),
        )
        is not None
    ):
        return default_provider[1]
    return None


def _credential_descriptor(credential: str) -> int:
    try:
        encoded = credential.strip().encode("utf-8")
    except Exception:
        raise ValueError from None
    if (
        not encoded
        or len(encoded) > _MAX_CREDENTIAL_BYTES
        or b"\x00" in encoded
    ):
        raise ValueError

    read_descriptor, write_descriptor = os.pipe()
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(write_descriptor, encoded[offset:])
            if written <= 0:
                raise OSError
            offset += written
    except Exception:
        os.close(read_descriptor)
        raise ValueError from None
    finally:
        os.close(write_descriptor)
    return read_descriptor


def _consume_credential_descriptor(raw_descriptor: str) -> str | None:
    if not raw_descriptor.isdigit():
        return None
    descriptor = int(raw_descriptor)
    if descriptor <= 2:
        return None
    chunks: list[bytes] = []
    remaining = _MAX_CREDENTIAL_BYTES + 1
    try:
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    encoded = b"".join(chunks)
    if (
        not encoded
        or len(encoded) > _MAX_CREDENTIAL_BYTES
        or b"\x00" in encoded
    ):
        return None
    try:
        credential = encoded.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return credential or None


@contextmanager
def _worker_credential_scope(mode: str):
    if mode not in _WORKER_CREDENTIAL_MODES:
        yield
        return

    raw_descriptor = os.environ.pop("REMEM_API_KEY_FD", "")
    os.environ.pop("REMEM_API_KEY", None)
    explicit_credential = bool(raw_descriptor)
    if explicit_credential:
        credential = _consume_credential_descriptor(raw_descriptor)
    else:
        try:
            credential = resolve_api_key(environment={})
        except Exception:
            credential = None

    previous_allow_local = os.environ.get(
        "REMEM_MEMORY_ALLOW_LOCAL_DEV"
    )
    raw_url = os.environ.get("REMEM_API_URL", _DEFAULT_API_URL)
    policy_environment: dict[str, str] = {}
    if explicit_credential and credential:
        policy_environment["REMEM_API_KEY"] = credential
        if previous_allow_local is not None:
            policy_environment["REMEM_MEMORY_ALLOW_LOCAL_DEV"] = (
                previous_allow_local
            )
    else:
        os.environ.pop("REMEM_MEMORY_ALLOW_LOCAL_DEV", None)

    try:
        normalized_url = normalize_api_origin_for_environment(
            raw_url,
            policy_environment,
        )
    except Exception:
        credential = None
    else:
        os.environ["REMEM_API_URL"] = normalized_url

    if credential:
        os.environ["REMEM_API_KEY"] = credential
    try:
        yield
    finally:
        os.environ.pop("REMEM_API_KEY", None)
        if previous_allow_local is None:
            os.environ.pop("REMEM_MEMORY_ALLOW_LOCAL_DEV", None)
        else:
            os.environ["REMEM_MEMORY_ALLOW_LOCAL_DEV"] = (
                previous_allow_local
            )


def _spawn_background(
    payload: dict[str, Any],
    harness: str,
    dependencies: Dependencies,
    settings: Settings,
    mode: str,
) -> dict[str, Any]:
    output = (
        {"continue": True}
        if harness == "codex" and mode == "stop"
        else {}
    )
    if settings.mode != "auto":
        return output
    store = StateStore(dependencies.state_dir)
    raw_session_id = _session_id(payload)
    try:
        with store.locked(raw_session_id):
            current = store.load(raw_session_id)
    except Exception:
        return output
    minimized = _background_payload(payload, mode)
    if minimized is None or not isinstance(
        minimized.get("session_id"),
        str,
    ):
        return output

    session_id = _session_id(minimized)
    turn_state: dict[str, Any] | None = None
    if mode == "stop":
        payload_turn_id = _turn_id(payload, current["turn_id"])
        if (
            current["turn_id"]
            and payload_turn_id != current["turn_id"]
        ):
            turn_state = {
                "current_prompt": "",
                "turn_id": payload_turn_id,
                "off_record": False,
                "off_record_seen": current["off_record_seen"],
            }
        else:
            turn_state = {
                "current_prompt": current["current_prompt"],
                "turn_id": current["turn_id"],
                "off_record": current["off_record"],
                "off_record_seen": current["off_record_seen"],
            }
        if turn_state["off_record"]:
            return output
    elif current["off_record"]:
        return output

    queue = BackgroundQueueStore(dependencies.state_dir)
    if not _enqueue_background(
        queue,
        session_id,
        mode,
        harness,
        minimized,
        turn_state,
        append_rollup_snapshot=(
            harness == "codex" and mode == "pre_compact"
        ),
        off_record_seen=current["off_record_seen"],
    ):
        return output

    environment = _worker_environment(
        dependencies.state_dir,
        harness,
        summaries_allowed=not current["off_record_seen"],
    )
    credential = os.environ.get("REMEM_API_KEY", "").strip()
    descriptor: int | None = None
    try:
        if credential:
            descriptor = _credential_descriptor(credential)
            environment["REMEM_API_KEY_FD"] = str(descriptor)
        python = str(Path(sys.executable).resolve(strict=True))
        script = Path(__file__).resolve(strict=True)
        process = subprocess.Popen(
            [
                python,
                "-I",
                "-c",
                _WORKER_BOOTSTRAP,
                str(script.parent),
                str(script),
                "--mode",
                _WORKER_DRAIN_MODE,
                "--harness",
                harness,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            env=environment,
            pass_fds=(descriptor,) if descriptor is not None else (),
        )
        if process.stdin is not None:
            process.stdin.write(
                json.dumps(
                    {"session_id": session_id},
                    ensure_ascii=True,
                ).encode("utf-8")
            )
            process.stdin.close()
    except Exception:
        pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return output


def _process_background_event(
    event: dict[str, Any],
    dependencies: Dependencies,
    settings: Settings,
) -> None:
    mode = event["mode"]
    harness = event["harness"]
    payload = event["payload"]
    live_state = _read_current_state(
        StateStore(dependencies.state_dir),
        _session_id(payload),
    )
    off_record_seen = bool(event.get("off_record_seen"))
    if live_state is None:
        off_record_seen = True
    else:
        off_record_seen = bool(
            off_record_seen
            or live_state["off_record_seen"]
        )
    if mode == "stop":
        turn_state = event.get("turn_state")
        if isinstance(turn_state, dict):
            turn_state = _normalize_turn_state(turn_state)
            turn_state["off_record_seen"] = bool(
                turn_state["off_record_seen"]
                or off_record_seen
            )
        _handle_stop(
            payload,
            harness,
            dependencies,
            settings,
            turn_state=turn_state,
        )
        return
    _invoke_engineering(
        dependencies,
        mode,
        payload,
        harness,
        summaries_allowed=not off_record_seen,
    )


def _drain_background_queue(
    payload: dict[str, Any],
    dependencies: Dependencies,
    settings: Settings,
) -> dict[str, Any]:
    session_id = _session_id(payload)
    queue = BackgroundQueueStore(dependencies.state_dir)
    with queue.worker_locked(session_id):
        while True:
            with queue.locked(session_id):
                events = queue.load(session_id)
                if not events:
                    return {}
                event = events[0]
                live_settings = _settings(dependencies)
                if live_settings.mode != "auto":
                    queue.save(session_id, [])
                    return {}
            try:
                _process_background_event(
                    event,
                    dependencies,
                    live_settings,
                )
            except Exception:
                return {}
            with queue.locked(session_id):
                current = queue.load(session_id)
                if (
                    current
                    and current[0].get("id") == event.get("id")
                ):
                    queue.save(session_id, current[1:])


def handle_event(
    payload: dict[str, Any],
    harness: str,
    mode: str,
    dependencies: Dependencies | None = None,
) -> dict[str, Any]:
    """Handle one hook event and always return valid, non-blocking JSON."""

    selected_dependencies = dependencies or Dependencies(
        background_writes=True
    )
    selected_harness = harness if harness in {"codex", "claude"} else "claude"
    fallback = (
        {"continue": True}
        if selected_harness == "codex" and mode == "stop"
        else {}
    )
    try:
        settings = _settings(selected_dependencies)
        if mode == "user_prompt_submit":
            return _handle_user_prompt(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
            )
        original_mode = _WRITE_MODE_ORIGINS.get(mode)
        if original_mode is not None:
            safe_payload = _background_payload(payload, original_mode)
            if safe_payload is None:
                return fallback
            payload = safe_payload
        if (
            mode
            in {
                "post_tool_use",
                "pre_compact",
                "session_end",
            }
            and not _engineering_enabled()
        ):
            return fallback
        if (
            selected_harness == "claude"
            or selected_dependencies.background_writes
        ) and mode in _BACKGROUND_MODES:
            return _spawn_background(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
                mode,
            )
        if mode == "stop":
            return _handle_stop(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
            )
        if mode == "post_tool_use":
            return _handle_engineering(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
                "post_tool_use",
            )
        if mode == "pre_compact":
            return _handle_engineering(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
                "pre_compact",
            )
        if mode == "session_end":
            return _spawn_background(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
                mode,
            )
        if mode == _WORKER_DRAIN_MODE:
            return _drain_background_queue(
                payload,
                selected_dependencies,
                settings,
            )
        if mode == "worker_stop":
            return _handle_stop(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
            )
        worker_engineering_modes = {
            "worker_post_tool_use": "post_tool_use",
            "worker_pre_compact": "pre_compact",
            "worker_session_end": "session_end",
            "engineering_session_end": "session_end",
        }
        if mode in worker_engineering_modes:
            return _handle_engineering(
                payload,
                selected_harness,
                selected_dependencies,
                settings,
                worker_engineering_modes[mode],
            )
        return fallback
    except Exception:
        return fallback


def _read_stdin_json() -> dict[str, Any]:
    try:
        parsed = json.loads(sys.stdin.read() or "{}")
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        required=True,
        choices=(
            "user_prompt_submit",
            "post_tool_use",
            "stop",
            "pre_compact",
            "session_end",
            "worker_post_tool_use",
            "worker_stop",
            "worker_pre_compact",
            "worker_session_end",
            _WORKER_DRAIN_MODE,
            "engineering_session_end",
        ),
    )
    parser.add_argument(
        "--harness",
        required=True,
        choices=("codex", "claude"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    with _worker_credential_scope(args.mode):
        result = handle_event(
            _read_stdin_json(),
            harness=args.harness,
            mode=args.mode,
        )
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
