#!/usr/bin/env python3
"""Canonical CLI for Remem Memory and its legacy workflow aliases."""

from __future__ import annotations

import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Mapping, Optional


_SCRIPT_PATH = Path(__file__).resolve()
_REPOSITORY_ROOT = _SCRIPT_PATH.parent.parent
_PLUGIN_SCRIPTS = (
    _REPOSITORY_ROOT / "plugins" / "remem-memory" / "scripts"
)
if str(_PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))

import remem_api  # noqa: E402


_COMMAND_TO_SCRIPT = {
    "checkpoint": "remem_checkpoint.py",
    "rollup": "remem_rollup.py",
    "recall": "remem_recall.py",
    "codex": "remem_codex_wrapper.py",
}
_ALIAS_TO_COMMAND = {
    "remem-dev-sessions-codex": "codex",
    "remem-codex": "codex",
    "remem-memory-codex": "codex",
    "remem-dev-sessions-checkpoint": "checkpoint",
    "remem-memory-checkpoint": "checkpoint",
    "remem-session-memory-checkpoint": "checkpoint",
    "remem-dev-sessions-rollup": "rollup",
    "remem-memory-rollup": "rollup",
    "remem-session-memory-rollup": "rollup",
    "remem-dev-sessions-recall": "recall",
    "remem-memory-recall": "recall",
    "remem-session-memory-recall": "recall",
}
_DEFAULT_SETTINGS = {
    "mode": "auto",
    "sensitivity": "balanced",
}
_DEFAULT_API_URL = "https://api.remem.io"
_CREDENTIAL_FD_ENV = "REMEM_API_KEY_FD"
_RUNTIME_ENV_FD = "REMEM_MEMORY_RUNTIME_ENV_FD"
_MAX_PIPE_PAYLOAD_BYTES = 8 * 1024
_HELPER_ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
    "CODEX_HOME",
    "NO_COLOR",
)
_VALID_MODES = {"auto", "recall-only", "off"}
_VALID_SENSITIVITIES = {
    "conservative",
    "balanced",
    "aggressive",
}
_DEFAULT_DATA_DIR = ".config/remem-memory"


def resolve_command(command: str) -> Path:
    """Resolve a supported workflow to its repository helper script."""

    try:
        script_name = _COMMAND_TO_SCRIPT[command]
    except (KeyError, TypeError):
        raise ValueError("unsupported Remem Memory command") from None
    return _SCRIPT_PATH.with_name(script_name)


def infer_alias_command(program: str) -> Optional[str]:
    """Map a recognized installed alias basename to one workflow."""

    return _ALIAS_TO_COMMAND.get(Path(program).name)


def _python_executable() -> str:
    """Use the already-running interpreter; manual helpers are stdlib-only."""

    return sys.executable


def _is_process_injection_variable(name: str) -> bool:
    return (
        name.startswith("PYTHON")
        or name.startswith("DYLD_")
        or name.startswith("LD_")
        or name == "__PYVENV_LAUNCHER__"
    )


def _workflow_needs_credential(
    command: str,
    arguments: List[str],
) -> bool:
    if "--dry-run" in arguments:
        return False
    if command in {"checkpoint", "rollup"}:
        return "--ingest" in arguments
    if command == "codex":
        return "--no-ingest" not in arguments
    return command == "recall"


def _forwarded_option(
    arguments: List[str],
    name: str,
) -> Optional[str]:
    prefix = f"{name}="
    for index, argument in enumerate(arguments):
        if argument.startswith(prefix):
            return argument[len(prefix) :]
        if argument == name and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def _write_anonymous_payload(payload: bytes) -> int:
    if not payload or len(payload) > _MAX_PIPE_PAYLOAD_BYTES:
        raise ValueError("invalid anonymous payload size")
    read_descriptor, write_descriptor = os.pipe()
    try:
        view = memoryview(payload)
        while view:
            written = os.write(write_descriptor, view)
            if written <= 0:
                raise OSError("anonymous payload write failed")
            view = view[written:]
    except Exception:
        os.close(read_descriptor)
        raise
    finally:
        os.close(write_descriptor)
    return read_descriptor


def run_command(command: str, forwarded_args: List[str]) -> int:
    """Run one compatibility workflow through the current interpreter."""

    try:
        script_path = resolve_command(command)
    except ValueError:
        print("error: unsupported Remem Memory command", file=sys.stderr)
        return 2
    if any(
        argument.split("=", 1)[0].startswith("--api-k")
        for argument in forwarded_args
    ):
        print(
            (
                "error: --api-key is not supported; "
                "use remem-memory auth"
            ),
            file=sys.stderr,
        )
        return 2
    if not script_path.is_file():
        print("error: Remem Memory helper is unavailable", file=sys.stderr)
        return 2
    parent_environment = dict(os.environ)
    needs_credential = _workflow_needs_credential(
        command,
        forwarded_args,
    )
    configured_api_url = (
        _forwarded_option(forwarded_args, "--api-url")
        or parent_environment.get("REMEM_API_URL", "")
        or _DEFAULT_API_URL
    )
    if needs_credential:
        try:
            configured_api_url = (
                remem_api.normalize_api_origin_for_environment(
                    configured_api_url,
                    parent_environment,
                )
            )
        except Exception:
            print("error: invalid Remem API URL", file=sys.stderr)
            return 2
    sanitized_environment = {
        name: value
        for name, value in parent_environment.items()
        if not _is_process_injection_variable(name)
    }
    sanitized_environment.pop("REMEM_API_KEY", None)
    sanitized_environment.pop(_CREDENTIAL_FD_ENV, None)
    sanitized_environment.pop(_RUNTIME_ENV_FD, None)
    if command == "codex":
        child_environment = sanitized_environment
    else:
        child_environment = {
            name: sanitized_environment[name]
            for name in _HELPER_ENVIRONMENT_KEYS
            if name in sanitized_environment
        }
        child_environment.update(
            {
                name: value
                for name, value in sanitized_environment.items()
                if name.startswith("REMEM_")
            }
        )
    child_environment["REMEM_API_URL"] = configured_api_url
    inherited_descriptors: List[int] = []
    explicit_key = parent_environment.get("REMEM_API_KEY", "")
    if (
        needs_credential
        and isinstance(explicit_key, str)
        and explicit_key.strip()
    ):
        try:
            descriptor = _write_anonymous_payload(
                explicit_key.strip().encode("utf-8")
            )
        except Exception:
            print(
                "error: Remem Memory helper could not start",
                file=sys.stderr,
            )
            return 2
        child_environment[_CREDENTIAL_FD_ENV] = str(descriptor)
        inherited_descriptors.append(descriptor)

    if command == "codex":
        runtime_values = {
            name: value
            for name, value in parent_environment.items()
            if _is_process_injection_variable(name)
        }
        if runtime_values:
            try:
                descriptor = _write_anonymous_payload(
                    json.dumps(
                        runtime_values,
                        ensure_ascii=True,
                    ).encode("utf-8")
                )
            except Exception:
                for inherited in inherited_descriptors:
                    os.close(inherited)
                print(
                    "error: Remem Memory helper could not start",
                    file=sys.stderr,
                )
                return 2
            child_environment[_RUNTIME_ENV_FD] = str(descriptor)
            inherited_descriptors.append(descriptor)
    try:
        invocation = [
            _python_executable(),
            "-I",
            str(script_path),
            *forwarded_args,
        ]
        run_options = {
            "env": child_environment,
            "check": False,
        }
        if inherited_descriptors:
            run_options["pass_fds"] = tuple(inherited_descriptors)
        result = subprocess.run(invocation, **run_options)
    except Exception:
        print("error: Remem Memory helper could not start", file=sys.stderr)
        return 2
    finally:
        for descriptor in inherited_descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return int(result.returncode)


def default_data_dir(
    environment: Optional[Mapping[str, str]] = None,
) -> Path:
    selected = os.environ if environment is None else environment
    configured = selected.get("REMEM_MEMORY_DATA_DIR", "")
    if isinstance(configured, str) and configured.strip():
        return Path(configured.strip()).expanduser()
    return Path.home() / _DEFAULT_DATA_DIR


def load_settings(data_dir: Optional[Path] = None) -> Dict[str, str]:
    """Load only the two bounded user controls with safe defaults."""

    path = (data_dir or default_data_dir()) / "settings.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(_DEFAULT_SETTINGS)
    if not isinstance(parsed, dict):
        return dict(_DEFAULT_SETTINGS)
    mode = parsed.get("mode")
    sensitivity = parsed.get("sensitivity")
    return {
        "mode": mode if mode in _VALID_MODES else "auto",
        "sensitivity": (
            sensitivity
            if sensitivity in _VALID_SENSITIVITIES
            else "balanced"
        ),
    }


def _store_settings(settings: Mapping[str, str]) -> None:
    """Atomically persist a private, bounded settings object."""

    bounded = {
        "mode": (
            settings.get("mode")
            if settings.get("mode") in _VALID_MODES
            else "auto"
        ),
        "sensitivity": (
            settings.get("sensitivity")
            if settings.get("sensitivity") in _VALID_SENSITIVITIES
            else "balanced"
        ),
    }
    data_dir = default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(data_dir, 0o700)
    destination = data_dir / "settings.json"
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".settings.",
            suffix=".tmp",
            dir=str(data_dir),
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(
                bounded,
                stream,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = ""
        os.chmod(destination, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                Path(temporary).unlink()
            except OSError:
                pass


def _set_setting(name: str, value: str) -> int:
    settings = load_settings()
    settings[name] = value
    try:
        _store_settings(settings)
    except Exception:
        print("error: unable to store Remem Memory settings", file=sys.stderr)
        return 2
    print(f"{name}: {value}")
    return 0


def _authenticate() -> int:
    try:
        value = getpass.getpass("Remem API key: ")
    except Exception:
        print("error: unable to read Remem credential", file=sys.stderr)
        return 2
    if not isinstance(value, str) or not value.strip():
        print("error: Remem credential cannot be empty", file=sys.stderr)
        return 2
    try:
        remem_api.store_api_key(value)
    except Exception:
        print("error: unable to store Remem credential", file=sys.stderr)
        return 2
    print("credential: configured")
    return 0


def _status() -> int:
    settings = load_settings()
    try:
        credential = remem_api.resolve_api_key()
    except Exception:
        credential = None
    print(f"mode: {settings['mode']}")
    print(f"sensitivity: {settings['sensitivity']}")
    print(
        "credential: configured"
        if credential
        else "credential: missing"
    )
    if shutil.which("uv"):
        print("uv: available")
    else:
        print("uv: missing (required for MCP)")
    return 0


def _usage(program: str) -> str:
    return (
        f"usage: {program} "
        "{checkpoint|rollup|recall|codex|mode|sensitivity|auth|status}"
    )


def _strip_separator(arguments: List[str]) -> List[str]:
    if arguments and arguments[0] == "--":
        return arguments[1:]
    return arguments


def main(
    argv: Optional[List[str]] = None,
    *,
    program: Optional[str] = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    basename = Path(program or sys.argv[0]).name
    alias_command = infer_alias_command(basename)
    if alias_command is not None:
        return run_command(
            alias_command,
            _strip_separator(arguments),
        )

    if not arguments:
        print(_usage(basename), file=sys.stderr)
        return 2
    if arguments[0] in {"-h", "--help"}:
        print(_usage(basename))
        return 0

    command = arguments.pop(0)
    if command in _COMMAND_TO_SCRIPT:
        return run_command(command, _strip_separator(arguments))
    if command == "mode":
        if len(arguments) != 1 or arguments[0] not in _VALID_MODES:
            print(
                "error: mode must be auto, recall-only, or off",
                file=sys.stderr,
            )
            return 2
        return _set_setting("mode", arguments[0])
    if command == "sensitivity":
        if (
            len(arguments) != 1
            or arguments[0] not in _VALID_SENSITIVITIES
        ):
            print(
                (
                    "error: sensitivity must be conservative, "
                    "balanced, or aggressive"
                ),
                file=sys.stderr,
            )
            return 2
        return _set_setting("sensitivity", arguments[0])
    if command == "auth" and not arguments:
        return _authenticate()
    if command == "status" and not arguments:
        return _status()

    print(_usage(basename), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
