#!/usr/bin/env python3
"""Launch the audited bundled Remem MCP with a transient credential."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Dict, List, Optional
from urllib import parse as urllib_parse

import remem_api
import remem_routing


_DEFAULT_API_URL = "https://api.remem.io"
_PROBE_CREDENTIAL = "remem-mcp-runtime-probe"
_PROBE_CODE = (
    "import os,sys;sys.path.insert(0,sys.argv[1]);"
    "import remem_mcp.server as server;"
    "ok=server._get_api_key()=='remem-mcp-runtime-probe' "
    "and 'REMEM_API_KEY_FD' not in os.environ "
    "and 'REMEM_API_KEY' not in os.environ;"
    "raise SystemExit(0 if ok else 9)"
)
_SERVER_CODE = (
    "import sys;sys.path.insert(0,sys.argv[1]);"
    "from remem_mcp.server import main;main()"
)
_MAX_CREDENTIAL_BYTES = 8192
_BUNDLE_HASHES = {
    "PROVENANCE.json": "1de3bda3f66bf41046177f1043102f7444f896c44902bda752c626102cb429a0",
    "pyproject.toml": "35d557173f5c2659517ab902e432f60f2068924751c859cf7e2a2c743b767ae7",
    "remem_mcp/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "remem_mcp/server.py": "19645b5b7e1e214476c7e2de5fc902c488fb06b8ba35c98fe2d0f037c5bdc695",
    "uv.lock": "2932996e6841f0430290443549a4073083a202fe676dd5d372074a0178a7ee24",
}
_CHILD_ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "REMEM_API_URL",
)


class _LauncherError(RuntimeError):
    pass


def _parse_arguments(argv: Sequence[str]) -> tuple[str, bool]:
    client: Optional[str] = None
    probe = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--probe" and not probe:
            probe = True
            index += 1
            continue
        if argument == "--client" and client is None and index + 1 < len(argv):
            candidate = argv[index + 1]
            if candidate in {"codex", "claude"}:
                client = candidate
                index += 2
                continue
        raise _LauncherError("error: invalid Remem MCP client")
    if client is None:
        raise _LauncherError("error: invalid Remem MCP client")
    return client, probe


def _is_generated_python_cache(root: Path, path: Path) -> bool:
    """Ignore only regular bytecode generated beneath one __pycache__."""

    relative = path.relative_to(root)
    parts = relative.parts
    if "__pycache__" not in parts or path.is_symlink():
        return False
    cache_index = parts.index("__pycache__")
    if cache_index != len(parts) - 2:
        return (
            cache_index == len(parts) - 1
            and path.is_dir()
        )
    return path.is_file() and path.suffix in {".pyc", ".pyo"}


def _default_bundle_root() -> Path:
    return Path(__file__).resolve().parents[1] / "mcp"


def _validate_bundle(bundle_root: Path) -> tuple[Path, str]:
    try:
        root = bundle_root.resolve(strict=True)
        observed = {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if not _is_generated_python_cache(root, path)
        }
        expected = set(_BUNDLE_HASHES) | {"remem_mcp"}
        if observed != expected:
            raise _LauncherError
        for relative, expected_digest in _BUNDLE_HASHES.items():
            path = root
            for component in Path(relative).parts:
                path = path / component
                if path.is_symlink():
                    raise _LauncherError
            if not path.is_file():
                raise _LauncherError
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected_digest:
                raise _LauncherError
    except Exception:
        raise _LauncherError(
            "error: bundled Remem MCP failed integrity validation"
        ) from None
    manifest = "\n".join(
        f"{relative}:{digest}"
        for relative, digest in sorted(_BUNDLE_HASHES.items())
    ).encode("ascii")
    return root, hashlib.sha256(manifest).hexdigest()


def _find_uv(
    environment: Mapping[str, str],
    which: Optional[Callable[[str], Optional[str]]],
) -> str:
    try:
        uv = (
            shutil.which("uv", path=environment.get("PATH"))
            if which is None
            else which("uv")
        )
    except Exception:
        uv = None
    if uv:
        if which is not None:
            return uv
        try:
            path = Path(uv)
            if path.is_absolute():
                path = path.resolve(strict=True)
                if path.is_file() and os.access(path, os.X_OK):
                    return str(path)
        except (OSError, RuntimeError):
            pass
    for candidate in _uv_fallback_paths(environment):
        try:
            path = Path(candidate).resolve(strict=True)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except (OSError, RuntimeError):
            continue
    raise _LauncherError(
        "error: uv is required for the Remem MCP server"
    )


def _uv_fallback_paths(environment: Mapping[str, str]) -> tuple[str, ...]:
    """Return conventional uv locations omitted by desktop app PATHs."""

    executable = "uv.exe" if os.name == "nt" else "uv"
    candidates: List[str] = []
    home = environment.get("HOME")
    if isinstance(home, str) and home.strip():
        base = Path(home)
        if base.is_absolute():
            candidates.extend(
                (
                    str(base / ".local" / "bin" / executable),
                    str(base / ".cargo" / "bin" / executable),
                )
            )
    candidates.extend(
        (
            str(Path("/opt/homebrew/bin") / executable),
            str(Path("/usr/local/bin") / executable),
        )
    )
    return tuple(candidates)


def _cache_environment(
    environment: Mapping[str, str],
    content_digest: str,
) -> str:
    home = environment.get("HOME")
    if not isinstance(home, str) or not home.strip():
        home = str(Path.home())
    cache = (
        Path(home).expanduser()
        / ".cache"
        / "remem-memory"
        / "mcp"
        / content_digest[:16]
    )
    try:
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        if cache.is_symlink() or not cache.is_dir():
            raise OSError
        cache.chmod(0o700)
    except OSError:
        raise _LauncherError(
            "error: unable to prepare the Remem MCP runtime cache"
        ) from None
    return str(cache / "environment")


def _uv_sync_arguments(uv: str, bundle: Path) -> List[str]:
    return [
        uv,
        "sync",
        "--no-config",
        "--project",
        str(bundle),
        "--locked",
        "--no-editable",
        "--no-install-project",
        "-q",
    ]


def _runtime_python(cache_environment: str) -> Path:
    relative = (
        Path("Scripts") / "python.exe"
        if os.name == "nt"
        else Path("bin") / "python"
    )
    return Path(cache_environment) / relative


def _python_arguments(
    python: Path,
    bundle: Path,
    code: str,
) -> List[str]:
    return [
        str(python),
        "-I",
        "-c",
        code,
        str(bundle),
    ]


def _child_environment(
    selected: Mapping[str, str],
    cache_environment: str,
) -> Dict[str, str]:
    child = {
        name: selected[name]
        for name in _CHILD_ENVIRONMENT_KEYS
        if name in selected and isinstance(selected[name], str)
    }
    child["UV_PROJECT_ENVIRONMENT"] = cache_environment
    child["PYTHONDONTWRITEBYTECODE"] = "1"
    return child


def _credential_descriptor(credential: str) -> int:
    try:
        encoded = credential.encode("utf-8")
    except Exception:
        raise _LauncherError from None
    if not encoded or len(encoded) > _MAX_CREDENTIAL_BYTES:
        raise _LauncherError

    read_descriptor, write_descriptor = os.pipe()
    try:
        os.set_inheritable(read_descriptor, True)
        offset = 0
        while offset < len(encoded):
            written = os.write(
                write_descriptor,
                encoded[offset:],
            )
            if written <= 0:
                raise OSError
            offset += written
    except Exception:
        os.close(read_descriptor)
        raise _LauncherError from None
    finally:
        os.close(write_descriptor)
    return read_descriptor


def _normalize_api_url(
    value: str,
    environment: Mapping[str, str],
) -> str:
    normalized = remem_api.normalize_api_origin_for_environment(
        value,
        environment,
    )
    hostname = urllib_parse.urlsplit(normalized).hostname
    if (
        normalized != _DEFAULT_API_URL
        and hostname not in {"localhost", "127.0.0.1", "::1"}
    ):
        raise _LauncherError
    return normalized


def _run_probe(
    uv: str,
    bundle: Path,
    environment: Dict[str, str],
    *,
    runner: Callable[..., object],
) -> int:
    descriptor: Optional[int] = None
    try:
        prepared = runner(
            _uv_sync_arguments(uv, bundle),
            cwd=str(bundle),
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            pass_fds=(),
        )
        if int(getattr(prepared, "returncode", 1)) != 0:
            raise _LauncherError

        cache_environment = environment["UV_PROJECT_ENVIRONMENT"]
        if Path(cache_environment).is_symlink():
            raise _LauncherError
        python = _runtime_python(cache_environment)
        if not python.is_file() or not os.access(python, os.X_OK):
            raise _LauncherError

        descriptor = _credential_descriptor(_PROBE_CREDENTIAL)
        probe_environment = dict(environment)
        probe_environment.pop("UV_PROJECT_ENVIRONMENT", None)
        probe_environment["REMEM_API_KEY_FD"] = str(descriptor)
        completed = runner(
            _python_arguments(
                python,
                bundle,
                _PROBE_CODE,
            ),
            cwd=str(bundle),
            env=probe_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            pass_fds=(descriptor,),
        )
        if int(getattr(completed, "returncode", 1)) != 0:
            raise _LauncherError
    except Exception:
        print(
            "error: bundled Remem MCP runtime probe failed",
            file=sys.stderr,
        )
        return 2
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return 0


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    resolver: Optional[Callable[..., Optional[str]]] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
    execvpe: Callable[[str, List[str], Dict[str, str]], object] = os.execvpe,
    runner: Callable[..., object] = subprocess.run,
    bundle_root: Optional[Path] = None,
) -> int:
    selected = dict(os.environ if environment is None else environment)
    try:
        client, probe = _parse_arguments(list(argv or ()))
        bundle, content_digest = _validate_bundle(
            bundle_root or _default_bundle_root()
        )
        uv = _find_uv(selected, which)
        cache = _cache_environment(selected, content_digest)
    except _LauncherError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    child = _child_environment(selected, cache)
    if probe:
        return _run_probe(uv, bundle, child, runner=runner)

    if _run_probe(uv, bundle, child, runner=runner) != 0:
        return 2
    entrypoint = _runtime_python(cache)
    if (
        not entrypoint.is_file()
        or not os.access(entrypoint, os.X_OK)
    ):
        print(
            "error: bundled Remem MCP runtime probe failed",
            file=sys.stderr,
        )
        return 2
    child.pop("UV_PROJECT_ENVIRONMENT", None)

    try:
        child["REMEM_API_URL"] = _normalize_api_url(
            selected.get("REMEM_API_URL", _DEFAULT_API_URL),
            selected,
        )
    except Exception:
        print("error: invalid Remem API URL", file=sys.stderr)
        return 2

    hostname = urllib_parse.urlsplit(
        child["REMEM_API_URL"]
    ).hostname
    try:
        data_dir = selected.get("REMEM_MEMORY_DATA_DIR")
        config = remem_routing.load_or_initialize_routing(
            Path(data_dir).expanduser()
            if isinstance(data_dir, str) and data_dir.strip()
            else None,
            selected,
            credential_loader=lambda: remem_api.default_keychain().read(
                remem_api.KEYCHAIN_SERVICE,
                remem_api.KEYCHAIN_ACCOUNT,
            ),
        )
        connection = remem_routing.resolve_mcp_connection(
            config,
            client=client,
        )
    except Exception:
        connection = None

    if hostname in {"localhost", "127.0.0.1", "::1"}:
        if connection is not None and connection.id == "primary":
            candidate = selected.get("REMEM_API_KEY")
            credential = (
                candidate.strip()
                if isinstance(candidate, str) and candidate.strip()
                else None
            )
        else:
            credential = None
    else:
        selected_resolver = resolver or remem_api.resolve_connection_api_key
        try:
            credential = (
                selected_resolver(
                    connection=connection,
                    environment=selected,
                )
                if connection is not None
                else None
            )
        except Exception:
            credential = None
    if not credential:
        print("error: Remem credential is not configured", file=sys.stderr)
        return 2
    descriptor: Optional[int] = None
    try:
        descriptor = _credential_descriptor(credential)
        child["REMEM_API_KEY_FD"] = str(descriptor)
        execvpe(
            str(entrypoint),
            _python_arguments(
                entrypoint,
                bundle,
                _SERVER_CODE,
            ),
            child,
        )
    except _LauncherError:
        print("error: Remem credential is not configured", file=sys.stderr)
        return 2
    except OSError:
        print(
            "error: unable to start the Remem MCP server",
            file=sys.stderr,
        )
        return 2
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
