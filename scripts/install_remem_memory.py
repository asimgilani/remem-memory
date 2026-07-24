#!/usr/bin/env python3
"""Secure, idempotent Remem Memory setup for Codex and Claude Code."""

from __future__ import annotations

import hmac
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence


_DEFAULT_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN_SCRIPTS = (
    _DEFAULT_REPOSITORY_ROOT / "plugins" / "remem-memory" / "scripts"
)
_INSERTED_PLUGIN_PATH = str(_PLUGIN_SCRIPTS) not in sys.path
if _INSERTED_PLUGIN_PATH:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))
try:
    import remem_api as _remem_api
finally:
    if _INSERTED_PLUGIN_PATH:
        sys.path.remove(str(_PLUGIN_SCRIPTS))


KEYCHAIN_SERVICE = _remem_api.KEYCHAIN_SERVICE
KEYCHAIN_ACCOUNT = _remem_api.KEYCHAIN_ACCOUNT
PLUGIN_NAME = "remem-memory"
PLUGIN_ID = "remem-memory@remem-memory"
PLUGIN_VERSION = "0.3.0"
LEGACY_PLUGIN_NAME = "remem-dev-sessions"
LEGACY_PLUGIN_ID = "remem-dev-sessions@remem-dev-sessions"
CANONICAL_REPOSITORY = "asimgilani/remem-memory"
CANONICAL_REPOSITORY_URL = (
    f"https://github.com/{CANONICAL_REPOSITORY}"
)

COMMAND_ALIASES = (
    "remem-memory",
    "remem-dev-sessions",
    "remem-session-memory",
    "remem-dev-sessions-codex",
    "remem-codex",
    "remem-memory-codex",
    "remem-dev-sessions-checkpoint",
    "remem-memory-checkpoint",
    "remem-session-memory-checkpoint",
    "remem-dev-sessions-rollup",
    "remem-memory-rollup",
    "remem-session-memory-rollup",
    "remem-dev-sessions-recall",
    "remem-memory-recall",
    "remem-session-memory-recall",
)
SKILL_ALIASES = (
    "remem-memory",
    "remem-dev-sessions",
    "remem-session-memory",
)

_LEGACY_ENV_TABLE = "mcp_servers.remem.env"
_LEGACY_SERVER_TABLE = "mcp_servers.remem"
_LEGACY_KEY = "REMEM_API_KEY"
_MCP_BOOTSTRAP = (
    "import os,runpy,sys;root=sys.argv[1];"
    "root=os.getcwd() if root.startswith('$') else root;"
    "scripts=os.path.join(root,'scripts');"
    "launcher=os.path.join(scripts,'remem_mcp_launcher.py');"
    "sys.path.insert(0,scripts);"
    "sys.argv=[launcher,*sys.argv[2:]];"
    "runpy.run_path(launcher,run_name='__main__')"
)
_CHILD_ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "USER",
    "LOGNAME",
    "SHELL",
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
)
_ESCAPES = {
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
}


class InstallerError(RuntimeError):
    """A fixed, non-secret setup error safe to show to users."""


class LegacyCredentialError(ValueError):
    """The old Codex credential is outside the accepted narrow grammar."""


@dataclass(frozen=True)
class _LegacyConfig:
    api_key: Optional[str]
    has_remem_mcp: bool


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str


Runner = Callable[..., Any]


def _decode_basic_string(value: str) -> tuple[str, str]:
    if not value.startswith('"'):
        raise LegacyCredentialError("unsupported legacy credential")
    decoded: list[str] = []
    index = 1
    while index < len(value):
        character = value[index]
        if character == '"':
            return "".join(decoded), value[index + 1 :]
        if character in {"\n", "\r"} or ord(character) < 0x20:
            raise LegacyCredentialError("unsupported legacy credential")
        if character != "\\":
            decoded.append(character)
            index += 1
            continue

        index += 1
        if index >= len(value):
            raise LegacyCredentialError("unsupported legacy credential")
        escaped = value[index]
        if escaped in _ESCAPES:
            decoded.append(_ESCAPES[escaped])
            index += 1
            continue
        if escaped not in {"u", "U"}:
            raise LegacyCredentialError("unsupported legacy credential")
        width = 4 if escaped == "u" else 8
        digits = value[index + 1 : index + 1 + width]
        if len(digits) != width or any(
            character not in "0123456789abcdefABCDEF" for character in digits
        ):
            raise LegacyCredentialError("unsupported legacy credential")
        codepoint = int(digits, 16)
        if (
            codepoint > 0x10FFFF
            or 0xD800 <= codepoint <= 0xDFFF
        ):
            raise LegacyCredentialError("unsupported legacy credential")
        decoded.append(chr(codepoint))
        index += width + 1
    raise LegacyCredentialError("unsupported legacy credential")


def _parse_key_assignment(line: str) -> str:
    if not line.startswith(_LEGACY_KEY):
        raise LegacyCredentialError("unsupported legacy credential")
    remainder = line[len(_LEGACY_KEY) :]
    if not remainder or remainder[0] not in {" ", "\t", "="}:
        raise LegacyCredentialError("unsupported legacy credential")
    remainder = remainder.lstrip(" \t")
    if not remainder.startswith("="):
        raise LegacyCredentialError("unsupported legacy credential")
    encoded = remainder[1:].lstrip(" \t")
    decoded, trailing = _decode_basic_string(encoded)
    trailing = trailing.strip(" \t")
    if trailing and not trailing.startswith("#"):
        raise LegacyCredentialError("unsupported legacy credential")
    if not decoded or "\x00" in decoded:
        raise LegacyCredentialError("unsupported legacy credential")
    return decoded


def _parse_legacy_config(text: str) -> _LegacyConfig:
    if not isinstance(text, str):
        raise LegacyCredentialError("unsupported legacy credential")

    current_table: Optional[str] = None
    exact_table_count = 0
    api_key: Optional[str] = None
    has_remem_mcp = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("["):
            header = stripped
            if "#" in header:
                header = header.split("#", 1)[0].rstrip()
            if (
                not header.startswith("[")
                or not header.endswith("]")
                or header.startswith("[[")
                or header.endswith("]]")
            ):
                current_table = None
                continue
            current_table = header[1:-1]
            if current_table == _LEGACY_ENV_TABLE:
                exact_table_count += 1
                has_remem_mcp = True
                if exact_table_count > 1:
                    raise LegacyCredentialError(
                        "unsupported legacy credential"
                    )
            elif current_table == _LEGACY_SERVER_TABLE:
                has_remem_mcp = True
            continue

        candidate = stripped.split("#", 1)[0].rstrip()
        if "=" not in candidate:
            continue
        assignment_key = candidate.split("=", 1)[0].strip()
        if _LEGACY_KEY.lower() not in assignment_key.lower():
            continue
        if current_table != _LEGACY_ENV_TABLE or api_key is not None:
            raise LegacyCredentialError("unsupported legacy credential")
        api_key = _parse_key_assignment(stripped)

    return _LegacyConfig(
        api_key=api_key,
        has_remem_mcp=has_remem_mcp,
    )


def parse_legacy_api_key(text: str) -> Optional[str]:
    """Parse only one exact TOML basic string from the old Remem env table."""

    return _parse_legacy_config(text).api_key


def _expand_home_path(value: str, home: Path) -> Path:
    if value == "~":
        return home
    if value.startswith("~/"):
        return home / value[2:]
    return Path(value)


def _constant_time_equal(left: Any, right: str) -> bool:
    if not isinstance(left, str):
        return False
    try:
        return hmac.compare_digest(
            left.encode("utf-8"),
            right.encode("utf-8"),
        )
    except UnicodeError:
        return False


def _json_records(payload: Any, collection: str) -> list[dict[str, Any]]:
    selected = payload
    if isinstance(payload, dict):
        if collection in payload:
            selected = payload[collection]
        elif collection == "plugins" and "installed" in payload:
            selected = payload["installed"]
        else:
            selected = []
    if isinstance(selected, dict):
        selected = list(selected.values())
    if not isinstance(selected, list):
        raise InstallerError("plugin state could not be verified")
    return [item for item in selected if isinstance(item, dict)]


def _record_name(record: Mapping[str, Any]) -> str:
    for field in ("name", "id", "plugin", "identity"):
        value = record.get(field)
        if isinstance(value, str):
            return value
    return ""


def _record_marketplace(record: Mapping[str, Any]) -> str:
    for field in ("marketplace", "marketplaceName", "marketplace_name"):
        value = record.get(field)
        if isinstance(value, str):
            return value
    return ""


def _find_record(
    records: Sequence[Mapping[str, Any]],
    name: str,
    *,
    marketplace: Optional[str] = None,
) -> Optional[Mapping[str, Any]]:
    combined = f"{name}@{marketplace}" if marketplace else ""
    for record in records:
        record_name = _record_name(record)
        record_marketplace = _record_marketplace(record)
        if combined and record_name == combined:
            return record
        if record_name != name:
            continue
        if marketplace and record_marketplace not in {"", marketplace}:
            continue
        return record
    return None


def _record_version(record: Mapping[str, Any]) -> str:
    version = record.get("version")
    if isinstance(version, str):
        return version
    manifest = record.get("manifest")
    if isinstance(manifest, dict):
        nested = manifest.get("version")
        if isinstance(nested, str):
            return nested
    return ""


def _record_enabled(record: Mapping[str, Any]) -> bool:
    enabled = record.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    status_value = record.get("status")
    return (
        isinstance(status_value, str)
        and status_value.lower() == "enabled"
    )


def _marketplace_is_git(record: Mapping[str, Any]) -> bool:
    for source in (
        record.get("source"),
        record.get("marketplaceSource"),
    ):
        if isinstance(source, str):
            lowered = source.lower()
            if lowered == "git" or lowered.startswith(
                ("git+", "https://", "ssh://")
            ):
                return True
        if isinstance(source, dict):
            for field in (
                "type",
                "sourceType",
                "source_type",
                "kind",
            ):
                value = source.get(field)
                if isinstance(value, str) and value.lower() == "git":
                    return True
    return False


def _is_canonical_repository(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip().lower().rstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    return candidate in {
        CANONICAL_REPOSITORY,
        CANONICAL_REPOSITORY_URL,
        f"git@github.com:{CANONICAL_REPOSITORY}",
        f"ssh://git@github.com/{CANONICAL_REPOSITORY}",
    }


def _is_exact_local_repository(value: Any, repo_root: Path) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return False
    try:
        return candidate.resolve(strict=False) == repo_root.resolve(
            strict=False
        )
    except OSError:
        return False


def _marketplace_matches_repository(
    record: Mapping[str, Any],
    repo_root: Path,
) -> bool:
    """Accept only this checkout or the canonical public repository."""

    source = record.get("source")
    if isinstance(source, str):
        kind = source.strip().lower()
        if kind == "github":
            return _is_canonical_repository(record.get("repo"))
        if kind in {"directory", "local", "path"}:
            return any(
                _is_exact_local_repository(record.get(field), repo_root)
                for field in ("path", "root")
            )
        if _is_canonical_repository(source):
            return True

    source_records = (
        source,
        record.get("marketplaceSource"),
    )
    for source_record in source_records:
        if not isinstance(source_record, Mapping):
            continue
        kind = ""
        for field in ("type", "sourceType", "source_type", "kind"):
            value = source_record.get(field)
            if isinstance(value, str):
                kind = value.strip().lower()
                break
        source_value = source_record.get("source")
        if kind == "git":
            return _is_canonical_repository(source_value)
        if kind in {"directory", "local", "path"}:
            candidates = (
                source_value,
                source_record.get("path"),
                source_record.get("root"),
                record.get("path"),
                record.get("root"),
            )
            return any(
                _is_exact_local_repository(value, repo_root)
                for value in candidates
            )

    if _is_canonical_repository(record.get("repo")):
        return True
    return False


class Installer:
    """Injectable setup implementation with no ambient-state writes in tests."""

    def __init__(
        self,
        *,
        home: Optional[Path] = None,
        environment: Optional[Mapping[str, str]] = None,
        runner: Optional[Runner] = None,
        keychain: Optional[Any] = None,
        repo_root: Optional[Path] = None,
    ) -> None:
        selected_environment = (
            dict(os.environ)
            if environment is None
            else dict(environment)
        )
        configured_home = selected_environment.get("HOME")
        if home is not None:
            selected_home = Path(home)
        elif isinstance(configured_home, str) and configured_home:
            selected_home = Path(configured_home)
        else:
            selected_home = Path.home()

        self.home = selected_home
        self.repo_root = Path(
            repo_root
            if repo_root is not None
            else _DEFAULT_REPOSITORY_ROOT
        )
        self.runner = runner or subprocess.run
        self.keychain = keychain
        self.environment = selected_environment
        codex_setting = selected_environment.get(
            "CODEX_HOME",
            str(self.home / ".codex"),
        )
        claude_setting = selected_environment.get(
            "CLAUDE_CONFIG_DIR",
            str(self.home / ".claude"),
        )
        self.codex_home = _expand_home_path(
            str(codex_setting),
            self.home,
        )
        self.claude_config = _expand_home_path(
            str(claude_setting),
            self.home,
        )
        self.child_environment = {
            name: selected_environment[name]
            for name in _CHILD_ENVIRONMENT_KEYS
            if (
                name in selected_environment
                and isinstance(selected_environment[name], str)
            )
        }
        self.child_environment["HOME"] = str(self.home)
        self.child_environment["CODEX_HOME"] = str(self.codex_home)
        self.child_environment["CLAUDE_CONFIG_DIR"] = str(
            self.claude_config
        )
        local_bin = str(self.home / ".local" / "bin")
        existing_path = self.child_environment.get("PATH", "")
        path_entries = [
            entry
            for entry in (
                existing_path.split(os.pathsep)
                if existing_path
                else []
            )
            if entry != local_bin
        ]
        path_entries.insert(0, local_bin)
        self.child_environment["PATH"] = os.pathsep.join(path_entries)

    def run(self) -> None:
        self._preflight()
        self._validate_repository()
        codex_available = self._tool_available("codex")
        claude_available = self._tool_available("claude")
        if codex_available:
            self._validate_harness_root(self.codex_home)
        if claude_available:
            self._validate_harness_root(self.claude_config)

        legacy_config = self._load_legacy_config()
        if legacy_config.api_key is not None:
            self._bridge_legacy_credential(legacy_config.api_key)

        if codex_available:
            self._prepare_harness_root(self.codex_home)
        if claude_available:
            self._prepare_harness_root(self.claude_config)
        self._install_aliases()

        if codex_available or claude_available:
            self._probe_mcp_runtime()

        codex_ready = False
        if codex_available:
            self._setup_codex()
            codex_ready = True
        claude_cleanup = (False, False)
        if claude_available:
            claude_cleanup = self._setup_claude()

        if legacy_config.has_remem_mcp and codex_ready:
            self._run_required(
                ("codex", "mcp", "remove", "remem"),
                "Codex legacy MCP cleanup failed",
            )

        if claude_available:
            self._cleanup_claude_legacy(*claude_cleanup)

    def _preflight(self) -> None:
        for tool in ("uv",):
            self._run_required(
                (tool, "--version"),
                f"required command unavailable: {tool}",
            )

    def _validate_repository(self) -> None:
        required = (
            self.repo_root / "scripts" / "remem_memory.py",
            *(
                self.repo_root
                / "codex"
                / "skills"
                / name
                / "SKILL.md"
                for name in SKILL_ALIASES
            ),
        )
        if not all(path.is_file() for path in required):
            raise InstallerError("Remem Memory checkout is incomplete")

    def _load_legacy_config(self) -> _LegacyConfig:
        config_path = self.codex_home / "config.toml"
        try:
            text = (
                config_path.read_text(encoding="utf-8")
                if config_path.is_file()
                else ""
            )
        except OSError:
            raise InstallerError(
                "Codex legacy configuration could not be read"
            ) from None
        try:
            return _parse_legacy_config(text)
        except LegacyCredentialError:
            raise InstallerError(
                "Codex legacy credential format is not supported"
            ) from None

    def _bridge_legacy_credential(self, value: str) -> None:
        selected_keychain = (
            self.keychain
            if self.keychain is not None
            else _remem_api.default_keychain()
        )
        try:
            existing = selected_keychain.read(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT,
            )
            if existing is not None:
                if not _constant_time_equal(
                    existing,
                    value,
                ):
                    raise InstallerError(
                        "Canonical credential differs from legacy credential"
                    )
            else:
                selected_keychain.write(
                    KEYCHAIN_SERVICE,
                    KEYCHAIN_ACCOUNT,
                    value,
                )
            verified = selected_keychain.read(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT,
            )
            if not _constant_time_equal(
                verified,
                value,
            ):
                raise InstallerError(
                    "Credential migration could not be verified"
                )
        except InstallerError:
            raise
        except Exception:
            raise InstallerError(
                "Credential migration could not be verified"
            ) from None

    @staticmethod
    def _validate_harness_root(path: Path) -> None:
        try:
            if path.is_symlink() or (
                path.exists() and not path.is_dir()
            ):
                raise InstallerError(
                    "Harness configuration path is invalid"
                )
        except InstallerError:
            raise
        except OSError:
            raise InstallerError(
                "Harness configuration path is invalid"
            ) from None

    @classmethod
    def _prepare_harness_root(cls, path: Path) -> None:
        cls._validate_harness_root(path)
        try:
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise InstallerError(
                    "Harness configuration path is invalid"
                )
            path.chmod(0o700)
        except InstallerError:
            raise
        except OSError:
            raise InstallerError(
                "Harness configuration path could not be prepared"
            ) from None

    def _install_aliases(self) -> None:
        canonical_script = (
            self.repo_root / "scripts" / "remem_memory.py"
        )
        try:
            canonical_script.chmod(
                canonical_script.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )
            bin_directory = self.home / ".local" / "bin"
            skill_directory = self.home / ".agents" / "skills"
            bin_directory.mkdir(parents=True, exist_ok=True)
            skill_directory.mkdir(parents=True, exist_ok=True)
            for alias in COMMAND_ALIASES:
                self._ensure_symlink(
                    canonical_script,
                    bin_directory / alias,
                    directory=False,
                )
            for alias in SKILL_ALIASES:
                skill_source = (
                    self.repo_root
                    / "codex"
                    / "skills"
                    / alias
                )
                if not (skill_source / "SKILL.md").is_file():
                    raise InstallerError(
                        "Command and skill aliases could not be installed"
                    )
                self._ensure_symlink(
                    skill_source,
                    skill_directory / alias,
                    directory=True,
                )
        except InstallerError:
            raise
        except OSError:
            raise InstallerError(
                "Command and skill aliases could not be installed"
            ) from None

    @staticmethod
    def _ensure_symlink(
        target: Path,
        destination: Path,
        *,
        directory: bool,
    ) -> None:
        if destination.is_symlink():
            if destination.resolve(strict=False) == target.resolve(
                strict=False
            ):
                return
            destination.unlink()
        elif destination.exists():
            raise InstallerError("Installation path is already occupied")
        destination.symlink_to(target, target_is_directory=directory)

    def _setup_codex(self) -> None:
        marketplace_payload = self._run_json(
            (
                "codex",
                "plugin",
                "marketplace",
                "list",
                "--json",
            ),
            "Codex plugin state could not be verified",
        )
        marketplace_records = _json_records(
            marketplace_payload,
            "marketplaces",
        )
        marketplace = _find_record(
            marketplace_records,
            PLUGIN_NAME,
        )
        if (
            marketplace is not None
            and not _marketplace_matches_repository(
                marketplace,
                self.repo_root,
            )
        ):
            raise InstallerError(
                "Codex marketplace source does not match Remem Memory"
            )
        initial_payload = self._run_json(
            ("codex", "plugin", "list", "--json"),
            "Codex plugin state could not be verified",
        )
        initial_plugins = _json_records(initial_payload, "plugins")
        current_plugin = _find_record(
            initial_plugins,
            PLUGIN_NAME,
            marketplace=PLUGIN_NAME,
        )
        marketplace_added = marketplace is None
        marketplace_upgraded = (
            marketplace is not None
            and _marketplace_is_git(marketplace)
        )

        if marketplace is None:
            self._run_required(
                (
                    "codex",
                    "plugin",
                    "marketplace",
                    "add",
                    str(self.repo_root),
                    "--json",
                ),
                "Codex marketplace setup failed",
            )
        elif marketplace_upgraded:
            self._run_required(
                (
                    "codex",
                    "plugin",
                    "marketplace",
                    "upgrade",
                    PLUGIN_NAME,
                    "--json",
                ),
                "Codex marketplace setup failed",
            )

        if (
            marketplace_added
            or marketplace_upgraded
            or current_plugin is None
            or _record_version(current_plugin) != PLUGIN_VERSION
            or not _record_enabled(current_plugin)
        ):
            self._run_required(
                (
                    "codex",
                    "plugin",
                    "add",
                    PLUGIN_ID,
                    "--json",
                ),
                "Codex plugin setup failed",
            )
        verified_payload = self._run_json(
            ("codex", "plugin", "list", "--json"),
            "Codex plugin state could not be verified",
        )
        verified_plugins = _json_records(
            verified_payload,
            "plugins",
        )
        installed = _find_record(
            verified_plugins,
            PLUGIN_NAME,
            marketplace=PLUGIN_NAME,
        )
        if (
            installed is None
            or _record_version(installed) != PLUGIN_VERSION
            or not _record_enabled(installed)
        ):
            raise InstallerError(
                "Codex plugin state could not be verified"
            )

    def _setup_claude(self) -> tuple[bool, bool]:
        marketplace_payload = self._run_json(
            (
                "claude",
                "plugin",
                "marketplace",
                "list",
                "--json",
            ),
            "Claude plugin state could not be verified",
        )
        marketplaces = _json_records(
            marketplace_payload,
            "marketplaces",
        )
        new_marketplace = _find_record(
            marketplaces,
            PLUGIN_NAME,
        )
        if (
            new_marketplace is not None
            and not _marketplace_matches_repository(
                new_marketplace,
                self.repo_root,
            )
        ):
            raise InstallerError(
                "Claude marketplace source does not match Remem Memory"
            )
        old_marketplace = _find_record(
            marketplaces,
            LEGACY_PLUGIN_NAME,
        )
        if new_marketplace is None:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "marketplace",
                    "add",
                    str(self.repo_root),
                ),
                "Claude marketplace setup failed",
            )
        else:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "marketplace",
                    "update",
                    PLUGIN_NAME,
                ),
                "Claude marketplace setup failed",
            )

        initial_payload = self._run_json(
            ("claude", "plugin", "list", "--json"),
            "Claude plugin state could not be verified",
        )
        initial_plugins = _json_records(initial_payload, "plugins")
        old_plugin = _find_record(
            initial_plugins,
            LEGACY_PLUGIN_NAME,
            marketplace=LEGACY_PLUGIN_NAME,
        )
        new_plugin = _find_record(
            initial_plugins,
            PLUGIN_NAME,
            marketplace=PLUGIN_NAME,
        )

        if new_plugin is None:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "install",
                    PLUGIN_ID,
                ),
                "Claude plugin setup failed",
            )
        elif _record_version(new_plugin) != PLUGIN_VERSION:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "update",
                    PLUGIN_ID,
                ),
                "Claude plugin setup failed",
            )
        elif not _record_enabled(new_plugin):
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "enable",
                    PLUGIN_ID,
                ),
                "Claude plugin setup failed",
            )

        verified_plugins = self._claude_plugins()
        verified = _find_record(
            verified_plugins,
            PLUGIN_NAME,
            marketplace=PLUGIN_NAME,
        )
        if (
            verified is not None
            and _record_version(verified) == PLUGIN_VERSION
            and not _record_enabled(verified)
        ):
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "enable",
                    PLUGIN_ID,
                ),
                "Claude plugin setup failed",
            )
            verified_plugins = self._claude_plugins()
            verified = _find_record(
                verified_plugins,
                PLUGIN_NAME,
                marketplace=PLUGIN_NAME,
            )

        if (
            verified is None
            or _record_version(verified) != PLUGIN_VERSION
            or not _record_enabled(verified)
        ):
            raise InstallerError(
                "Claude plugin state could not be verified"
            )

        return old_plugin is not None, old_marketplace is not None

    def _cleanup_claude_legacy(
        self,
        remove_plugin: bool,
        remove_marketplace: bool,
    ) -> None:
        if remove_plugin:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "disable",
                    LEGACY_PLUGIN_ID,
                ),
                "Claude legacy plugin cleanup failed",
            )
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "uninstall",
                    LEGACY_PLUGIN_ID,
                    "--keep-data",
                ),
                "Claude legacy plugin cleanup failed",
            )
        if remove_marketplace:
            self._run_required(
                (
                    "claude",
                    "plugin",
                    "marketplace",
                    "remove",
                    LEGACY_PLUGIN_NAME,
                ),
                "Claude legacy marketplace cleanup failed",
            )

    def _probe_mcp_runtime(self) -> None:
        plugin_root = self.repo_root / "plugins" / "remem-memory"
        self._run_required(
            (
                sys.executable,
                "-I",
                "-c",
                _MCP_BOOTSTRAP,
                str(plugin_root),
                "--probe",
            ),
            "Remem MCP runtime verification failed",
            timeout_seconds=75,
        )

    def _claude_plugins(self) -> list[dict[str, Any]]:
        payload = self._run_json(
            ("claude", "plugin", "list", "--json"),
            "Claude plugin state could not be verified",
        )
        return _json_records(payload, "plugins")

    def _tool_available(self, command: str) -> bool:
        result = self._invoke((command, "--version"))
        return result is not None and result.returncode == 0

    def _run_required(
        self,
        command: Sequence[str],
        error_message: str,
        *,
        timeout_seconds: Optional[int] = None,
    ) -> str:
        result = self._invoke(
            command,
            timeout_seconds=timeout_seconds,
        )
        if result is None or result.returncode != 0:
            raise InstallerError(error_message)
        return result.stdout

    def _run_json(
        self,
        command: Sequence[str],
        error_message: str,
    ) -> Any:
        output = self._run_required(command, error_message)
        try:
            return json.loads(output)
        except (TypeError, ValueError):
            raise InstallerError(error_message) from None

    def _invoke(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: Optional[int] = None,
    ) -> Optional[_CommandResult]:
        try:
            runner_arguments: dict[str, Any] = {
                "cwd": str(self.repo_root),
                "env": dict(self.child_environment),
                "check": False,
                "capture_output": True,
                "text": True,
            }
            if timeout_seconds is not None:
                runner_arguments["timeout"] = timeout_seconds
            completed = self.runner(
                list(command),
                **runner_arguments,
            )
        except FileNotFoundError:
            return None
        except Exception:
            return _CommandResult(returncode=1, stdout="")
        try:
            returncode = int(completed.returncode)
        except Exception:
            returncode = 1
        stdout = (
            completed.stdout
            if isinstance(getattr(completed, "stdout", None), str)
            else ""
        )
        return _CommandResult(
            returncode=returncode,
            stdout=stdout,
        )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    home: Optional[Path] = None,
    environment: Optional[Mapping[str, str]] = None,
    runner: Optional[Runner] = None,
    keychain: Optional[Any] = None,
    repo_root: Optional[Path] = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print(
            "error: secure Remem Memory setup accepts no options",
            file=sys.stderr,
        )
        return 2
    try:
        Installer(
            home=home,
            environment=environment,
            runner=runner,
            keychain=keychain,
            repo_root=repo_root,
        ).run()
    except InstallerError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Remem Memory setup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
