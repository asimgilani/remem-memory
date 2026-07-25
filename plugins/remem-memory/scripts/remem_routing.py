"""Validated, non-secret local routing configuration for Remem Memory."""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
import tempfile
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Mapping
from types import MappingProxyType

try:
    import fcntl
except ImportError:  # pragma: no cover - this plugin runs on macOS
    fcntl = None  # type: ignore[assignment]


_SCHEMA_VERSION = 1
_MAX_CONFIG_BYTES = 65_536
_MAX_HEALTH_BYTES = 32_768
_MAX_MIGRATION_STAGE_BYTES = 4_096
_MAX_LEGACY_CONFIG_BYTES = 65_536
_MAX_CONNECTIONS = 16
_MAX_RECALL_TARGETS = 16
_MAX_HEALTH_RECORDS = 64
_CLIENTS = frozenset(("codex", "claude"))
_BEHAVIORS = frozenset(("recall", "memory", "sessions"))
_HEALTH_STATUSES = frozenset(
    (
        "ok",
        "credential_error",
        "auth_error",
        "permission_error",
        "namespace_error",
        "request_error",
        "transient_error",
    )
)
_CONNECTION_ID = re.compile(r"conn_([0-9a-f]{32})\Z")
_DETAIL_CODE = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_UTC_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z"
)
_ROUTES_FILE = "routes.json"
_HEALTH_FILE = "route-health.json"
_MIGRATION_STAGE_FILE = "routing-migration-stage.json"
_LEGACY_ENV_TABLE = "mcp_servers.remem.env"
_LEGACY_KEY = "REMEM_API_KEY"
_LEGACY_ESCAPES = {
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "f": "\f",
    "r": "\r",
    '"': '"',
    "\\": "\\",
}


@dataclass(frozen=True)
class Connection:
    id: str
    label: str
    keychain_account: str
    configured: bool


@dataclass(frozen=True)
class RouteTarget:
    connection_id: str
    namespace: str


@dataclass(frozen=True)
class RouteLayer:
    routes: Mapping[str, tuple[RouteTarget, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "routes", MappingProxyType(dict(self.routes)))


@dataclass(frozen=True)
class RoutingConfig:
    schema_version: int
    revision: int
    connections: tuple[Connection, ...]
    global_routes: RouteLayer
    client_routes: Mapping[str, RouteLayer]
    mcp_connections: Mapping[str, str]
    legacy_namespace_migration_completed: bool
    migration_write_blocked: bool
    deprecations: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "connections", tuple(self.connections))
        object.__setattr__(
            self,
            "client_routes",
            MappingProxyType(dict(self.client_routes)),
        )
        object.__setattr__(
            self,
            "mcp_connections",
            MappingProxyType(dict(self.mcp_connections)),
        )
        object.__setattr__(self, "deprecations", tuple(self.deprecations))


@dataclass(frozen=True)
class RouteHealthRecord:
    client: str
    behavior: str
    connection_id: str
    namespace: str
    status: str
    detail_code: str
    observed_at: str


@dataclass(frozen=True)
class LegacyDiscovery:
    distinct_credentials: int
    destination_candidates: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "destination_candidates",
            MappingProxyType(
                {
                    behavior: tuple(candidates)
                    for behavior, candidates in self.destination_candidates.items()
                }
            ),
        )


@dataclass(frozen=True)
class MigrationOutcome:
    initialized: bool
    distinct_credentials: int = 0
    credential_ambiguous: bool = False
    destination_ambiguous: bool = False
    deprecations: tuple[str, ...] = ()


class LegacyCredentialError(ValueError):
    """The old Codex credential is outside the accepted narrow grammar."""


def _default_data_dir() -> Path:
    configured = os.getenv("REMEM_MEMORY_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "remem-memory"


def _selected_data_dir(data_dir: Path | None) -> Path:
    return Path(data_dir) if data_dir is not None else _default_data_dir()


def _primary_connection() -> Connection:
    return Connection("primary", "Primary", "default", True)


def built_in_routes() -> Mapping[str, tuple[RouteTarget, ...]]:
    return MappingProxyType(
        {
            "recall": (RouteTarget("primary", "@readable"),),
            "memory": (RouteTarget("primary", "@default"),),
            "sessions": (RouteTarget("primary", "@default"),),
        }
    )


def _empty_config() -> RoutingConfig:
    return RoutingConfig(
        schema_version=_SCHEMA_VERSION,
        revision=0,
        connections=(_primary_connection(),),
        global_routes=RouteLayer({}),
        client_routes={},
        mcp_connections={},
        legacy_namespace_migration_completed=False,
        migration_write_blocked=False,
        deprecations=(),
    )


def _is_plain_int(value: object) -> bool:
    return type(value) is int


def _validate_client(value: object) -> str:
    if not isinstance(value, str) or value not in _CLIENTS:
        raise ValueError("Unsupported routing client")
    return value


def _validate_behavior(value: object) -> str:
    if not isinstance(value, str) or value not in _BEHAVIORS:
        raise ValueError("Unsupported routing behavior")
    return value


def _validate_connection_id(value: object) -> str:
    if value == "primary":
        return "primary"
    if not isinstance(value, str) or _CONNECTION_ID.fullmatch(value) is None:
        raise ValueError("Invalid routing connection")
    return value


def _validate_namespace(value: object, *, behavior: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 100
    ):
        raise ValueError("Invalid routing namespace")
    if value == "@readable":
        if behavior != "recall":
            raise ValueError("@readable is valid only for recall")
        return value
    if value == "@default":
        if behavior not in {"memory", "sessions"}:
            raise ValueError("@default is valid only for writes")
        return value
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("Invalid routing namespace")
    return value


def _validate_connection(connection: object, *, primary_seen: bool) -> Connection:
    if not isinstance(connection, Connection):
        raise ValueError("Invalid routing connection")
    connection_id = _validate_connection_id(connection.id)
    if not isinstance(connection.label, str) or not (
        1 <= len(connection.label) <= 64
    ) or not connection.label.isprintable():
        raise ValueError("Invalid routing connection label")
    if type(connection.configured) is not bool:
        raise ValueError("Invalid routing connection")
    if connection_id == "primary":
        if primary_seen or connection != _primary_connection():
            raise ValueError("Primary connection is immutable")
    else:
        match = _CONNECTION_ID.fullmatch(connection_id)
        assert match is not None
        if connection.keychain_account != f"connection:{match.group(1)}":
            raise ValueError("Invalid routing Keychain account")
    return connection


def _validate_layer(
    layer: object,
    *,
    connection_ids: frozenset[str],
) -> RouteLayer:
    if not isinstance(layer, RouteLayer) or not isinstance(layer.routes, Mapping):
        raise ValueError("Invalid route layer")
    routes: dict[str, tuple[RouteTarget, ...]] = {}
    for behavior, targets in layer.routes.items():
        behavior = _validate_behavior(behavior)
        if not isinstance(targets, tuple):
            raise ValueError("Invalid route targets")
        if behavior == "recall":
            if len(targets) > _MAX_RECALL_TARGETS:
                raise ValueError("Too many recall targets")
        elif len(targets) > 1:
            raise ValueError("Write routes have one target at most")
        checked_targets: list[RouteTarget] = []
        for route_target in targets:
            if not isinstance(route_target, RouteTarget):
                raise ValueError("Invalid route target")
            connection_id = _validate_connection_id(route_target.connection_id)
            if connection_id not in connection_ids:
                raise ValueError("Route references an unknown connection")
            namespace = _validate_namespace(
                route_target.namespace,
                behavior=behavior,
            )
            checked_targets.append(RouteTarget(connection_id, namespace))
        routes[behavior] = tuple(checked_targets)
    return RouteLayer(routes)


def _validate_config(config: object) -> RoutingConfig:
    if not isinstance(config, RoutingConfig):
        raise ValueError("Invalid routing configuration")
    if config.schema_version != _SCHEMA_VERSION:
        raise ValueError("Unsupported routing schema")
    if not _is_plain_int(config.revision) or config.revision < 0:
        raise ValueError("Invalid routing revision")
    if not isinstance(config.connections, tuple) or not (
        1 <= len(config.connections) <= _MAX_CONNECTIONS
    ):
        raise ValueError("Invalid routing connections")
    seen_connections: set[str] = set()
    primary_seen = False
    checked_connections: list[Connection] = []
    for connection in config.connections:
        checked = _validate_connection(connection, primary_seen=primary_seen)
        if checked.id in seen_connections:
            raise ValueError("Duplicate routing connection")
        primary_seen = primary_seen or checked.id == "primary"
        seen_connections.add(checked.id)
        checked_connections.append(checked)
    if not primary_seen:
        raise ValueError("Primary routing connection is required")
    if any(
        connection.label in seen_connections
        and connection.label != connection.id
        for connection in checked_connections
    ):
        raise ValueError("Routing connection label collides with an ID")
    connection_ids = frozenset(seen_connections)
    global_routes = _validate_layer(
        config.global_routes,
        connection_ids=connection_ids,
    )
    if not isinstance(config.client_routes, Mapping):
        raise ValueError("Invalid client routes")
    client_routes: dict[str, RouteLayer] = {}
    for client, layer in config.client_routes.items():
        client = _validate_client(client)
        client_routes[client] = _validate_layer(
            layer,
            connection_ids=connection_ids,
        )
    if not isinstance(config.mcp_connections, Mapping):
        raise ValueError("Invalid MCP routing connections")
    mcp_connections: dict[str, str] = {}
    for client, connection_id in config.mcp_connections.items():
        client = _validate_client(client)
        connection_id = _validate_connection_id(connection_id)
        if connection_id not in connection_ids:
            raise ValueError("MCP connection is not configured")
        mcp_connections[client] = connection_id
    if type(config.legacy_namespace_migration_completed) is not bool or type(
        config.migration_write_blocked
    ) is not bool:
        raise ValueError("Invalid routing migration state")
    if not isinstance(config.deprecations, tuple) or any(
        not isinstance(item, str) or not item or len(item) > 128
        for item in config.deprecations
    ):
        raise ValueError("Invalid routing deprecations")
    return RoutingConfig(
        schema_version=config.schema_version,
        revision=config.revision,
        connections=tuple(checked_connections),
        global_routes=global_routes,
        client_routes=client_routes,
        mcp_connections=mcp_connections,
        legacy_namespace_migration_completed=config.legacy_namespace_migration_completed,
        migration_write_blocked=config.migration_write_blocked,
        deprecations=config.deprecations,
    )


def parse_target(
    value: str,
    *,
    direction: Literal["read", "write"],
) -> RouteTarget:
    if direction not in {"read", "write"} or not isinstance(value, str):
        raise ValueError("Invalid route target")
    connection_id, separator, namespace = value.partition("/")
    if not separator:
        raise ValueError("Invalid route target")
    connection_id = _validate_connection_id(connection_id)
    behavior = "recall" if direction == "read" else "memory"
    return RouteTarget(
        connection_id,
        _validate_namespace(namespace, behavior=behavior),
    )


def resolve_routes(
    config: RoutingConfig,
    *,
    behavior: Literal["recall", "memory", "sessions"],
    client: Literal["codex", "claude"],
) -> tuple[RouteTarget, ...]:
    checked = _validate_config(config)
    behavior = _validate_behavior(behavior)
    client = _validate_client(client)
    if checked.migration_write_blocked and behavior in {"memory", "sessions"}:
        return ()
    client_layer = checked.client_routes.get(client)
    if client_layer is not None and behavior in client_layer.routes:
        return client_layer.routes[behavior]
    if behavior in checked.global_routes.routes:
        return checked.global_routes.routes[behavior]
    return built_in_routes()[behavior]


def resolve_mcp_connection(
    config: RoutingConfig,
    *,
    client: Literal["codex", "claude"],
) -> Connection:
    checked = _validate_config(config)
    client = _validate_client(client)
    selected_id = checked.mcp_connections.get(client, "primary")
    for connection in checked.connections:
        if connection.id == selected_id:
            return connection
    raise ValueError("MCP connection is not configured")


def use_default_routes(config: RoutingConfig) -> RoutingConfig:
    checked = _validate_config(config)
    return replace(
        checked,
        global_routes=RouteLayer({}),
        client_routes={},
        migration_write_blocked=False,
    )


def _has_explicit_global_write_routes(config: RoutingConfig) -> bool:
    return all(
        behavior in config.global_routes.routes
        for behavior in ("memory", "sessions")
    )


def _ensure_data_dir(data_dir: Path) -> None:
    try:
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    descriptor = _open_directory(data_dir)
    try:
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def _inspect_data_dir(data_dir: Path) -> None:
    try:
        metadata = data_dir.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("Routing storage has unsafe permissions")
    descriptor = _open_directory(data_dir)
    os.close(descriptor)


def _open_directory(data_dir: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(data_dir, flags)
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("Routing storage must be a directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _secure_file_path(data_dir: Path, filename: str) -> Path:
    path = data_dir / filename
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Routing storage must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("Routing storage has unsafe permissions")
    return path


def _read_bounded(data_dir: Path, filename: str, maximum: int) -> bytes:
    path = _secure_file_path(data_dir, filename)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Routing storage exceeds its size limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > maximum:
            raise ValueError("Routing storage exceeds its size limit")
        return content
    finally:
        os.close(descriptor)


def _atomic_write(data_dir: Path, filename: str, content: bytes) -> None:
    path = _secure_file_path(data_dir, filename)
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{filename}.",
            suffix=".tmp",
            dir=data_dir,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = ""
        directory_descriptor = _open_directory(data_dir)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                Path(temporary).unlink()
            except OSError:
                pass


@contextmanager
def _locked(data_dir: Path, filename: str):
    _ensure_data_dir(data_dir)
    path = _secure_file_path(data_dir, filename)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ValueError("Routing storage is unavailable") from error
    try:
        os.fchmod(descriptor, 0o600)
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _routes_to_data(layer: RouteLayer) -> dict[str, list[dict[str, str]]]:
    return {
        behavior: [
            {
                "connection_id": route_target.connection_id,
                "namespace": route_target.namespace,
            }
            for route_target in targets
        ]
        for behavior, targets in layer.routes.items()
    }


def _config_to_data(config: RoutingConfig) -> dict[str, object]:
    return {
        "schema_version": config.schema_version,
        "revision": config.revision,
        "connections": [
            {
                "id": connection.id,
                "label": connection.label,
                "keychain_account": connection.keychain_account,
                "configured": connection.configured,
            }
            for connection in config.connections
        ],
        "global_routes": _routes_to_data(config.global_routes),
        "client_routes": {
            client: _routes_to_data(layer)
            for client, layer in config.client_routes.items()
        },
        "mcp_connections": dict(config.mcp_connections),
        "legacy_namespace_migration_completed": (
            config.legacy_namespace_migration_completed
        ),
        "migration_write_blocked": config.migration_write_blocked,
        "deprecations": list(config.deprecations),
    }


def _require_exact_keys(value: object, keys: frozenset[str], *, message: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(message)
    return value


def _data_to_layer(value: object) -> RouteLayer:
    if not isinstance(value, dict):
        raise ValueError("Invalid route layer")
    routes: dict[str, tuple[RouteTarget, ...]] = {}
    for behavior, encoded_targets in value.items():
        if not isinstance(encoded_targets, list):
            raise ValueError("Invalid route targets")
        targets: list[RouteTarget] = []
        for encoded_target in encoded_targets:
            fields = _require_exact_keys(
                encoded_target,
                frozenset(("connection_id", "namespace")),
                message="Invalid route target",
            )
            targets.append(
                RouteTarget(
                    fields["connection_id"],  # type: ignore[arg-type]
                    fields["namespace"],  # type: ignore[arg-type]
                )
            )
        routes[behavior] = tuple(targets)
    return RouteLayer(routes)


def _data_to_config(value: object) -> RoutingConfig:
    fields = _require_exact_keys(
        value,
        frozenset(
            (
                "schema_version",
                "revision",
                "connections",
                "global_routes",
                "client_routes",
                "mcp_connections",
                "legacy_namespace_migration_completed",
                "migration_write_blocked",
                "deprecations",
            )
        ),
        message="Invalid routing configuration",
    )
    encoded_connections = fields["connections"]
    if not isinstance(encoded_connections, list):
        raise ValueError("Invalid routing connections")
    connections: list[Connection] = []
    for encoded_connection in encoded_connections:
        connection = _require_exact_keys(
            encoded_connection,
            frozenset(("id", "label", "keychain_account", "configured")),
            message="Invalid routing connection",
        )
        connections.append(
            Connection(
                connection["id"],  # type: ignore[arg-type]
                connection["label"],  # type: ignore[arg-type]
                connection["keychain_account"],  # type: ignore[arg-type]
                connection["configured"],  # type: ignore[arg-type]
            )
        )
    encoded_client_routes = fields["client_routes"]
    if not isinstance(encoded_client_routes, dict):
        raise ValueError("Invalid client routes")
    encoded_mcp_connections = fields["mcp_connections"]
    if not isinstance(encoded_mcp_connections, dict):
        raise ValueError("Invalid MCP routing connections")
    deprecations = fields["deprecations"]
    if not isinstance(deprecations, list):
        raise ValueError("Invalid routing deprecations")
    return _validate_config(
        RoutingConfig(
            schema_version=fields["schema_version"],  # type: ignore[arg-type]
            revision=fields["revision"],  # type: ignore[arg-type]
            connections=tuple(connections),
            global_routes=_data_to_layer(fields["global_routes"]),
            client_routes={
                client: _data_to_layer(layer)
                for client, layer in encoded_client_routes.items()
            },
            mcp_connections=dict(encoded_mcp_connections),
            legacy_namespace_migration_completed=fields[
                "legacy_namespace_migration_completed"
            ],  # type: ignore[arg-type]
            migration_write_blocked=fields["migration_write_blocked"],  # type: ignore[arg-type]
            deprecations=tuple(deprecations),
        )
    )


def _encode(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _reject_duplicate_object_names(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    object_value: dict[str, object] = {}
    for key, value in pairs:
        if key in object_value:
            raise ValueError("Duplicate JSON object name")
        object_value[key] = value
    return object_value


def _decode_json(content: bytes) -> object:
    return json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_object_names,
    )


def load_routing(data_dir: Path | None = None) -> RoutingConfig:
    selected = _selected_data_dir(data_dir)
    _ensure_data_dir(selected)
    try:
        content = _read_bounded(selected, _ROUTES_FILE, _MAX_CONFIG_BYTES)
        decoded = _decode_json(content)
    except FileNotFoundError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Routing configuration is invalid") from None
    return _data_to_config(decoded)


def inspect_routing(data_dir: Path | None = None) -> RoutingConfig:
    """Read and validate routing without creating or repairing storage."""

    selected = _selected_data_dir(data_dir)
    _inspect_data_dir(selected)
    try:
        content = _read_bounded(selected, _ROUTES_FILE, _MAX_CONFIG_BYTES)
        decoded = _decode_json(content)
    except FileNotFoundError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Routing configuration is invalid") from None
    return _data_to_config(decoded)


def store_routing(config: RoutingConfig, data_dir: Path | None = None) -> None:
    checked = _validate_config(config)
    encoded = _encode(_config_to_data(checked))
    if len(encoded) > _MAX_CONFIG_BYTES:
        raise ValueError("Routing configuration exceeds its size limit")
    selected = _selected_data_dir(data_dir)
    _ensure_data_dir(selected)
    _atomic_write(selected, _ROUTES_FILE, encoded)


def update_routing(
    mutator: Callable[[RoutingConfig], RoutingConfig],
    data_dir: Path | None = None,
    *,
    resolve_migration_write_block: bool = False,
) -> RoutingConfig:
    if not callable(mutator):
        raise ValueError("Routing update must be callable")
    if type(resolve_migration_write_block) is not bool:
        raise ValueError("Invalid migration write-block resolution")
    selected = _selected_data_dir(data_dir)
    with _locked(selected, "routes.lock"):
        current = load_routing(selected)
        updated = _validate_config(mutator(current))
        if resolve_migration_write_block:
            if not _has_explicit_global_write_routes(updated):
                raise ValueError("Global write routes are incomplete")
            updated = replace(updated, migration_write_blocked=False)
        elif current.migration_write_blocked:
            updated = replace(updated, migration_write_blocked=True)
        updated = replace(updated, revision=current.revision + 1)
        store_routing(updated, selected)
        return updated


def reset_routing_to_defaults(
    data_dir: Path | None = None,
) -> RoutingConfig:
    """Atomically clear automatic routes and the migration write block."""

    selected = _selected_data_dir(data_dir)
    with _locked(selected, "routes.lock"):
        current = load_routing(selected)
        updated = replace(
            use_default_routes(current),
            revision=current.revision + 1,
        )
        store_routing(updated, selected)
        return updated


def _decode_legacy_basic_string(value: str) -> tuple[str, str]:
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
        if escaped in _LEGACY_ESCAPES:
            decoded.append(_LEGACY_ESCAPES[escaped])
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
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            raise LegacyCredentialError("unsupported legacy credential")
        decoded.append(chr(codepoint))
        index += width + 1
    raise LegacyCredentialError("unsupported legacy credential")


def _parse_legacy_key_assignment(line: str) -> str:
    if not line.startswith(_LEGACY_KEY):
        raise LegacyCredentialError("unsupported legacy credential")
    remainder = line[len(_LEGACY_KEY) :]
    if not remainder or remainder[0] not in {" ", "\t", "="}:
        raise LegacyCredentialError("unsupported legacy credential")
    remainder = remainder.lstrip(" \t")
    if not remainder.startswith("="):
        raise LegacyCredentialError("unsupported legacy credential")
    encoded = remainder[1:].lstrip(" \t")
    decoded, trailing = _decode_legacy_basic_string(encoded)
    trailing = trailing.strip(" \t")
    if trailing and not trailing.startswith("#"):
        raise LegacyCredentialError("unsupported legacy credential")
    if not decoded or "\x00" in decoded:
        raise LegacyCredentialError("unsupported legacy credential")
    return decoded


def parse_legacy_api_key(text: str) -> str | None:
    """Parse only one exact basic string from the old Codex Remem table."""

    if not isinstance(text, str):
        raise LegacyCredentialError("unsupported legacy credential")
    current_table: str | None = None
    exact_table_count = 0
    api_key: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            header = stripped.split("#", 1)[0].rstrip()
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
                if exact_table_count > 1:
                    raise LegacyCredentialError(
                        "unsupported legacy credential"
                    )
            continue
        candidate = stripped.split("#", 1)[0].rstrip()
        if "=" not in candidate:
            continue
        assignment_key = candidate.split("=", 1)[0].strip()
        if _LEGACY_KEY.lower() not in assignment_key.lower():
            continue
        if current_table != _LEGACY_ENV_TABLE or api_key is not None:
            raise LegacyCredentialError("unsupported legacy credential")
        api_key = _parse_legacy_key_assignment(stripped)
    return api_key


def _environment_home(environment: Mapping[str, str]) -> Path:
    home = environment.get("HOME", "")
    if isinstance(home, str) and home.strip():
        return Path(home).expanduser()
    return Path.home()


def _legacy_codex_config_path(environment: Mapping[str, str]) -> Path:
    home = _environment_home(environment)
    configured = environment.get("CODEX_HOME", "")
    if not isinstance(configured, str):
        raise ValueError("Invalid legacy environment")
    value = configured.strip()
    if not value:
        return home / ".codex" / "config.toml"
    if value == "~":
        return home / "config.toml"
    if value.startswith("~/"):
        return home / value[2:] / "config.toml"
    return Path(value) / "config.toml"


def _read_legacy_api_key(environment: Mapping[str, str]) -> str | None:
    path = _legacy_codex_config_path(environment)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError("Legacy routing discovery failed") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_LEGACY_CONFIG_BYTES
        ):
            raise ValueError("Legacy routing discovery failed")
        chunks: list[bytes] = []
        remaining = _MAX_LEGACY_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_LEGACY_CONFIG_BYTES:
            raise ValueError("Legacy routing discovery failed")
    finally:
        os.close(descriptor)
    try:
        return parse_legacy_api_key(content.decode("utf-8"))
    except (UnicodeDecodeError, LegacyCredentialError):
        raise ValueError("Legacy routing discovery failed") from None


def discover_legacy_routing(
    environment: Mapping[str, str] | None = None,
    *,
    distinct_credentials: int = 1,
) -> LegacyDiscovery:
    if not _is_plain_int(distinct_credentials) or distinct_credentials < 0:
        raise ValueError("Invalid legacy credential count")
    source = os.environ if environment is None else environment
    if not isinstance(source, Mapping):
        raise ValueError("Invalid legacy environment")
    destinations: dict[str, tuple[str, ...]] = {}
    for behavior, variable in (
        ("memory", "REMEM_MEMORY_PERSONAL_NAMESPACE"),
        ("sessions", "REMEM_MEMORY_ENGINEERING_NAMESPACE"),
    ):
        value = source.get(variable, "")
        if not isinstance(value, str):
            raise ValueError("Invalid legacy namespace")
        if value:
            destinations[behavior] = (
                _validate_namespace(value, behavior=behavior),
            )
    return LegacyDiscovery(distinct_credentials, destinations)


def discover_local_legacy_routing(
    environment: Mapping[str, str],
    credential_loader: Callable[[], str | None],
) -> LegacyDiscovery:
    """Compare canonical and legacy local credentials without persisting either."""

    if not isinstance(environment, Mapping) or not callable(credential_loader):
        raise ValueError("Invalid legacy discovery")
    legacy = _read_legacy_api_key(environment)
    if legacy is None:
        return discover_legacy_routing(environment)
    try:
        canonical = credential_loader()
    except Exception:
        raise ValueError("Legacy routing discovery failed") from None
    if canonical is not None and (
        not isinstance(canonical, str) or not canonical
    ):
        raise ValueError("Legacy routing discovery failed")
    distinct_credentials = 1
    if canonical is not None:
        try:
            equal = hmac.compare_digest(
                legacy.encode("utf-8"),
                canonical.encode("utf-8"),
            )
        except UnicodeError:
            raise ValueError("Legacy routing discovery failed") from None
        if not equal:
            distinct_credentials = 2
    return discover_legacy_routing(
        environment,
        distinct_credentials=distinct_credentials,
    )


def _checked_legacy_discovery(discovery: object) -> LegacyDiscovery:
    if not isinstance(discovery, LegacyDiscovery):
        raise ValueError("Invalid legacy discovery")
    if not _is_plain_int(discovery.distinct_credentials) or (
        discovery.distinct_credentials < 0
        or discovery.distinct_credentials > 2
    ):
        raise ValueError("Invalid legacy credential count")
    destinations: dict[str, tuple[str, ...]] = {}
    candidate_count = 0
    for behavior, candidates in discovery.destination_candidates.items():
        if behavior not in {"memory", "sessions"} or not isinstance(
            candidates, tuple
        ):
            raise ValueError("Invalid legacy destinations")
        nonempty: list[str] = []
        for candidate in candidates:
            if not isinstance(candidate, str):
                raise ValueError("Invalid legacy namespace")
            if candidate:
                nonempty.append(_validate_namespace(candidate, behavior=behavior))
                candidate_count += 1
                if candidate_count > _MAX_RECALL_TARGETS:
                    raise ValueError("Too many legacy destinations")
        if nonempty:
            destinations[behavior] = tuple(nonempty)
    return LegacyDiscovery(discovery.distinct_credentials, destinations)


def _merge_legacy_discoveries(
    *discoveries: LegacyDiscovery,
) -> LegacyDiscovery:
    checked = tuple(_checked_legacy_discovery(item) for item in discoveries)
    destinations: dict[str, tuple[str, ...]] = {}
    for behavior in ("memory", "sessions"):
        candidates: list[str] = []
        for discovery in checked:
            candidates.extend(
                discovery.destination_candidates.get(behavior, ())
            )
        distinct = tuple(dict.fromkeys(candidates))
        if distinct:
            destinations[behavior] = distinct
    return _checked_legacy_discovery(
        LegacyDiscovery(
            max(
                (item.distinct_credentials for item in checked),
                default=0,
            ),
            destinations,
        )
    )


def _stage_to_data(discovery: LegacyDiscovery) -> dict[str, object]:
    checked = _checked_legacy_discovery(discovery)
    return {
        "schema_version": _SCHEMA_VERSION,
        "distinct_credentials": checked.distinct_credentials,
        "destination_candidates": {
            behavior: list(candidates)
            for behavior, candidates in checked.destination_candidates.items()
        },
    }


def _data_to_stage(value: object) -> LegacyDiscovery:
    fields = _require_exact_keys(
        value,
        frozenset(
            (
                "schema_version",
                "distinct_credentials",
                "destination_candidates",
            )
        ),
        message="Invalid routing migration stage",
    )
    if fields["schema_version"] != _SCHEMA_VERSION:
        raise ValueError("Invalid routing migration stage")
    destinations = fields["destination_candidates"]
    if not isinstance(destinations, dict):
        raise ValueError("Invalid routing migration stage")
    decoded: dict[str, tuple[str, ...]] = {}
    for behavior, candidates in destinations.items():
        if not isinstance(candidates, list):
            raise ValueError("Invalid routing migration stage")
        decoded[behavior] = tuple(candidates)  # type: ignore[arg-type]
    return _checked_legacy_discovery(
        LegacyDiscovery(
            fields["distinct_credentials"],  # type: ignore[arg-type]
            decoded,
        )
    )


def _load_staged_legacy_routing(data_dir: Path) -> LegacyDiscovery | None:
    try:
        content = _read_bounded(
            data_dir,
            _MIGRATION_STAGE_FILE,
            _MAX_MIGRATION_STAGE_BYTES,
        )
        decoded = _decode_json(content)
        return _data_to_stage(decoded)
    except FileNotFoundError:
        return None
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Routing migration stage is invalid") from None


def _store_staged_legacy_routing(
    discovery: LegacyDiscovery,
    data_dir: Path,
) -> None:
    encoded = _encode(_stage_to_data(discovery))
    if len(encoded) > _MAX_MIGRATION_STAGE_BYTES:
        raise ValueError("Routing migration stage exceeds its size limit")
    _atomic_write(data_dir, _MIGRATION_STAGE_FILE, encoded)


def _clear_staged_legacy_routing(data_dir: Path) -> None:
    try:
        path = _secure_file_path(data_dir, _MIGRATION_STAGE_FILE)
        path.unlink()
        descriptor = _open_directory(data_dir)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        # Final routing state is already durable. Retaining a valid stage lets
        # a later initializer retry cleanup without weakening migration safety.
        pass


def stage_legacy_routing(
    discovery: LegacyDiscovery,
    data_dir: Path | None = None,
) -> LegacyDiscovery:
    """Durably stage credential-free discovery before installer mutations."""

    selected = _selected_data_dir(data_dir)
    checked = _checked_legacy_discovery(discovery)
    with _locked(selected, "routes.lock"):
        existing = _load_staged_legacy_routing(selected)
        merged = (
            checked
            if existing is None
            else _merge_legacy_discoveries(existing, checked)
        )
        _store_staged_legacy_routing(merged, selected)
        return merged


def _legacy_default_deprecations(environment: Mapping[str, str]) -> tuple[str, ...]:
    if "REMEM_DEFAULT_NAMESPACE" in environment:
        return ("REMEM_DEFAULT_NAMESPACE is deprecated",)
    return ()


def _migrate_legacy_routing(
    discovery: LegacyDiscovery,
    environment: Mapping[str, str],
    base: RoutingConfig | None = None,
    *,
    initialized: bool,
) -> tuple[RoutingConfig, MigrationOutcome]:
    checked = _checked_legacy_discovery(discovery)
    prior = _empty_config() if base is None else _validate_config(base)
    routes = dict(prior.global_routes.routes)
    destination_ambiguous = False
    for behavior, candidates in checked.destination_candidates.items():
        distinct_destinations = tuple(dict.fromkeys(candidates))
        if len(distinct_destinations) > 1:
            destination_ambiguous = True
            continue
        if behavior not in routes:
            routes[behavior] = (RouteTarget("primary", distinct_destinations[0]),)
    credential_ambiguous = checked.distinct_credentials > 1
    deprecations = tuple(
        dict.fromkeys(prior.deprecations + _legacy_default_deprecations(environment))
    )
    config = replace(
        prior,
        global_routes=RouteLayer(routes),
        legacy_namespace_migration_completed=True,
        migration_write_blocked=(
            prior.migration_write_blocked
            or credential_ambiguous
            or destination_ambiguous
        ),
        deprecations=deprecations,
    )
    return config, MigrationOutcome(
        initialized=initialized,
        distinct_credentials=checked.distinct_credentials,
        credential_ambiguous=credential_ambiguous,
        destination_ambiguous=destination_ambiguous,
        deprecations=deprecations,
    )


def initialize_routing(
    data_dir: Path | None = None,
    environment: Mapping[str, str] | None = None,
    discovery: LegacyDiscovery | None = None,
    *,
    credential_loader: Callable[[], str | None] | None = None,
) -> tuple[RoutingConfig, MigrationOutcome]:
    selected = _selected_data_dir(data_dir)
    with _locked(selected, "routes.lock"):
        try:
            current = load_routing(selected)
        except FileNotFoundError:
            current = None
        staged = _load_staged_legacy_routing(selected)
        source = os.environ if environment is None else environment
        if not isinstance(source, Mapping):
            raise ValueError("Invalid legacy environment")
        selected_discovery: LegacyDiscovery | None = (
            _checked_legacy_discovery(discovery)
            if discovery is not None
            else None
        )
        if (
            selected_discovery is None
            and staged is None
            and current is not None
            and current.legacy_namespace_migration_completed
        ):
            return current, MigrationOutcome(False)
        if selected_discovery is None and staged is None:
            selected_discovery = (
                discover_local_legacy_routing(source, credential_loader)
                if credential_loader is not None
                else discover_legacy_routing(source)
            )
            if credential_loader is not None:
                _store_staged_legacy_routing(selected_discovery, selected)
                staged = selected_discovery
        if staged is not None:
            selected_discovery = (
                staged
                if selected_discovery is None
                else _merge_legacy_discoveries(
                    staged,
                    selected_discovery,
                )
            )
        assert selected_discovery is not None
        if current is not None and current.legacy_namespace_migration_completed:
            checked = _checked_legacy_discovery(selected_discovery)
            credential_ambiguous = checked.distinct_credentials > 1
            destination_ambiguous = any(
                len(tuple(dict.fromkeys(candidates))) > 1
                for candidates in checked.destination_candidates.values()
            )
            if (
                not current.migration_write_blocked
                and (credential_ambiguous or destination_ambiguous)
            ):
                current = replace(
                    current,
                    revision=current.revision + 1,
                    migration_write_blocked=True,
                )
                store_routing(current, selected)
            _clear_staged_legacy_routing(selected)
            return current, MigrationOutcome(
                False,
                distinct_credentials=checked.distinct_credentials,
                credential_ambiguous=credential_ambiguous,
                destination_ambiguous=destination_ambiguous,
                deprecations=current.deprecations,
            )
        config, outcome = _migrate_legacy_routing(
            selected_discovery,
            source,
            current,
            initialized=current is None,
        )
        store_routing(config, selected)
        _clear_staged_legacy_routing(selected)
        return config, outcome


def load_or_initialize_routing(
    data_dir: Path | None = None,
    environment: Mapping[str, str] | None = None,
    *,
    credential_loader: Callable[[], str | None] | None = None,
) -> RoutingConfig:
    def unavailable_credential_loader() -> str | None:
        raise ValueError("Canonical credential loader is unavailable")

    return initialize_routing(
        data_dir,
        environment,
        credential_loader=(
            credential_loader
            if credential_loader is not None
            else unavailable_credential_loader
        ),
    )[0]


def _validate_health_record(record: object) -> RouteHealthRecord:
    if not isinstance(record, RouteHealthRecord):
        raise ValueError("Invalid route health record")
    client = _validate_client(record.client)
    behavior = _validate_behavior(record.behavior)
    connection_id = _validate_connection_id(record.connection_id)
    namespace = _validate_namespace(record.namespace, behavior=behavior)
    if record.status not in _HEALTH_STATUSES:
        raise ValueError("Invalid route health status")
    if not isinstance(record.detail_code, str) or _DETAIL_CODE.fullmatch(
        record.detail_code
    ) is None:
        raise ValueError("Invalid route health detail code")
    if not isinstance(record.observed_at, str) or _UTC_RFC3339.fullmatch(
        record.observed_at
    ) is None:
        raise ValueError("Invalid route health timestamp")
    try:
        observed = datetime.fromisoformat(record.observed_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid route health timestamp") from None
    if not record.observed_at.endswith("Z") or observed.tzinfo != timezone.utc:
        raise ValueError("Invalid route health timestamp")
    return RouteHealthRecord(
        client,
        behavior,
        connection_id,
        namespace,
        record.status,
        record.detail_code,
        record.observed_at,
    )


def _health_to_data(record: RouteHealthRecord) -> dict[str, str]:
    return {
        "client": record.client,
        "behavior": record.behavior,
        "connection_id": record.connection_id,
        "namespace": record.namespace,
        "status": record.status,
        "detail_code": record.detail_code,
        "observed_at": record.observed_at,
    }


def _data_to_health(value: object) -> RouteHealthRecord:
    fields = _require_exact_keys(
        value,
        frozenset(
            (
                "client",
                "behavior",
                "connection_id",
                "namespace",
                "status",
                "detail_code",
                "observed_at",
            )
        ),
        message="Invalid route health record",
    )
    return _validate_health_record(
        RouteHealthRecord(
            fields["client"],  # type: ignore[arg-type]
            fields["behavior"],  # type: ignore[arg-type]
            fields["connection_id"],  # type: ignore[arg-type]
            fields["namespace"],  # type: ignore[arg-type]
            fields["status"],  # type: ignore[arg-type]
            fields["detail_code"],  # type: ignore[arg-type]
            fields["observed_at"],  # type: ignore[arg-type]
        )
    )


def load_route_health(data_dir: Path | None = None) -> tuple[RouteHealthRecord, ...]:
    selected = _selected_data_dir(data_dir)
    _ensure_data_dir(selected)
    try:
        content = _read_bounded(selected, _HEALTH_FILE, _MAX_HEALTH_BYTES)
    except FileNotFoundError:
        return ()
    try:
        decoded = _decode_json(content)
        if not isinstance(decoded, list) or len(decoded) > _MAX_HEALTH_RECORDS:
            raise ValueError("Invalid route health storage")
        return tuple(_data_to_health(item) for item in decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Route health storage is invalid") from None


def inspect_route_health(
    data_dir: Path | None = None,
) -> tuple[RouteHealthRecord, ...]:
    """Read validated route health without mutating its storage."""

    selected = _selected_data_dir(data_dir)
    _inspect_data_dir(selected)
    try:
        content = _read_bounded(selected, _HEALTH_FILE, _MAX_HEALTH_BYTES)
    except FileNotFoundError:
        return ()
    try:
        decoded = _decode_json(content)
        if not isinstance(decoded, list) or len(decoded) > _MAX_HEALTH_RECORDS:
            raise ValueError("Invalid route health storage")
        return tuple(_data_to_health(item) for item in decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Route health storage is invalid") from None


def record_route_health(
    record: RouteHealthRecord,
    data_dir: Path | None = None,
) -> None:
    checked = _validate_health_record(record)
    selected = _selected_data_dir(data_dir)
    with _locked(selected, "route-health.lock"):
        records = (*load_route_health(selected), checked)[-_MAX_HEALTH_RECORDS:]
        encoded = _encode([_health_to_data(item) for item in records])
        if len(encoded) > _MAX_HEALTH_BYTES:
            raise ValueError("Route health storage exceeds its size limit")
        _atomic_write(selected, _HEALTH_FILE, encoded)
