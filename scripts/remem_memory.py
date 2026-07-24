#!/usr/bin/env python3
"""Canonical CLI for Remem Memory and its legacy workflow aliases."""

from __future__ import annotations

import getpass
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


_SCRIPT_PATH = Path(__file__).resolve()
_REPOSITORY_ROOT = _SCRIPT_PATH.parent.parent
_PLUGIN_SCRIPTS = (
    _REPOSITORY_ROOT / "plugins" / "remem-memory" / "scripts"
)
if str(_PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SCRIPTS))

import remem_api  # noqa: E402
import remem_mcp_launcher  # noqa: E402
import remem_routing  # noqa: E402


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
_UTC_RFC3339_COMPONENTS = re.compile(
    r"\A([0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z\Z"
)
_INVALID_RFC3339_SORT_KEY = (
    0,
    datetime.min.replace(tzinfo=timezone.utc),
    Decimal(0),
)
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
_CLIENTS = ("codex", "claude")
_BEHAVIORS = ("recall", "memory", "sessions")
_DOCTOR_ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
)
_MAX_PLUGIN_LIST_BYTES = 64 * 1024
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


def _load_or_initialize_routing() -> remem_routing.RoutingConfig:
    return remem_routing.load_or_initialize_routing(
        default_data_dir(),
        os.environ,
    )


def _connection_name(
    config: remem_routing.RoutingConfig,
    connection_id: str,
) -> str:
    for connection in config.connections:
        if connection.id == connection_id:
            return (
                "primary"
                if connection.id == "primary"
                else connection.label
            )
    raise ValueError("Unknown routing connection")


def _find_connection(
    config: remem_routing.RoutingConfig,
    name: str,
) -> remem_routing.Connection:
    if name == "primary":
        return config.connections[0]
    matches = [
        connection
        for connection in config.connections
        if connection.label == name or connection.id == name
    ]
    if len(matches) != 1:
        raise ValueError("Unknown routing connection")
    return matches[0]


def _format_targets(
    config: remem_routing.RoutingConfig,
    targets: tuple[remem_routing.RouteTarget, ...],
) -> list[str]:
    return [
        (
            f"{_connection_name(config, target.connection_id)}"
            f"/{target.namespace}"
        )
        for target in targets
    ]


def _global_routes(
    config: remem_routing.RoutingConfig,
    mode: str,
) -> dict[str, tuple[remem_routing.RouteTarget, ...]]:
    defaults = remem_routing.built_in_routes()
    routes: dict[str, tuple[remem_routing.RouteTarget, ...]] = {}
    for behavior in _BEHAVIORS:
        suppressed = (
            mode == "off"
            or (
                mode == "recall-only"
                and behavior in {"memory", "sessions"}
            )
            or (
                config.migration_write_blocked
                and behavior in {"memory", "sessions"}
            )
        )
        if suppressed:
            routes[behavior] = ()
        else:
            routes[behavior] = config.global_routes.routes.get(
                behavior,
                defaults[behavior],
            )
    return routes


def _latest_health(
    config: remem_routing.RoutingConfig,
    clients: tuple[str, ...],
    mode: str,
    *,
    read_only: bool = False,
) -> list[dict[str, str]]:
    selected: dict[
        tuple[str, str, str, str],
        remem_routing.RouteHealthRecord,
    ] = {}
    try:
        records = (
            remem_routing.inspect_route_health(default_data_dir())
            if read_only
            else remem_routing.load_route_health(default_data_dir())
        )
    except Exception:
        return []
    affected = {
        (
            client,
            behavior,
            target.connection_id,
            target.namespace,
        )
        for client in clients
        for behavior in _BEHAVIORS
        for target in (
            ()
            if mode == "off"
            or mode == "recall-only"
            and behavior in {"memory", "sessions"}
            else remem_routing.resolve_routes(
                config,
                behavior=behavior,
                client=client,
            )
        )
    }
    for record in records:
        key = (
            record.client,
            record.behavior,
            record.connection_id,
            record.namespace,
        )
        prior = selected.get(key)
        if key in affected and (
            prior is None
            or _rfc3339_sort_key(record.observed_at)
            >= _rfc3339_sort_key(prior.observed_at)
        ):
            selected[key] = record
    return [
        {
            "behavior": record.behavior,
            "client": record.client,
            "detail_code": record.detail_code,
            "observed_at": record.observed_at,
            "route": (
                f"{_connection_name(config, record.connection_id)}"
                f"/{record.namespace}"
            ),
            "status": record.status,
        }
        for _key, record in sorted(selected.items())
    ]


def _rfc3339_sort_key(value: object) -> tuple[int, datetime, Decimal]:
    if not isinstance(value, str):
        return _INVALID_RFC3339_SORT_KEY
    match = _UTC_RFC3339_COMPONENTS.fullmatch(value)
    if match is None:
        return _INVALID_RFC3339_SORT_KEY
    try:
        observed = datetime.strptime(
            match.group(1),
            "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return _INVALID_RFC3339_SORT_KEY
    fraction = match.group(2)
    return (
        1,
        observed,
        Decimal(f"0.{fraction}") if fraction is not None else Decimal(0),
    )


def _routes_payload(
    config: remem_routing.RoutingConfig,
    clients: tuple[str, ...],
) -> dict[str, Any]:
    mode = load_settings()["mode"]
    global_routes = _global_routes(config, mode)
    client_routes: dict[str, dict[str, dict[str, Any]]] = {}
    for client in clients:
        layer = config.client_routes.get(client)
        client_routes[client] = {}
        for behavior in _BEHAVIORS:
            source = (
                "override"
                if layer is not None and behavior in layer.routes
                else "inherit"
            )
            client_routes[client][behavior] = {
                "routes": _format_targets(
                    config,
                    (
                        ()
                        if mode == "off"
                        or mode == "recall-only"
                        and behavior in {"memory", "sessions"}
                        else remem_routing.resolve_routes(
                            config,
                            behavior=behavior,
                            client=client,
                        )
                    ),
                ),
                "source": source,
            }
    return {
        "clients": client_routes,
        "connections": [
            {
                "configured": connection.configured,
                "credential": (
                    "available"
                    if remem_api.resolve_connection_api_key(
                        connection,
                        environment=os.environ,
                    )
                    else "missing"
                ),
                "name": connection.label,
            }
            for connection in config.connections
        ],
        "deprecations": list(config.deprecations),
        "global_routes": {
            behavior: _format_targets(config, global_routes[behavior])
            for behavior in _BEHAVIORS
        },
        "last_api_results": _latest_health(config, clients, mode),
        "migration_write_blocked": config.migration_write_blocked,
        "mode": mode,
    }


def _render_route_values(values: list[str]) -> str:
    return ", ".join(values) if values else "off"


def _show_routes(clients: tuple[str, ...], as_json: bool) -> int:
    try:
        config = _load_or_initialize_routing()
        payload = _routes_payload(config, clients)
    except Exception:
        print("error: unable to read Remem routing", file=sys.stderr)
        return 1
    if as_json:
        print(
            json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    print(f"mode: {payload['mode']}")
    print(
        "migration write block: "
        + ("on" if payload["migration_write_blocked"] else "off")
    )
    print("Global routes")
    for behavior in _BEHAVIORS:
        print(
            f"  {behavior}: "
            f"{_render_route_values(payload['global_routes'][behavior])}"
        )
    for client in clients:
        print(f"{client.title()} routes")
        for behavior in _BEHAVIORS:
            route = payload["clients"][client][behavior]
            print(
                f"  {behavior}: {route['source']} -> "
                f"{_render_route_values(route['routes'])}"
            )
    print("Connections")
    for connection in payload["connections"]:
        state = "configured" if connection["configured"] else "missing"
        print(
            f"  {connection['name']}: {state}; "
            f"credential {connection['credential']}"
        )
    print("Last API results")
    if not payload["last_api_results"]:
        print("  none")
    else:
        for record in payload["last_api_results"]:
            print(
                f"  {record['route']} {record['behavior']} "
                f"({record['client']}): {record['status']} "
                f"[{record['detail_code']}]"
            )
    if payload["deprecations"]:
        print("Migration diagnostics")
        for diagnostic in payload["deprecations"]:
            print(f"  {diagnostic}")
    return 0


def _parse_show_options(
    arguments: List[str],
) -> Optional[tuple[tuple[str, ...], bool]]:
    clients: tuple[str, ...] = _CLIENTS
    as_json = False
    index = 0
    client_seen = False
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--json" and not as_json:
            as_json = True
            index += 1
            continue
        if (
            argument == "--client"
            and not client_seen
            and index + 1 < len(arguments)
            and arguments[index + 1] in _CLIENTS
        ):
            clients = (arguments[index + 1],)
            client_seen = True
            index += 2
            continue
        return None
    return clients, as_json


def _parse_target(
    config: remem_routing.RoutingConfig,
    value: str,
    *,
    behavior: str,
) -> remem_routing.RouteTarget:
    if not isinstance(value, str) or not value or value == "off":
        raise ValueError("Invalid route target")
    if "/" in value:
        connection_name, separator, namespace = value.partition("/")
        if not separator or not namespace:
            raise ValueError("Invalid route target")
        connection = _find_connection(config, connection_name)
    else:
        if len(config.connections) != 1:
            raise ValueError("A connection name is required")
        connection = config.connections[0]
        namespace = value
    if not connection.configured:
        raise ValueError("Routing connection is not configured")
    direction = "read" if behavior == "recall" else "write"
    return remem_routing.parse_target(
        f"{connection.id}/{namespace}",
        direction=direction,
    )


def _set_routes(arguments: List[str]) -> int:
    if len(arguments) < 2 or arguments[0] not in _BEHAVIORS:
        print("error: invalid routes command", file=sys.stderr)
        return 2
    behavior = arguments[0]
    remaining = arguments[1:]
    client: Optional[str] = None
    if (
        len(remaining) >= 2
        and remaining[-2] == "--client"
        and remaining[-1] in _CLIENTS
    ):
        client = remaining[-1]
        remaining = remaining[:-2]
    try:
        config = _load_or_initialize_routing()
        if behavior == "recall":
            if remaining == ["--off"]:
                targets: tuple[remem_routing.RouteTarget, ...] = ()
            elif (
                len(remaining) >= 2
                and remaining[0] == "--from"
                and all(not item.startswith("--") for item in remaining[1:])
            ):
                targets = tuple(
                    _parse_target(config, item, behavior=behavior)
                    for item in remaining[1:]
                )
            else:
                raise ValueError("Invalid recall route")
        else:
            if len(remaining) != 2 or remaining[0] != "--to":
                raise ValueError("Invalid write route")
            targets = (
                ()
                if remaining[1] == "off"
                else (
                    _parse_target(
                        config,
                        remaining[1],
                        behavior=behavior,
                    ),
                )
            )

        def mutate(
            current: remem_routing.RoutingConfig,
        ) -> remem_routing.RoutingConfig:
            if client is None:
                routes = dict(current.global_routes.routes)
                routes[behavior] = targets
                return replace(
                    current,
                    global_routes=remem_routing.RouteLayer(routes),
                )
            client_routes = dict(current.client_routes)
            layer_routes = dict(
                client_routes.get(
                    client,
                    remem_routing.RouteLayer({}),
                ).routes
            )
            layer_routes[behavior] = targets
            client_routes[client] = remem_routing.RouteLayer(layer_routes)
            return replace(current, client_routes=client_routes)

        resolve_block = (
            client is None
            and behavior in {"memory", "sessions"}
            and all(
                item == behavior or item in config.global_routes.routes
                for item in ("memory", "sessions")
            )
        )
        remem_routing.update_routing(
            mutate,
            default_data_dir(),
            resolve_migration_write_block=resolve_block,
        )
    except Exception:
        print("error: invalid routes command", file=sys.stderr)
        return 2
    scope = client or "global"
    print(
        f"{scope} {behavior}: "
        f"{_render_route_values(_format_targets(config, targets))}"
    )
    return 0


def _use_default_routes() -> int:
    try:
        _load_or_initialize_routing()
        remem_routing.reset_routing_to_defaults(
            default_data_dir(),
        )
    except Exception:
        print("error: unable to reset Remem routing", file=sys.stderr)
        return 1
    print("routes: default")
    return 0


def _routes_command(arguments: List[str]) -> int:
    if arguments == ["use-default"]:
        return _use_default_routes()
    if arguments and arguments[0] == "show":
        parsed = _parse_show_options(arguments[1:])
        if parsed is None:
            print("error: invalid routes command", file=sys.stderr)
            return 2
        return _show_routes(*parsed)
    if arguments and arguments[0] == "set":
        return _set_routes(arguments[1:])
    print("error: invalid routes command", file=sys.stderr)
    return 2


def _connection_clients(
    config: remem_routing.RoutingConfig,
    connection_id: str,
) -> list[str]:
    return [
        client
        for client in _CLIENTS
        if config.mcp_connections.get(client, "primary") == connection_id
    ]


def _connections_list(as_json: bool) -> int:
    try:
        config = _load_or_initialize_routing()
    except Exception:
        print("error: unable to read Remem connections", file=sys.stderr)
        return 1
    connections = [
        {
            "configured": connection.configured,
            "mcp_clients": _connection_clients(config, connection.id),
            "name": connection.label,
        }
        for connection in config.connections
    ]
    if as_json:
        print(
            json.dumps(
                {"connections": connections},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    else:
        for connection in connections:
            clients = ", ".join(connection["mcp_clients"]) or "none"
            state = "configured" if connection["configured"] else "missing"
            print(
                f"{connection['name']}: {state}; "
                f"MCP clients: {clients}"
            )
    return 0


def _add_connection(name: str) -> int:
    try:
        config = _load_or_initialize_routing()
    except Exception:
        print(
            "error: unable to configure Remem connection",
            file=sys.stderr,
        )
        return 1
    if any(connection.id == name for connection in config.connections):
        print("error: invalid connections command", file=sys.stderr)
        return 2
    matches = [
        connection
        for connection in config.connections
        if connection.label == name
    ]
    if matches and matches[0].configured:
        print("error: invalid connections command", file=sys.stderr)
        return 2
    try:
        value = getpass.getpass("Remem API key: ")
    except Exception:
        print("error: unable to read Remem credential", file=sys.stderr)
        return 1
    normalized = value.strip() if isinstance(value, str) else ""
    if not normalized:
        print("error: Remem credential cannot be empty", file=sys.stderr)
        return 2
    try:
        if matches:
            connection = matches[0]
        else:
            if name.lower() == "primary":
                raise ValueError("Reserved connection name")
            token = uuid.uuid4().hex
            connection = remem_routing.Connection(
                f"conn_{token}",
                name,
                f"connection:{token}",
                False,
            )

            def add_pending(
                current: remem_routing.RoutingConfig,
            ) -> remem_routing.RoutingConfig:
                if any(
                    item.label == name for item in current.connections
                ):
                    raise ValueError("Duplicate connection")
                return replace(
                    current,
                    connections=(*current.connections, connection),
                )

            config = remem_routing.update_routing(
                add_pending,
                default_data_dir(),
            )
            connection = _find_connection(config, name)
        remem_api.store_keychain_api_key(
            connection.keychain_account,
            normalized,
        )
        verified = remem_api.resolve_keychain_api_key(
            connection.keychain_account,
        )
        if not isinstance(verified, str) or not hmac.compare_digest(
            normalized,
            verified,
        ):
            raise ValueError("Credential verification failed")

        def mark_configured(
            current: remem_routing.RoutingConfig,
        ) -> remem_routing.RoutingConfig:
            updated = tuple(
                replace(item, configured=True)
                if item.id == connection.id
                else item
                for item in current.connections
            )
            return replace(current, connections=updated)

        remem_routing.update_routing(
            mark_configured,
            default_data_dir(),
        )
    except Exception:
        print(
            "error: unable to configure Remem connection",
            file=sys.stderr,
        )
        return 1
    print(f"connection: {name} configured")
    return 0


def _use_connection(name: str, client: str) -> int:
    try:
        config = _load_or_initialize_routing()
        selected = _find_connection(config, name)
        if not selected.configured:
            raise ValueError("Connection is not configured")

        def mutate(
            current: remem_routing.RoutingConfig,
        ) -> remem_routing.RoutingConfig:
            mcp_connections = dict(current.mcp_connections)
            mcp_connections[client] = selected.id
            return replace(
                current,
                mcp_connections=mcp_connections,
            )

        remem_routing.update_routing(mutate, default_data_dir())
    except Exception:
        print("error: invalid connections command", file=sys.stderr)
        return 2
    print(f"{client} MCP connection: {selected.label}")
    return 0


def _connections_command(arguments: List[str]) -> int:
    if arguments == ["list"]:
        return _connections_list(False)
    if arguments == ["list", "--json"]:
        return _connections_list(True)
    if (
        len(arguments) == 2
        and arguments[0] == "add"
        and _valid_connection_name(arguments[1])
    ):
        return _add_connection(arguments[1])
    if (
        len(arguments) == 4
        and arguments[0] == "use"
        and arguments[2] == "--client"
        and arguments[3] in _CLIENTS
    ):
        return _use_connection(arguments[1], arguments[3])
    print("error: invalid connections command", file=sys.stderr)
    return 2


def _valid_connection_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and name == name.strip()
        and 1 <= len(name) <= 64
        and name.isprintable()
        and "/" not in name
        and not name.startswith("-")
        and name.lower() not in {"primary", "off"}
    )


def _uv_available() -> bool:
    try:
        remem_mcp_launcher._find_uv(os.environ, None)
    except Exception:
        return False
    return True


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
    try:
        config = _load_or_initialize_routing()
    except Exception:
        config = None
        print("routing: invalid")
    else:
        print("routing: valid")
        global_routes = _global_routes(config, settings["mode"])
        print(
            "routes: "
            + " ".join(
                (
                    f"{behavior}="
                    f"{_render_route_values(_format_targets(config, global_routes[behavior]))}"
                )
                for behavior in _BEHAVIORS
            )
        )
        for client in _CLIENTS:
            print(
                f"{client} routes: "
                + " ".join(
                    (
                        f"{behavior}="
                        + _render_route_values(
                            _format_targets(
                                config,
                                (
                                    ()
                                    if settings["mode"] == "off"
                                    or settings["mode"] == "recall-only"
                                    and behavior
                                    in {"memory", "sessions"}
                                    else remem_routing.resolve_routes(
                                        config,
                                        behavior=behavior,
                                        client=client,
                                    )
                                ),
                            )
                        )
                    )
                    for behavior in _BEHAVIORS
                )
            )
        print(
            "migration write block: "
            + ("on" if config.migration_write_blocked else "off")
        )
        configured = sum(
            1 for connection in config.connections if connection.configured
        )
        missing = len(config.connections) - configured
        print(
            f"connections: {configured} configured, {missing} missing"
        )
        for connection in config.connections:
            try:
                connection_credential = (
                    remem_api.resolve_connection_api_key(
                        connection,
                        environment=os.environ,
                    )
                )
            except Exception:
                connection_credential = None
            state = "configured" if connection.configured else "missing"
            credential_state = (
                "available" if connection_credential else "missing"
            )
            print(
                f"connection {connection.label}: {state}; "
                f"credential {credential_state}"
            )
        health = _latest_health(
            config,
            _CLIENTS,
            settings["mode"],
        )
        if health:
            latest = max(
                health,
                key=lambda record: _rfc3339_sort_key(
                    record["observed_at"]
                ),
            )
            print(
                f"last API result: {latest['route']} "
                f"{latest['behavior']} ({latest['client']}): "
                f"{latest['status']} [{latest['detail_code']}]"
            )
        for diagnostic in config.deprecations:
            print(f"migration: {diagnostic}")
    if _uv_available():
        print("uv: available")
    else:
        print("uv: missing (required for MCP)")
    return 0


def _plugin_records(value: object) -> list[dict[str, Any]]:
    selected = value
    if isinstance(value, dict):
        if "plugins" in value:
            selected = value["plugins"]
        elif "installed" in value:
            selected = value["installed"]
        else:
            selected = []
    if isinstance(selected, dict):
        selected = list(selected.values())
    if not isinstance(selected, list):
        raise ValueError("Invalid plugin list")
    return [item for item in selected if isinstance(item, dict)]


def _plugin_record_name(record: Mapping[str, Any]) -> str:
    for field in ("name", "id", "plugin", "identity"):
        value = record.get(field)
        if isinstance(value, str):
            return value
    return ""


def _plugin_record_enabled(record: Mapping[str, Any]) -> bool:
    enabled = record.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    status = record.get("status")
    return isinstance(status, str) and status.lower() == "enabled"


def _doctor_client_registrations(
) -> tuple[tuple[str, str], tuple[str, str]]:
    child_environment = {
        name: os.environ[name]
        for name in _DOCTOR_ENVIRONMENT_KEYS
        if name in os.environ and isinstance(os.environ[name], str)
    }
    installed = 0
    codex_enabled = False

    def result(
        registration: tuple[str, str],
    ) -> tuple[tuple[str, str], tuple[str, str]]:
        hook_presence = (
            ("ok", "installed_plugin_enabled")
            if codex_enabled
            else ("warning", "trust_unverified")
        )
        return registration, hook_presence

    for client in _CLIENTS:
        try:
            executable = shutil.which(
                client,
                path=os.environ.get("PATH"),
            )
        except Exception:
            executable = None
        if not executable:
            continue
        installed += 1
        try:
            completed = subprocess.run(
                [executable, "plugin", "list", "--json"],
                env=child_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            rendered = completed.stdout
            if (
                completed.returncode != 0
                or not isinstance(rendered, str)
                or len(rendered.encode("utf-8"))
                > _MAX_PLUGIN_LIST_BYTES
            ):
                return result(("failed", "plugin_state_unavailable"))
            payload = json.loads(rendered)
            records = _plugin_records(payload)
        except Exception:
            return result(("failed", "plugin_state_invalid"))
        matching = [
            record
            for record in records
            if _plugin_record_name(record)
            in {"remem-memory", "remem-memory@remem-memory"}
        ]
        if not matching:
            return result(("failed", "plugin_missing"))
        enabled = any(_plugin_record_enabled(record) for record in matching)
        if client == "codex":
            codex_enabled = enabled
        if not enabled:
            return result(("failed", "plugin_disabled"))
    if installed == 0:
        return result(("info", "client_not_installed"))
    return result(("ok", "verified"))


def _doctor_checks() -> list[dict[str, str]]:
    checks: dict[str, tuple[str, str]] = {}
    try:
        config = remem_routing.inspect_routing(default_data_dir())
    except FileNotFoundError:
        config = None
        checks["routing_storage"] = ("failed", "missing")
    except Exception:
        config = None
        checks["routing_storage"] = ("failed", "invalid")
    else:
        checks["routing_storage"] = ("ok", "valid")

    if config is None:
        checks["credentials"] = ("failed", "routing_unavailable")
        checks["namespace_readability"] = (
            "info",
            "routing_unavailable",
        )
    else:
        missing = 0
        for connection in config.connections:
            if not connection.configured or not remem_api.resolve_connection_api_key(
                connection,
                environment=os.environ,
            ):
                missing += 1
        checks["credentials"] = (
            ("ok", "available")
            if missing == 0
            else ("failed", "credential_unavailable")
        )
        health = [
            record
            for record in _latest_health(
                config,
                _CLIENTS,
                load_settings()["mode"],
                read_only=True,
            )
            if record["behavior"] == "recall"
        ]
        if not health:
            checks["namespace_readability"] = (
                "info",
                "no_prior_read",
            )
        elif all(record["status"] == "ok" for record in health):
            checks["namespace_readability"] = ("ok", "authorized")
        else:
            failure_status = next(
                record["status"]
                for record in health
                if record["status"] != "ok"
            )
            checks["namespace_readability"] = (
                "failed",
                failure_status,
            )
        if config.deprecations or config.migration_write_blocked:
            checks["migration"] = ("info", "attention_required")
        else:
            checks["migration"] = ("ok", "complete")

    uv = _uv_available()
    checks["runtime"] = (
        ("ok", "uv_available")
        if uv
        else ("failed", "uv_missing")
    )
    (
        checks["client_registrations"],
        checks["hook_presence"],
    ) = _doctor_client_registrations()
    launcher = _PLUGIN_SCRIPTS / "remem_mcp_launcher.py"
    checks["mcp_startup"] = (
        ("warning", "no_read_only_probe")
        if uv and launcher.is_file()
        else ("failed", "launcher_unavailable")
    )
    return [
        {
            "detail_code": checks[name][1],
            "name": name,
            "status": checks[name][0],
        }
        for name in sorted(checks)
    ]


def _doctor(as_json: bool) -> int:
    checks = _doctor_checks()
    statuses = {check["status"] for check in checks}
    if "failed" in statuses:
        status = "failed"
    elif "warning" in statuses:
        status = "warning"
    else:
        status = "healthy"
    healthy = status == "healthy"
    try:
        migration_diagnostics = list(
            remem_routing.inspect_routing(default_data_dir()).deprecations
        )
    except Exception:
        migration_diagnostics = []
    if as_json:
        print(
            json.dumps(
                {
                    "checks": checks,
                    "healthy": healthy,
                    "migration_diagnostics": migration_diagnostics,
                    "read_only": True,
                    "status": status,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    else:
        print(f"doctor: {status}")
        for check in checks:
            print(
                f"{check['name']}: {check['status']} "
                f"[{check['detail_code']}]"
            )
        for diagnostic in migration_diagnostics:
            print(f"migration: {diagnostic}")
    return 1 if status == "failed" else 0


def _usage(program: str) -> str:
    return (
        f"usage: {program} "
        "{checkpoint|rollup|recall|codex|mode|sensitivity|auth|status|"
        "routes|connections|doctor}"
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
    if command == "routes":
        return _routes_command(arguments)
    if command == "connections":
        return _connections_command(arguments)
    if command == "doctor":
        if not arguments:
            return _doctor(False)
        if arguments == ["--json"]:
            return _doctor(True)
        print("error: invalid doctor command", file=sys.stderr)
        return 2

    print(_usage(basename), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
