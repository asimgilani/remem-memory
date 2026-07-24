# Generic Namespace Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure, CLI-only, behavior-based namespace and credential routing to Remem Memory while retaining its automatic recall, durable memory, session checkpoints, roll-ups, MCP tools, Codex integration, Claude Code integration, and simple one-key installation.

**Architecture:** A new standard-library routing module owns a versioned, non-secret local routing document. It resolves `recall`, `memory`, and `sessions` routes by client and selects credentials by opaque Keychain account. Remem API keys remain the only permission boundary and their server-side default remains authoritative for `@default`. All automatic, manual, background, wrapper, and MCP paths consume the same router; explicit failures suppress the affected operation without fallback.

**Tech Stack:** Python 3 standard library, macOS Keychain, local stdio MCP, Claude/Codex plugin manifests and lifecycle hooks, `unittest`, and JSON configuration.

## Global Constraints

- Do not modify the Remem API, customer portal, cloud namespaces, API-key scopes, or existing cloud records.
- Do not add a browser wizard, local web server, daemon, graphical setup panel, or customer-facing account workflow.
- Do not hardcode namespace meanings such as `personal`, `engineering`, Maya, or Hermes.
- Do not persist a plugin-owned permission model. `off` disables a behavior; it is not read-only authorization.
- Keep API keys out of command arguments, route files, manifests, logs, status output, process listings, and chat. Store named credentials only in macOS Keychain.
- Keep `primary` backward compatible with Keychain service `io.remem.memory`, account `default`.
- Restrict the production origin to `https://api.remem.io`; retain only the existing explicitly enabled loopback development exception.
- Apply test-driven development for every behavior change.
- Keep compatibility aliases operational, but use `sessions` in new user-facing language.
- Release the behavior change as `0.4.0`.

---

## Task 1: Add the routing domain model and secure local storage

**Files:**

- Create: `plugins/remem-memory/scripts/remem_routing.py`
- Create: `tests/test_routing_config.py`

**Interfaces:**

```python
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

def built_in_routes() -> Mapping[str, tuple[RouteTarget, ...]]: ...
def load_routing(data_dir: Path | None = None) -> RoutingConfig: ...
def load_or_initialize_routing(
    data_dir: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> RoutingConfig: ...
def discover_legacy_routing(
    environment: Mapping[str, str] | None = None,
    *,
    distinct_credentials: int = 1,
) -> LegacyDiscovery: ...
def initialize_routing(
    data_dir: Path | None = None,
    environment: Mapping[str, str] | None = None,
    discovery: LegacyDiscovery | None = None,
) -> tuple[RoutingConfig, MigrationOutcome]: ...
def store_routing(
    config: RoutingConfig,
    data_dir: Path | None = None,
) -> None: ...
def update_routing(
    mutator: Callable[[RoutingConfig], RoutingConfig],
    data_dir: Path | None = None,
) -> RoutingConfig: ...
def use_default_routes(config: RoutingConfig) -> RoutingConfig: ...
def parse_target(
    value: str,
    *,
    direction: Literal["read", "write"],
) -> RouteTarget: ...
def resolve_routes(
    config: RoutingConfig,
    *,
    behavior: Literal["recall", "memory", "sessions"],
    client: Literal["codex", "claude"],
) -> tuple[RouteTarget, ...]: ...
def resolve_mcp_connection(
    config: RoutingConfig,
    *,
    client: Literal["codex", "claude"],
) -> Connection: ...
def load_route_health(
    data_dir: Path | None = None,
) -> tuple[RouteHealthRecord, ...]: ...
def record_route_health(
    record: RouteHealthRecord,
    data_dir: Path | None = None,
) -> None: ...
```

`RouteLayer.routes` has three states per behavior:

- missing key: inherit the next layer;
- present non-empty tuple: use the listed target or targets;
- present empty tuple: behavior is off.

The built-in routes are:

```python
{
    "recall": (RouteTarget("primary", "@readable"),),
    "memory": (RouteTarget("primary", "@default"),),
    "sessions": (RouteTarget("primary", "@default"),),
}
```

Configuration limits are fixed and tested:

- maximum file size: 65,536 bytes;
- maximum connections: 16;
- maximum recall targets in persisted configuration: 16;
- `memory` and `sessions`: exactly zero or one target at every layer;
- `@readable`: valid only for `recall`;
- `@default`: valid only for `memory` and `sessions`;
- connection labels: 1–64 printable characters;
- explicit namespace keys: 1–100 non-control characters;
- supported clients: `codex`, `claude`;
- supported behaviors: `recall`, `memory`, `sessions`;
- immutable primary connection: ID `primary`, Keychain account `default`;
- additional connection IDs: `conn_` followed by 32 lowercase hexadecimal characters;
- additional Keychain accounts: `connection:` followed by the same 32 hexadecimal characters.

`route-health.json` is also non-secret and atomically replaced. It is bounded
to 32,768 bytes and 64 records. Each record contains only the seven fields in
`RouteHealthRecord`; `status` is one of `ok`, `credential_error`,
`auth_error`, `permission_error`, `namespace_error`, or `transient_error`.
`detail_code` is a fixed internal code of at most 64 ASCII characters, and
`observed_at` is a UTC RFC 3339 timestamp. No API body, recalled content,
credential, Keychain account, or free-form exception string is stored.

- [ ] Write failing tests for built-in route resolution, client precedence,
      explicit Off, separate MCP selection, strict target validation,
      read/write selector direction, write-route arity, immutable `primary`,
      deterministic JSON, revision increments, bounded non-secret health
      storage, and `routes use-default` semantics.

```python
def test_client_off_override_beats_global_route(self):
    config = routing_config(
        global_routes={"memory": (target("primary", "default"),)},
        client_routes={"claude": {"memory": ()}},
    )
    self.assertEqual(
        (),
        remem_routing.resolve_routes(
            config, behavior="memory", client="claude"
        ),
    )

def test_use_default_preserves_connections_and_mcp_selection(self):
    reset = remem_routing.use_default_routes(config)
    self.assertEqual({}, reset.global_routes.routes)
    self.assertEqual({}, reset.client_routes)
    self.assertEqual(config.connections, reset.connections)
    self.assertEqual(config.mcp_connections, reset.mcp_connections)
```

- [ ] Run the focused tests and confirm they fail because the routing module does not exist.

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_routing_config -v
```

Expected: import failure for `remem_routing`.

- [ ] Implement immutable dataclasses, strict parsing/validation, built-in resolution, client override resolution, MCP connection resolution, and pure update helpers.
- [ ] Implement `routes.json` storage under the existing private data directory with directory mode `0700`, file mode `0600`, symlink refusal, advisory locking for read-modify-write, bounded reads, `fsync`, and atomic `os.replace`.
- [ ] Keep non-secret observed health in a separate bounded `route-health.json` so health updates never change routing revision or invalidate queued work.
- [ ] Reject malformed, oversized, partially written, version-mismatched, or referentially invalid files rather than silently using defaults.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/scripts/remem_routing.py tests/test_routing_config.py
git commit -m "feat(routing): add secure route configuration"
```

## Task 2: Add one-time legacy namespace migration

**Files:**

- Modify: `plugins/remem-memory/scripts/remem_routing.py`
- Modify: `tests/test_routing_config.py`

**Migration contract:**

- Import `REMEM_MEMORY_PERSONAL_NAMESPACE` once as the global `memory` target on `primary`.
- Import `REMEM_MEMORY_ENGINEERING_NAMESPACE` once as the global `sessions` target on `primary`.
- Never infer a namespace meaning.
- Never import `REMEM_DEFAULT_NAMESPACE`; record a deprecation for CLI/status display.
- Persist `legacy_namespace_migration_completed=True` even when no legacy variables exist.
- Once the marker exists, legacy variables never affect routing again, including after `routes use-default`.
- An ordinary one-primary-credential setup preserves the current global mode.
- The installer reports the number of genuinely distinct usable credentials
  it discovered. If a legacy source and canonical Keychain contain the same
  key, it compares them only in memory with `hmac.compare_digest` and counts
  them as one credential. It never persists a key hash or fingerprint. More
  than one distinct credential is ambiguous because legacy configuration
  cannot associate one with a behavior.
- A destination conflict exists only when two supported legacy sources
  provide different non-empty namespace keys for the same behavior. The
  current supported environment has one source per behavior, so this rule is
  defensive and must not treat different `memory` and `sessions`
  destinations as a conflict.
- Either ambiguity sets `migration_write_blocked=True`. Effective automatic
  writes stay suppressed until `routes use-default`, or until both global
  write behaviors have explicit entries (`memory` and `sessions`, each a
  destination or Off). A client-only edit and a partial global edit do not
  clear the block.
- Migration is local and credential-free. It never calls Remem or edits shell startup files.

- [ ] Add failing migration tests for clean initialization, each legacy variable independently, both variables, deprecated `REMEM_DEFAULT_NAMESPACE`, reloading with changed environment, `routes use-default`, ambiguous credentials, and secret-free migration output.

```python
def test_legacy_environment_is_imported_only_once(self):
    first, _ = remem_routing.initialize_routing(
        self.data_dir,
        {"REMEM_MEMORY_PERSONAL_NAMESPACE": "default"},
    )
    second, _ = remem_routing.initialize_routing(
        self.data_dir,
        {"REMEM_MEMORY_PERSONAL_NAMESPACE": "changed"},
    )
    self.assertEqual(
        "default",
        remem_routing.resolve_routes(
            second, behavior="memory", client="codex"
        )[0].namespace,
    )
    self.assertTrue(first.legacy_namespace_migration_completed)
```

- [ ] Run the focused tests and confirm the new migration assertions fail.
- [ ] Implement `MigrationOutcome`, one-time initialization, durable marker
      handling, deprecation recording, exact credential/destination ambiguity
      detection, and the two explicit unblock paths.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/scripts/remem_routing.py tests/test_routing_config.py
git commit -m "feat(routing): migrate legacy namespaces once"
```

## Task 3: Make credentials connection-aware without weakening transport

**Files:**

- Modify: `plugins/remem-memory/scripts/remem_api.py`
- Modify: `tests/test_remem_memory_hook.py`
- Modify: `tests/test_cli_security_boundaries.py`

**Interfaces:**

```python
def resolve_keychain_api_key(
    account: str,
    *,
    keychain: Keychain | None = None,
) -> str | None: ...

def store_keychain_api_key(
    account: str,
    value: str,
    *,
    keychain: Keychain | None = None,
) -> None: ...

def resolve_connection_api_key(
    connection: Connection,
    *,
    environment: Mapping[str, str] | None = None,
    keychain: Keychain | None = None,
) -> str | None: ...
```

Compatibility behavior:

- `resolve_api_key()` and `store_api_key()` remain wrappers for account `default`.
- The ambient legacy `REMEM_API_KEY` value may select only `primary`; it never
  replaces a named connection.
- `resolve_connection_api_key()` resolves a selected connection from Keychain
  (or the ambient legacy value for `primary`) in the trusted parent process.
- `REMEM_API_KEY_FD` does not select or override a connection. After routing,
  the trusted parent may place the already-selected primary or named
  connection credential in that anonymous descriptor for exactly one worker
  or MCP child. The child consumes the descriptor without re-resolving a
  connection.
- A named connection reads only its opaque Keychain account.
- Error text never includes a credential, opaque account ID, or recalled content.
- Descriptor transport remains anonymous, one-use, bounded, and closed after handoff.

- [ ] Add failing tests proving different accounts resolve different keys,
      the primary ambient override cannot replace a named connection, the
      trusted descriptor carries the specifically selected named credential
      without selecting another connection, compatibility wrappers still
      target `default`, and errors/output remain secret-free.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_remem_memory_hook \
  tests.test_cli_security_boundaries -v
```

Expected: failures for missing account-aware APIs.

- [ ] Implement account validation and account-aware Keychain access while preserving all origin, TLS, redirect, proxy, and redaction controls.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/scripts/remem_api.py tests/test_remem_memory_hook.py tests/test_cli_security_boundaries.py
git commit -m "feat(auth): isolate credentials by connection"
```

## Task 4: Add the routing and connection CLI

**Files:**

- Modify: `scripts/remem_memory.py`
- Modify: `tests/test_remem_memory_cli.py`
- Modify: `tests/test_cli_security_boundaries.py`

**Commands:**

```text
remem-memory routes use-default
remem-memory routes show [--client codex|claude] [--json]
remem-memory routes set recall --from CONNECTION/NAMESPACE [CONNECTION/NAMESPACE ...]
remem-memory routes set recall --off
remem-memory routes set memory --to CONNECTION/NAMESPACE|off
remem-memory routes set sessions --to CONNECTION/NAMESPACE|off
remem-memory routes set recall --off --client codex|claude
remem-memory routes set memory --to CONNECTION/NAMESPACE|off --client codex|claude
remem-memory routes set sessions --to CONNECTION/NAMESPACE|off --client codex|claude
remem-memory connections list [--json]
remem-memory connections add NAME
remem-memory connections use NAME --client codex|claude
remem-memory doctor [--json]
```

CLI rules:

- When only `primary` exists, an explicit namespace may omit the `primary/` prefix.
- `routes show` always prints `connection/selector`.
- `connections add` reads the key through `getpass.getpass`; it never accepts a key argument.
- The add transaction persists `configured:false`, writes and verifies the Keychain item, then marks it configured. Re-running the same label resumes an interrupted add.
- Routing rejects an unconfigured connection.
- `connections use` changes only explicit MCP credential selection for one client.
- `routes use-default` clears custom automatic global/client routes and the migration write block, but preserves connections, MCP selections, and the completed migration marker.
- `routes show` prints the effective global routes, each requested client
  override/inheritance result, global mode, migration write block, connection
  health, and the last fixed-code authorization result for each affected
  route. It never prints free-form API bodies.
- `status` prints the same effective route summary in compact form plus
  sensitivity and configured/missing connection counts.
- `doctor` is read-only: validate storage, credentials, namespace readability
  with a metadata-only/read-only API check where the credential permits it,
  runtime, client registrations, MCP startup, and hook presence without
  canary writes, query-result content, or recalled text.
- Exit codes: `0` healthy/success, `1` failed doctor checks or unavailable required credential, `2` invalid invocation.

- [ ] Add failing parser and command tests for every command form, target validation, client precedence, interrupted connection recovery, non-destructive doctor, deterministic JSON, stable human output, and unchanged `mode`/`sensitivity` commands.
- [ ] Add security tests proving keys do not enter argv, environment for another connection, `routes.json`, stdout, stderr, or exceptions.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_remem_memory_cli \
  tests.test_cli_security_boundaries -v
```

Expected: unknown-command failures for `routes`, `connections`, and `doctor`.

- [ ] Implement strict manual argument parsing without adding a dependency.
- [ ] Implement connection add/list/use and route show/set/reset against atomic routing updates.
- [ ] Extend `status` with mode, sensitivity, compact effective global/client
      routes, effective write-block state, configured/missing connection
      counts, and routing validity without printing opaque account IDs.
- [ ] Implement `routes show` and doctor reporting against the bounded
      `RouteHealthRecord` interface from Task 1.
- [ ] Ensure hooks never print migration warnings to hook stdout; expose them only through `status`, `routes show`, and `doctor`.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add scripts/remem_memory.py tests/test_remem_memory_cli.py tests/test_cli_security_boundaries.py
git commit -m "feat(cli): configure routes and connections"
```

## Task 5: Route automatic recall and durable conversation memory

**Files:**

- Modify: `plugins/remem-memory/scripts/remem_memory_hook.py`
- Modify: `plugins/remem-memory/scripts/memory_policy.py`
- Modify: `plugins/remem-memory/scripts/remem_api.py`
- Modify: `plugins/remem-memory/hooks/hooks.json`
- Modify: `tests/test_remem_memory_hook.py`
- Modify: `tests/test_memory_policy.py`
- Modify: `tests/test_plugin_contract.py`

**Runtime behavior:**

- Every hook invocation identifies `codex` or `claude`. The shared hook
  bootstrap examines the original `${CLAUDE_PLUGIN_ROOT}` token before
  fallback: a resolved absolute plugin root means `claude`; an unresolved
  dollar-prefixed token means `codex`. It appends the resulting explicit
  `--harness` argument to `remem_memory_hook.py`. The hook parser rejects any
  missing/unknown value.
- `UserPromptSubmit` resolves the effective `recall` route before any credential is loaded.
- Recall targets group by connection. `@readable` calls
  `RememAPI.query(..., namespaces=None)`, and `query` omits the `namespaces`
  JSON member entirely. Explicit sources pass a non-empty list and send only
  those namespace keys.
- Merge all connection results under one global cap of four.
- Deduplicate first by stable document/chunk identity, otherwise by normalized content SHA-256.
- Order by descending score, then configured connection order, namespace order, and original result order.
- One failed source does not prevent other sources from contributing.
- `RememAPIError` exposes a fixed non-secret `kind`:
  `auth` for 401, `permission` for 403, `namespace` for 404, `request` for
  other 400/422 responses, and `transient` for timeouts/network failures,
  429, 500, 502, 503, or 504. It never includes a response body.
- `auth`, `permission`, `namespace`, and `request` do not retry or fall back.
- `transient` receives at most three total attempts with injected sleeps of
  0.25 and 0.5 seconds. Every attempt uses the same query, route, namespace
  list, write destination, source ID, and idempotency value.
- Durable conversation capture resolves only `memory`; Off, `recall-only`, global `off`, off-record, and migration write block suppress it.
- An explicit namespace is always sent. `@default` omits the namespace so Remem chooses the key default.

- [ ] Add failing tests for built-in recall, omitted `@readable` namespace,
      multi-source grouping, two-connection isolation, global cap four,
      deterministic deduplication, partial-source failure, fixed error-kind
      classification, no API-body leakage, explicit failure without fallback,
      exact transient retry attempts/backoff, stable idempotency, explicit
      hook client bootstrap, client override, memory Off, `@default`, and
      explicit memory namespace.
- [ ] Add tests showing global `recall-only`, global `off`, off-record, and migration blocking override the resolved route.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_remem_memory_hook \
  tests.test_memory_policy \
  tests.test_plugin_contract -v
```

Expected: new routing assertions fail against the single-key/single-namespace path.

- [ ] Inject routing and connection credential resolvers into hook dependencies.
- [ ] Replace legacy personal/engineering namespace selection with neutral recall and memory resolution.
- [ ] Add bounded HTTP-status classification and injectable retry timing to
      `remem_api.py`; manual helpers in Task 7 reuse this transport.
- [ ] Implement global merge/deduplication and bounded health recording.
- [ ] Preserve fail-open behavior for the user’s main task and all current privacy filters.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/scripts/remem_memory_hook.py plugins/remem-memory/scripts/memory_policy.py plugins/remem-memory/scripts/remem_api.py plugins/remem-memory/hooks/hooks.json tests/test_remem_memory_hook.py tests/test_memory_policy.py tests/test_plugin_contract.py
git commit -m "feat(hooks): route recall and durable memory"
```

## Task 6: Route session checkpoints and roll-ups safely in background jobs

**Files:**

- Modify: `plugins/remem-memory/scripts/remem_memory_hook.py`
- Modify: `plugins/remem-memory/scripts/auto_memory_hook.py`
- Modify: `tests/test_remem_memory_hook.py`
- Modify: `tests/test_auto_memory_hook.py`

**Queued job contract:**

```python
@dataclass(frozen=True)
class RoutedBackgroundEvent:
    schema_version: int
    id: str
    client: Literal["codex", "claude"]
    behavior: Literal["memory", "sessions"]
    lifecycle_mode: str
    connection_id: str
    namespace: str
    route_revision: int
    session_id: str
    payload: Mapping[str, Any]
    off_record_seen: bool
```

`schema_version` is `1`; `id` is a 32-character lowercase hexadecimal UUID;
`lifecycle_mode` is one of the existing bounded background modes; `session_id`
is at most 200 characters; and `payload` is the existing output of
`_background_payload`, not a path or external reference. Queue files remain
private and atomic, gain a 262,144-byte read/write bound, and retain the
existing maximum of 128 events. Oversized, malformed, unknown-version, or
secret-bearing events are rejected and never executed.

The job contains no credential. Stop may enqueue separate `memory` and
`sessions` jobs because they can use different connections and destinations.
Immediately before a write, the worker reloads routing and verifies:

- global mode still permits the behavior;
- off-record is still false;
- route revision is unchanged;
- connection and destination exactly match the current effective route;
- the connection is configured.

Any mismatch discards the stale job. It never reroutes. The worker resolves only the selected connection credential and supplies the resolved explicit namespace or omits namespace for `@default`.

- [ ] Add failing tests for separate Stop jobs, exact event normalization,
      malformed/oversized/secret-bearing event rejection, queue size bounds,
      different credentials/destinations, `sessions` Off, `recall-only`,
      global Off, off-record, stale revision, changed connection, changed
      destination, and missing credential.
- [ ] Add tests that existing checkpoint cadence, milestone metadata, session IDs, project metadata, roll-up triggers, idempotency, retries, and cleanup remain intact.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_remem_memory_hook \
  tests.test_auto_memory_hook -v
```

Expected: failures because jobs do not yet carry neutral route identity/revision.

- [ ] Resolve routes before enqueue and split memory/session jobs.
- [ ] Make `auto_memory_hook.py` consume the resolved job target rather than independently reading namespace environment variables.
- [ ] Isolate worker state by session and connection and pass only the selected credential through the existing descriptor mechanism.
- [ ] Preserve the same idempotency identifier across bounded transient retries.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/scripts/remem_memory_hook.py plugins/remem-memory/scripts/auto_memory_hook.py tests/test_remem_memory_hook.py tests/test_auto_memory_hook.py
git commit -m "feat(sessions): route checkpoints and rollups"
```

## Task 7: Put manual helpers and the Codex wrapper on the same router

**Files:**

- Modify: `scripts/remem_checkpoint.py`
- Modify: `scripts/remem_rollup.py`
- Modify: `scripts/remem_recall.py`
- Modify: `scripts/remem_codex_wrapper.py`
- Modify: `scripts/remem_memory.py`
- Modify: `tests/test_manual_helper_transport.py`
- Modify: `tests/test_recall_cli.py`
- Modify: `tests/test_codex_wrapper.py`

**Behavior:**

- Canonical manual commands accept `--client codex|claude` and default to
  `codex` for compatibility with the existing Codex-named wrapper and aliases.
- `checkpoint --ingest` and roll-up ingestion use the effective `sessions`
  route for that explicit client.
- Manual recall uses the effective `recall` route and the same global merge cap/deduplication rules.
- The Codex wrapper re-resolves live routing instead of capturing one credential/namespace for the entire wrapper lifetime.
- Compatibility aliases delegate to the canonical router.
- `checkpoint` and `rollup` accept an optional explicit `--to
  CONNECTION/NAMESPACE`; `recall` accepts repeatable `--from
  CONNECTION/NAMESPACE`. These are routing intent, not permission. Without
  them, the command uses the effective client route.
- An explicit `--to` or `--from` takes precedence over an Off automatic route.
  Without an explicit target, an Off route exits `1` and never selects a
  default.
- The canonical CLI creates a bounded non-secret JSON route descriptor in an
  anonymous descriptor named by `REMEM_MEMORY_ROUTE_FD`. Its schema is
  `{schema_version, client, behavior, route_revision, connection_id,
  read_namespaces, write_namespace}`; it is at most 4,096 bytes and contains
  exactly one connection. Recall descriptors set `read_namespaces` to `null`
  for `@readable` or a non-empty array for explicit sources and set
  `write_namespace` to `null`. Write descriptors set `read_namespaces` to
  `null` and set `write_namespace` to `null` for `@default` or one explicit
  namespace key.
- Each write helper child receives one route descriptor and that connection's
  credential descriptor. Multi-connection recall spawns one helper child per
  connection, captures each JSON result, and performs the same deterministic
  global four-result merge in the trusted parent. A helper never receives
  another connection's credential.
- Manual and wrapper API calls reuse Task 5's fixed error kinds and retry only
  transient errors with the same target/idempotency. No manual or wrapper
  path falls back.

- [ ] Add failing tests for the explicit/default client, explicit `--to` and
      repeatable `--from` precedence, configured explicit namespace,
      `@default`, named connection isolation, descriptor size/shape,
      multi-process recall fan-in, client override, stale wrapper state, Off
      behavior with and without explicit intent, fixed failure/retry behavior,
      and legacy aliases.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_manual_helper_transport \
  tests.test_recall_cli \
  tests.test_codex_wrapper -v
```

Expected: route-aware assertions fail against current primary-only dispatch.

- [ ] Add and validate `REMEM_MEMORY_ROUTE_FD` alongside the existing
      credential FD transport; consume and close it exactly once.
- [ ] Resolve manual `sessions` and `recall` routes in the canonical CLI, then spawn each helper with only the required credential.
- [ ] Make the Codex wrapper reload routing at each lifecycle boundary and discard stale scheduled work.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add scripts/remem_checkpoint.py scripts/remem_rollup.py scripts/remem_recall.py scripts/remem_codex_wrapper.py scripts/remem_memory.py tests/test_manual_helper_transport.py tests/test_recall_cli.py tests/test_codex_wrapper.py
git commit -m "feat(workflows): share routing across manual helpers"
```

## Task 8: Route explicit MCP connections and remove the hardcoded namespace

**Files:**

- Modify: `plugins/remem-memory/.mcp.json`
- Modify: `plugins/remem-memory/scripts/remem_mcp_launcher.py`
- Modify: `plugins/remem-memory/mcp/remem_mcp/server.py`
- Modify: `plugins/remem-memory/mcp/PROVENANCE.json`
- Modify: `scripts/install_remem_memory.py`
- Modify: `tests/test_remem_memory_cli.py`
- Modify: `tests/test_plugin_contract.py`
- Modify: `tests/test_packaging_docs.py`
- Modify: `tests/test_installer.py`

**Behavior:**

- The one shared `.mcp.json` bootstrap derives the client from its original
  root token before fallback, using the same exact rule as hooks: resolved
  absolute `${CLAUDE_PLUGIN_ROOT}` is `claude`; unresolved dollar-prefixed
  token is `codex`. It appends `--client codex|claude` to the launcher.
- The installer’s `_MCP_BOOTSTRAP` uses the same derivation when writing the
  Codex MCP registration. The launcher requires and validates the client.
- It resolves only that client’s selected MCP connection and passes only that credential.
- An explicit MCP read uses supplied namespaces, or all key-readable namespaces when omitted.
- An explicit MCP write uses a supplied namespace, or the selected key’s server-defined default when omitted.
- Explicit MCP calls do not inherit automatic `memory` or `sessions` destinations.
- Remove `REMEM_DEFAULT_NAMESPACE` from child-environment forwarding and stop injecting `default`.
- MCP requests use the Task 5 failure matrix: no retry for 400, 401, 403,
  404, or 422; at most three total attempts with 0.25/0.5-second backoff for
  httpx timeouts/network errors, 429, 500, 502, 503, or 504. Retries retain
  the same method, path, parameters, body, source ID, and explicit namespace.
  Returned MCP error text is a fixed status/kind and never includes the API
  response body.
- Recompute the bundled server SHA-256 and update both `PROVENANCE.json` and `_BUNDLE_HASHES`.

- [ ] Add failing tests for root-token client derivation in the shared
      descriptor and installer registration, per-client MCP selection,
      primary default, named credential isolation, omitted write namespace,
      explicit write namespace, omitted read namespaces, exact retry/no-retry
      behavior, stable payload/idempotency, response-body redaction,
      fixed-origin policy, bundle integrity, and absence of
      `REMEM_DEFAULT_NAMESPACE`.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_remem_memory_cli \
  tests.test_plugin_contract \
  tests.test_packaging_docs \
  tests.test_installer -v
```

Expected: failures for missing client selection and current forced `default`.

- [ ] Add concrete root-token client derivation to `.mcp.json` and the
      installer registration, then require the explicit client in the
      launcher parser.
- [ ] Resolve the selected MCP connection and preserve the one-use credential FD transport.
- [ ] Change bundled MCP payload creation so a missing namespace remains omitted.
- [ ] Recompute and validate provenance hashes.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add plugins/remem-memory/.mcp.json plugins/remem-memory/scripts/remem_mcp_launcher.py plugins/remem-memory/mcp/remem_mcp/server.py plugins/remem-memory/mcp/PROVENANCE.json scripts/install_remem_memory.py tests/test_remem_memory_cli.py tests/test_plugin_contract.py tests/test_packaging_docs.py tests/test_installer.py
git commit -m "feat(mcp): select credentials per client"
```

## Task 9: Integrate idempotent installer migration

**Files:**

- Modify: `scripts/install_remem_memory.py`
- Modify: `scripts/remem_memory.py`
- Modify: `plugins/remem-memory/scripts/remem_memory_hook.py`
- Modify: `plugins/remem-memory/scripts/remem_mcp_launcher.py`
- Modify: `tests/test_installer.py`
- Modify: `tests/test_remem_memory_cli.py`
- Modify: `tests/test_remem_memory_hook.py`

**Installer ordering:**

1. Complete preflight and repository validation.
2. Load legacy configuration and bridge a discovered canonical credential
   before any client/plugin mutation.
3. Prepare harness directories, install aliases, and probe the bundled MCP.
4. Install and verify Codex and Claude plugin/MCP/hook registrations.
5. Run the same local, credential-free `initialize_routing`, supplying the
   exact `LegacyDiscovery` count/candidates observed in step 2.
6. Persist migration status before any legacy MCP/plugin cleanup.
7. Leave the current mode unchanged for the unambiguous simple setup.
8. Keep ambiguous writes effectively blocked until explicit CLI resolution.

The installer must not contact Remem to infer routing, create namespaces, modify scopes, write memories, or store keys in startup files.

- [ ] Generalize the fake Keychain to a `(service, account)` mapping.
- [ ] Add failing tests for fresh install, upgrade from `0.3.2`, one-time
      legacy import, credential-bridge-before-mutation ordering,
      routing-initialization-before-cleanup ordering, interrupted rerun,
      ambiguous multi-credential blocking, no-variable simple setup, no API
      call, no shell-file key write, runtime initialization through the CLI,
      hook, and MCP launcher when the installer was skipped, and existing
      alias preservation.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_installer \
  tests.test_remem_memory_cli \
  tests.test_remem_memory_hook -v
```

Expected: migration assertions fail before installer integration.

- [ ] Import and call the shared routing initializer at the exact post-client-
      verification, pre-legacy-cleanup seam.
- [ ] Make the canonical CLI, hook entrypoint, and MCP launcher call
      `load_or_initialize_routing` before route resolution so an upgrade that
      skips the installer still performs the same one-time local migration.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add scripts/install_remem_memory.py scripts/remem_memory.py plugins/remem-memory/scripts/remem_memory_hook.py plugins/remem-memory/scripts/remem_mcp_launcher.py tests/test_installer.py tests/test_remem_memory_cli.py tests/test_remem_memory_hook.py
git commit -m "feat(installer): initialize routing safely"
```

## Task 10: Publish neutral documentation and version `0.4.0`

**Files:**

- Modify: `README.md`
- Modify: `.codex/INSTALL.md`
- Modify: `docs/README.codex.md`
- Modify: `docs/SECURITY.md`
- Modify: `.claude-plugin/marketplace.json`
- Modify: `plugins/remem-memory/.claude-plugin/plugin.json`
- Modify: `plugins/remem-memory/.codex-plugin/plugin.json`
- Modify: `plugins/remem-memory/skills/remem-memory/SKILL.md`
- Modify: `plugins/remem-memory/skills/session-memory/SKILL.md`
- Modify: `codex/skills/remem-memory/SKILL.md`
- Modify: `codex/skills/remem-dev-sessions/SKILL.md`
- Modify: `codex/skills/remem-session-memory/SKILL.md`
- Modify: `scripts/install_remem_memory.py`
- Modify: `tests/test_packaging_docs.py`
- Modify: `tests/test_plugin_contract.py`
- Modify: `tests/test_installer.py`

**Documentation contract:**

- Lead with the simple one-key install: install, authenticate, trust hooks in Codex Desktop when prompted, restart/reload the client, and run `status`/`doctor`.
- Explain that most users need no routing setup.
- Document `recall`, `memory`, and `sessions` without prescribing namespace names.
- Document custom CLI routes and per-client overrides.
- State that API-key grants and server default are controlled in Remem, while the plugin only selects routes.
- Explain that true read-only isolation requires a read-only Remem key as a separate connection.
- State that Claude Code plugin updates require marketplace update/plugin update or reinstall as appropriate; restarting alone does not fetch a new version.
- Explain Codex Desktop hook trust and CLI behavior.
- Retain the README-led agent installation flow.
- Retain compatibility aliases with a deprecation explanation.
- Do not mention Maya, Hermes, the user’s personal namespaces, or private deployment details.

- [ ] Add failing packaging/documentation tests for version consistency, neutral route vocabulary, command examples, simple-path prominence, hook trust, Claude update steps, API-key authority wording, compatibility aliases, and absence of private terms.
- [ ] Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_packaging_docs \
  tests.test_plugin_contract \
  tests.test_installer -v
```

Expected: failures while manifests remain at `0.3.2` and docs omit routing.

- [ ] Rewrite the public setup and routing sections concisely.
- [ ] Update the packaged canonical/compatibility skills and all three
      Codex-side canonical/legacy aliases so no old namespace-variable
      guidance or engineering-as-destination assumption remains.
- [ ] Bump every declared/package/installer version to `0.4.0` and assert exact consistency.
- [ ] Run the focused tests and confirm green.
- [ ] Commit:

```bash
git add README.md .codex/INSTALL.md docs/README.codex.md docs/SECURITY.md .claude-plugin/marketplace.json plugins/remem-memory/.claude-plugin/plugin.json plugins/remem-memory/.codex-plugin/plugin.json plugins/remem-memory/skills/remem-memory/SKILL.md plugins/remem-memory/skills/session-memory/SKILL.md codex/skills/remem-memory/SKILL.md codex/skills/remem-dev-sessions/SKILL.md codex/skills/remem-session-memory/SKILL.md scripts/install_remem_memory.py tests/test_packaging_docs.py tests/test_plugin_contract.py tests/test_installer.py
git commit -m "docs: release generic routing in 0.4.0"
```

## Task 11: Full QA, review, release, and local consumption

**Files:**

- Inspect all changed files.
- Modify only defects found by tests or review.

- [ ] Run the entire regression suite from a clean process:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Expected: all tests pass.

- [ ] Run syntax and manifest validation:

```bash
python3 -m compileall -q scripts plugins/remem-memory/scripts plugins/remem-memory/mcp/remem_mcp
python3 -m json.tool .claude-plugin/marketplace.json >/dev/null
python3 -m json.tool plugins/remem-memory/.claude-plugin/plugin.json >/dev/null
python3 -m json.tool plugins/remem-memory/.codex-plugin/plugin.json >/dev/null
python3 -m json.tool plugins/remem-memory/.mcp.json >/dev/null
python3 -m json.tool plugins/remem-memory/hooks/hooks.json >/dev/null
python3 -m json.tool plugins/remem-memory/mcp/PROVENANCE.json >/dev/null
python3 plugins/remem-memory/scripts/remem_mcp_launcher.py --client codex --probe
python3 plugins/remem-memory/scripts/remem_mcp_launcher.py --client claude --probe
```

Expected: every command exits `0`; both probes validate the declared
`PROVENANCE.json` files and `_BUNDLE_HASHES` before starting the isolated MCP
runtime.

- [ ] Run security-focused suites again:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_cli_security_boundaries \
  tests.test_manual_helper_transport \
  tests.test_plugin_contract -v
```

Expected: all tests pass.

- [ ] Have an independent reviewer audit spec compliance, credential isolation, migration behavior, fail-closed routing, and backward compatibility.
- [ ] Fix every material finding with a failing regression test first, rerun focused tests, and commit fixes.
- [ ] Verify `git diff --check`, version consistency, and a clean working tree after commits.
- [ ] Push `codex/generic-namespace-routing` to `origin` for an auditable branch.
- [ ] Fetch `origin/master`, verify it is still an ancestor of the reviewed
      branch, and fast-forward `origin/master` with
      `git push origin HEAD:master`. Stop rather than force-push if the remote
      advanced incompatibly.
- [ ] Treat that versioned master commit as the `0.4.0` marketplace release.
      This repository has no release-tag or GitHub Release convention, so do
      not invent one.
- [ ] In the existing clean local consumer checkout, pull `master`
      fast-forward and run `./install-codex-skill.sh`; verify both clients
      report the exact reviewed `0.4.0` commit/version.
- [ ] Run:

```text
~/.local/bin/remem-memory status
~/.local/bin/remem-memory routes show
~/.local/bin/remem-memory routes show --client codex
~/.local/bin/remem-memory routes show --client claude
~/.local/bin/remem-memory doctor
```

Expected for the current machine before custom routing: valid `primary`, hooks/MCP registered, and automatic writes still held at the existing safety setting until explicit current-user routes are confirmed.

- [ ] Configure this machine through the public CLI only:

```bash
~/.local/bin/remem-memory routes set recall --from primary/@readable
~/.local/bin/remem-memory routes set memory --to primary/default
~/.local/bin/remem-memory routes set sessions --to primary/engineering
~/.local/bin/remem-memory routes show --client codex
~/.local/bin/remem-memory routes show --client claude
```

Use the actual namespace keys already confirmed by the user. Do not create or modify Remem namespaces.

- [ ] Verify routed recall from both client identities without logging recalled
      content:

```bash
~/.local/bin/remem-memory recall --client codex --query "Remem Memory routing release continuity" --no-log
~/.local/bin/remem-memory recall --client claude --query "Remem Memory routing release continuity" --no-log
```

- [ ] Create a bounded QA checkpoint and roll-up through the public CLI:

```bash
remem_qa_dir="$(mktemp -d)"
~/.local/bin/remem-memory checkpoint --client codex --project remem-memory --session-id routing-release-0.4.0 --kind milestone --summary "Verified generic namespace routing release." --log-file "$remem_qa_dir/checkpoints.ndjson" --ingest --return-id
~/.local/bin/remem-memory rollup --client codex --project remem-memory --session-id routing-release-0.4.0 --kind final --summary "Completed local Codex and Claude routing verification." --log-file "$remem_qa_dir/checkpoints.ndjson" --ingest --return-id
```

Inspect only returned non-secret document IDs and route-health status needed
to prove both writes used `primary/engineering`; do not print document
content or credentials.
- [ ] Switch global mode from `recall-only` to `auto` only after route display, doctor, key authorization, and destination verification succeed.
- [ ] Restart/reload both clients if their plugin loaders require it and confirm installed version `0.4.0`.
- [ ] If QA uncovers a defect, add only the exact files changed for that defect
      with individual `git add PATH` arguments and commit them as
      `fix: complete generic routing release QA`. If QA finds no defect, do
      not create an empty release commit.
