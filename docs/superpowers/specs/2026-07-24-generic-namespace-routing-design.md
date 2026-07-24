# Remem Memory Generic Namespace Routing Design

Date: 2026-07-24  
Status: Approved for implementation

## Problem

Remem Memory currently names two automatic write paths `personal` and
`engineering`, accepts optional namespace environment variables for each, and
falls back to the API key's default namespace when either variable is unset.
That behavior is convenient for one namespace, but it can silently mix
conversation memory with session checkpoints and roll-ups when a key can
access several namespaces.

The namespace names and meanings belong to each Remem user. The plugin must
not assume that a namespace is named `engineering`, `personal`, `work`, or
anything else. It also must not create a second read/write permission system
that can disagree with the API key configuration in Remem.

## Goals

1. Preserve a zero-friction path for the common case: one API key and one
   effective namespace.
2. Add CLI-only custom routing for users with several namespaces, workspaces,
   keys, or client-specific behavior.
3. Route by neutral plugin behavior instead of namespace meaning.
4. Keep API key grants and the key's default namespace as the sole
   authorization and default-write authority.
5. Preserve automatic recall, durable conversation memory, checkpoints,
   roll-ups, explicit MCP tools, and the existing Codex and Claude Code
   lifecycle integrations.
6. Make every routing intent visible, resolve server-owned defaults when the
   API exposes them, and make invalid routes fail without redirecting data.
7. Allow normal conversations to recall useful session continuity without
   forcing both data types into the same write namespace.
8. Keep the current one-plugin, local-stdio, macOS Keychain architecture.

## Non-goals

- No Remem API or portal implementation change.
- No installation-, configuration-, or migration-time mutation of Remem
  accounts, namespaces, API-key scopes, or existing cloud data. Normal
  user-authorized memory writes remain part of runtime behavior.
- No visual setup panel, browser wizard, local web server, daemon, or
  customer-facing Remem portal workflow.
- No built-in personal, engineering, Maya, persona, or profile semantics.
- No plugin-owned `read_only` or `read_write` permission flags.
- No automatic namespace creation or inference from namespace names.
- No general content rules engine.
- No project-path routing in the first release.
- No automatic movement, copying, or deletion of existing Remem documents.

## Authority boundary

Remem and its API keys remain authoritative for:

- which workspace a credential reaches;
- which namespaces the key can read;
- which namespaces the key can write;
- the key's default write namespace; and
- whether a request is permitted at execution time.

The plugin is authoritative only for routing intent:

- which namespaces should be searched for a behavior;
- where durable conversation memory should be sent;
- where session continuity should be sent;
- whether an automatic behavior is enabled; and
- which credential connection a client or route should use.

The plugin must not persist a duplicate permission grant. It may display live
or last-observed API capability information and reject an obviously invalid
route during validation, but the Remem API response remains the source of
truth. A `403` must be reported as an API-key scope problem, not as a local
read-only setting.

Disabling an automatic route is a behavior choice, not an authorization
control. It does not make a credential read-only and must not be labeled that
way.

## Neutral routing model

The plugin exposes three behavior routes:

| Route | Direction | Meaning |
| --- | --- | --- |
| `recall` | Read from zero or more sources | Context searched before an answer |
| `memory` | Write to one destination or Off | Durable preferences, decisions, facts, and other selected conversation memory |
| `sessions` | Write to one destination or Off | Checkpoints, milestone summaries, and session roll-ups |

`sessions` replaces `engineering` in new user-facing configuration. The
session pipeline remains distinct because it has different lifecycle
triggers, cadence, metadata, and roll-up behavior. Routing changes its
destination; it does not collapse it into ordinary conversational capture.

A recall route can include the namespace receiving session data. This allows a
normal Codex or Claude Code conversation to benefit from prior checkpoints and
roll-ups while new session data remains stored separately.

## Connections

A connection is one credential stored in macOS Keychain for the fixed Remem
production API origin. Most users have one implicit connection named `primary`
and never manage connections directly. The existing explicitly enabled
loopback-only development exception remains available for development, but a
connection or route can never select an arbitrary API origin.

Additional connections are an advanced CLI feature for:

- different Remem workspaces or accounts;
- different API key scopes for different clients; or
- stronger least-privilege separation.

Connection labels are non-secret local metadata. Keychain accounts use stable,
opaque identifiers so renaming a label cannot orphan or duplicate a
credential. The existing `io.remem.memory` / `default` item becomes the
backward-compatible credential source for the initial `primary` connection.

The bare legacy `REMEM_API_KEY` override may affect only `primary`. It must
never globally replace every configured connection.

## Route targets

Routes use a connection and either a reserved selector or an explicit
namespace key:

- `@readable`: every namespace the selected key is allowed to read;
- `@default`: the selected key's current server-defined default write
  namespace;
- an explicit namespace key such as `default`, `work`, or `project-a`; or
- `off` for the two automatic write behaviors.

`@readable` is valid only for reads. `@default` and explicit namespace keys are
valid for one write destination. Automatic writes never fan out. The CLI may
display the namespace currently resolved by `@default` when Remem exposes it
to that credential; otherwise it displays the routing intent `@default`
without guessing.

The simple configuration is:

```text
recall   <- primary/@readable
memory   -> primary/@default
sessions -> primary/@default
```

This delegates access and default-write changes to the Remem key. A user who
changes the key's grants or default namespace in Remem does not need to
maintain a second local permission record.

Custom routing replaces only the desired route:

```text
recall   <- primary/default + primary/project-history
memory   -> primary/default
sessions -> primary/project-history
```

Every explicit write target is included in the Remem request. `@default`
intentionally omits the namespace so the API key's current server default is
used. An authorization or lookup failure on an explicit destination must
never retry through `@default` or another connection.

## Client overrides

Global routes apply to every supported client unless that client has an
explicit override. The first release supports `codex` and `claude`.

Resolution order is:

1. client-specific route override;
2. global route; and
3. the simple built-in route when no custom routing file exists.

There is no content-, model-, persona-, or inferred-project-based routing.

Example:

```text
Global
  recall   <- primary/default + primary/project-history
  memory   -> primary/default
  sessions -> primary/project-history

Claude overrides
  memory   -> off
  sessions -> off

Codex
  inherits the global routes
```

This means Claude's automatic memory and session writers are disabled; it does
not mean Claude is cryptographically read-only. If Claude must be unable to
write through explicit MCP tools as well, the user creates a read-only API key
in Remem, stores it as another connection, and selects that connection for
Claude's recall and MCP process. Remem then enforces the restriction.

MCP launchers and automatic hooks must identify their client explicitly. A
client may select one connection as its MCP connection. That connection
supplies the credential for explicit MCP reads and writes; its Remem grants
govern the available operations. Explicit MCP calls do not inherit the
automatic `memory` or `sessions` destination:

- an explicit read uses the namespaces supplied to the tool, or all namespaces
  readable by the selected key when omitted;
- an explicit write uses the namespace supplied to the tool, or the selected
  key's server-defined default when omitted; and
- the router resolves and transports only the selected MCP connection's
  credential to that MCP process.

## CLI experience

No visual setup surface is added. Existing installation and hidden
authentication remain the simple path.

The proposed command family is:

```text
remem-memory routes use-default
remem-memory routes show [--client codex|claude] [--json]
remem-memory routes set recall --from CONNECTION/NAMESPACE [...]
remem-memory routes set recall --off
remem-memory routes set memory --to CONNECTION/NAMESPACE|off
remem-memory routes set sessions --to CONNECTION/NAMESPACE|off
remem-memory routes set ... --client codex|claude
remem-memory connections list
remem-memory connections add NAME
remem-memory connections use NAME --client codex|claude
remem-memory doctor
```

For route syntax, `CONNECTION/@readable` and `CONNECTION/@default` represent
the reserved selectors. When only `primary` exists, commands may accept a
namespace without the `primary/` prefix, while `routes show` always prints the
fully resolved connection.

`connections add` obtains the key only through a hidden prompt and stores it
in Keychain. Keys are never accepted through chat, command arguments, route
configuration, or plugin manifests. The CLI never writes a key into a shell
startup file; the legacy process-environment override remains supported only
for `primary`.

`connections use` selects the credential used by that client's explicit MCP
tools. It does not alter the client's automatic routes, API key grants, or the
connection used by another client. Without an override, both clients use
`primary`.

Connection and credential deletion are intentionally outside the first
release. API key revocation remains a Remem portal operation, and the plugin
must not silently delete a Keychain credential.

`routes use-default` removes custom global automatic routes and automatic
client route overrides so the built-in simple behavior applies again. It does
not change a client's separately selected MCP connection; resetting that
selection requires the explicit
`connections use primary --client codex|claude` command. It does not persist a
second copy of the defaults or change API key grants or the key's server
default.

`routes show` reports routing intent, connection health, and any last
authorization error without claiming locally stored permissions. Example:

```text
Global routes
  recall:   primary/@readable
  memory:   primary/default
  sessions: primary/project-history

Claude overrides
  memory:   off
  sessions: off

Last API result
  primary/project-history sessions: blocked — key has no write access
```

`doctor` is non-destructive. It verifies configuration shape, Keychain
availability, connection authentication, namespace readability where the API
allows it, client registrations, MCP startup, and hook installation. It does
not perform a canary write or modify API key scopes.

The existing `mode auto|recall-only|off` remains a global safety control:

- `auto` allows configured automatic routes;
- `recall-only` permits recall but suppresses both automatic write routes; and
- `off` suppresses all automatic memory behavior.

The global mode does not alter route configuration or API key permissions.

## Runtime data flow

1. A Codex or Claude adapter receives a lifecycle event with an explicit
   client identifier.
2. The central router classifies the operation as `recall`, `memory`, or
   `sessions`.
3. The router resolves the client override or global route.
4. For each selected automatic route, it resolves only that route's
   connection credential. Explicit MCP calls resolve only the invoking
   client's selected MCP connection.
5. Recall groups sources by connection, sends one query per connection with
   its configured namespace list or the server's all-readable selector, and
   merges the results under one global result cap of four. Results are
   deduplicated by stable document/chunk identity when available and otherwise
   by a content hash, then ordered by score with stable connection and source
   order as deterministic tie-breakers.
6. Memory and session writes send one explicit namespace, except that
   `@default` intentionally delegates to the key's server default.
7. The Remem API independently authorizes the request.
8. The plugin records a bounded non-secret success or failure state for
   `status`.

A Stop event may produce both a durable-memory job and a session job. They
must be queued separately after routing so each worker receives only the
credential and destination required for that job. Each job carries a
non-secret route revision. Immediately before writing, the worker rechecks the
live mode, off-record state, route revision, connection selection, and
destination. A stale or disabled job is discarded; it is never rerouted.

Manual checkpoint, roll-up, wrapper, and MCP paths must use the same router or
an explicitly supplied connection/namespace. They may not retain a separate
implicit namespace implementation.

## Failure behavior

- Missing connection credential: skip only routes using that connection.
- Missing or malformed route: suppress that operation and report an
  unconfigured route.
- Explicit namespace not found: suppress that operation; never fall back.
- API denies read: return no recalled context from that source and continue
  the user's main task.
- API returns `401`, `403`, or a permanent namespace lookup failure: keep the
  destination unchanged, report the credential or key-scope problem, and do
  not retry or redirect the document.
- A transient network failure, `429`, or selected `5xx` response: apply bounded
  retry/backoff using the same source/idempotency identifier and destination.
- A referenced connection becomes unavailable or a client override becomes
  invalid: affected routes stop until reconfigured.
- A key's server default changes: `@default` follows it automatically.
- A key's grants change: the next request follows the server decision; no
  cached local permission may override it.
- One recall source fails: other configured sources may still return results,
  subject to the single global four-result cap.
- `off-record`, `recall-only`, and `off` continue to override routing.

No error path may expose a credential, namespace content, recalled private
text, or another connection's identity beyond its user-assigned label.

## Configuration and compatibility

Routing is stored in the existing private Remem Memory data directory as a
versioned, non-secret, atomically replaced JSON document. Credentials remain
in Keychain. Invalid or partially written configuration is never accepted.

The migration behavior is:

1. Preserve the existing canonical credential as `primary`.
2. Preserve the user's global `mode` and sensitivity.
3. Only when no versioned routing configuration exists, import an explicit
   `REMEM_MEMORY_PERSONAL_NAMESPACE` once into the `memory` route and an
   explicit `REMEM_MEMORY_ENGINEERING_NAMESPACE` once into the `sessions`
   route. After that migration, environment variables never override CLI
   routing and are ignored for route resolution.
4. Retire `REMEM_DEFAULT_NAMESPACE` as a runtime default and emit a
   deprecation warning when it is present during one-time migration. Explicit
   MCP writes may keep supplying a namespace; omitted MCP writes use the API
   key's server default.
5. Do not infer meaning from a discovered namespace or legacy credential.
6. Treat an ordinary installation with one canonical credential and no custom
   namespace variables as the unambiguous simple path; preserve its existing
   mode.
7. If several credentials or conflicting explicit destinations are
   discovered, remain in `recall-only` until the user runs
   `routes use-default` or sets explicit custom routes.
8. Never migrate, rename, copy, or delete cloud data.

Compatibility command and skill aliases remain, but new documentation uses
`sessions` and neutral routing language. Existing project/session metadata
continues to distinguish checkpoint and roll-up records inside their selected
namespace.

## Security properties

- Remem API key grants remain the only hard namespace permission boundary.
- The router may narrow behavior but cannot expand server access.
- A separate read-only connection is required for server-enforced client
  read-only behavior.
- Each worker and MCP process receives only its selected connection
  credential through the existing anonymous one-use descriptor transport.
- Route and connection files contain no key values.
- Automatic writes resolve one destination and never broadcast or fall back.
- The router does not resolve or transport credentials for connections that
  are not selected by the effective route or client MCP assignment. Remem
  grants remain the hard boundary.
- Existing hook trust, fixed API-origin validation, redirect/proxy blocking,
  off-record handling, and credential redaction remain unchanged.

## Test strategy

Implementation uses test-driven development and must cover:

1. Simple one-key routing through `@readable` and `@default`.
2. Explicit recall sources and distinct memory/session destinations.
3. Neutral `sessions` behavior retaining existing checkpoint and roll-up
   metadata and cadence.
4. Global routes and Codex/Claude overrides with deterministic precedence.
5. An automatic route set to Off without representing a permission grant.
6. Multiple connection credentials remaining isolated across hooks, workers,
   MCP, manual helpers, and the Codex wrapper.
7. API permission denial surfacing as a server/key-scope error with no
   fallback.
8. A changed server default being honored by `@default` without local scope
   mutation.
9. Revoked or narrowed key grants taking effect without a stale local
   permission cache.
10. Separate Stop jobs when memory and sessions use different connections.
11. Stale queued jobs being discarded after mode, off-record, route revision,
    or connection changes.
12. One global bounded, deduplicated, deterministic recall merge across
    multiple connections.
13. Atomic configuration writes, malformed-config rejection, and secret-free
    status/JSON output.
14. Legacy environment-variable translation, retirement of
    `REMEM_DEFAULT_NAMESPACE`, and ambiguous migration remaining
    recall-only.
15. Global mode and off-record behavior overriding every route.
16. Full Codex and Claude hook, plugin, MCP, packaging, installer, and
    compatibility regression suites.

## Acceptance criteria

- A one-key, one-namespace user completes installation without learning the
  routing model and can restore the simple behavior with one command.
- A multi-namespace user can configure recall, durable memory, and session
  destinations entirely through the CLI.
- Namespace names have no built-in semantic meaning.
- Remem portal/API-key settings are the sole source of read/write permission
  and default-write authority.
- The plugin contains no conflicting local read-only permission.
- A true per-client read-only policy is achieved by selecting a server-scoped
  read-only key, not by a plugin permission toggle.
- Claude and Codex can inherit or override routes without changing their
  existing lifecycle functionality.
- Normal conversations can recall selected session history while new session
  records continue writing to their configured namespace.
- Every explicit routing failure is visible and never redirects a write.
- No Remem API, portal, namespace, or existing cloud record is changed by the
  plugin release.
