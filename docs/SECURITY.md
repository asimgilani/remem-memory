# Remem Memory security model

Remem Memory connects a local Claude Code or Codex host to the user's existing
Remem account. This document describes what crosses that boundary, what stays
local, and which controls are advisory versus mechanically enforced.

## Data sent to Remem

Automatic hooks can send:

- a sanitized recall query, bounded to 2,000 characters;
- a durable conversation capture containing the safe user prompt and assistant
  answer, plus hashed session/turn identifiers and the working-directory source
  path;
- structured session checkpoints and rollups containing project/session
  identifiers, repository path, branch, files touched, safe tool summaries,
  decisions, open questions, and next actions; and
- namespace keys selected by the effective behavior route.

Automatic recall asks for at most four results. The returned text is filtered
and bounded to 6,000 characters before it is added to model context. Explicit
read-only MCP tools, write MCP tools such as `remem_ingest` and
`remem_extract_facts`, or manual CLI operations send the supplied fields and
are not a second automatic safety boundary.

Remem cloud storage, retention, account access, namespace authorization, and
the key's default write namespace are controlled by Remem and its API keys.
The plugin selects a connection and namespace route; it never grants access.
Use a least-privilege key and separate accounts or keys for hosts that should
not share memory.

## Bounded untrusted recall

All automatic recalled content is treated as untrusted historical data. The
hook wraps it in an explicit untrusted-data envelope, neutralizes fake envelope
delimiters, excludes secret-shaped results, and instructs the model not to
follow embedded commands. Recalled memory must not override current system or
user instructions, verified facts, or files in the active workspace.

This reduces prompt-injection risk; it does not prove that stored content is
correct. Confirm consequential or conflicting memories with the user.

## Secret filtering

Automatic paths perform secret filtering before queries, local state, local
logs, optional summaries, or remote ingestion. They reject recognized API
keys, tokens, passwords, private-key markers, bearer credentials, and
high-entropy credential-like strings. Secret-bearing tool events, paths,
transcript turns, results, and final payloads are dropped instead of redacted
and forwarded.

Filtering is defense in depth, not a guarantee that every form of private data
will be recognized. Do not paste credentials into conversations. An explicit
MCP or manual command can bypass automatic policy if an agent supplies unsafe
arguments, so the canonical skill prohibits secret-bearing explicit calls.

## Local state and logs

Automatic hook state and settings live under
`~/.config/remem-memory/` by default. The plugin creates its state directories
with owner-only access and state/settings files with owner read/write
permissions. Its private ordered worker queue lives below that same directory.
Session and queue filenames use a hash rather than the raw session ID.

Session automation keeps project-local files under `.remem/`, normally:

- `.remem/auto-memory-state.json`;
- `.remem/session-checkpoints.ndjson`; and
- optional manual recall/checkpoint logs.

The repository ignores `.remem/`, but another project may not. These files are
not encrypted and can include prompts, summaries, local paths, query results
from manual recall, and ingest response metadata. Keep them out of version
control, restrict host access, and use a manual command's `--no-log` option
when local retention is not wanted.

“Off the record” suppresses automatic recall, capture, checkpoints, and rollups
for the current turn. It does not delete content stored before that turn.

## Optional transcript summary provider

Session checkpoints can use an optional summary provider. Depending on
configuration, bounded transcript-derived text may be sent to a local Claude
CLI, a local Codex CLI, the Anthropic API, or the OpenAI API. That provider has
its own data policy and credential boundary.

Without an explicit provider override, summarization is pinned to the invoking
harness: Claude events use the Claude CLI and Codex events use the Codex CLI.
Setting `REMEM_MEMORY_SUMMARY_PROVIDER` is an explicit opt-in to the selected
cross-provider boundary. Claude prompts are sent over stdin rather than process
arguments. Nested Codex summarization runs from an empty temporary workspace
with shell, unified execution, code, plugin, and workspace readers disabled.

Disable this path with:

```bash
export REMEM_MEMORY_SUMMARY_ENABLED="0"
```

The secret filter runs before the summary request, but disable external
summaries when project policy does not allow another model provider to receive
the material.

## Credential handling and precedence

The canonical credential is a macOS Keychain generic password:

- service: `io.remem.memory`
- account: `default`

That item backs the implicit `primary` connection. Additional named
connections use separate opaque Keychain accounts; their labels are non-secret
local metadata. Route files contain labels and opaque identifiers, never API
keys.

`remem-memory auth` uses a hidden terminal prompt. `remem-memory status` reports
only `configured` or `missing`, never the value or a fingerprint. Runtime
credential precedence is:

1. a non-empty `REMEM_API_KEY` environment variable;
2. the canonical macOS Keychain item.

Environment precedence supports deliberate process-local overrides for
`primary` only, but an old shell export can unexpectedly shadow Keychain. It
does not replace additional named connections. The installer never edits shell
startup files or `PATH`. The CLI is installed at
`~/.local/bin/remem-memory`; use that full path if
`command -v remem-memory` cannot find it. Verify Keychain without the override
using `env -u REMEM_API_KEY ~/.local/bin/remem-memory status`. Remove a
pre-existing credential export only after that verification, then use
`unset REMEM_API_KEY` in the active shell.

For the one-time legacy Codex bridge, setup parses only one exact basic-string
`REMEM_API_KEY` assignment in the exact old Remem MCP environment table. It
copies the value to Keychain, reads it back, and uses constant-time comparison.
A malformed, duplicate, ambiguous, or different existing value fails closed.
The legacy MCP block remains until the Keychain copy and canonical Codex plugin
are verified.

The installer removes `REMEM_API_KEY` from child setup environments and never
places it in arguments, logs, plugin JSON, marketplace JSON, or new Codex
configuration.

### Host boundary

Keychain protects at-rest configuration and reduces accidental exposure. It is
not a sandbox from the logged-in user: a fully compromised same-user host or a
user-authorized process may access credentials, process memory, local files,
or recalled data using the user's authority. This plugin cannot promise
secrecy against arbitrary local code. Protect the macOS account, approve client
and hook access deliberately, and revoke the Remem key after a host compromise.

### Credential-bearing HTTP proxy and CA boundary

Automatic hooks and manual CLI helpers share the same hardened standard-library
Remem transport. It ignores ambient `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
`NO_PROXY`, `SSL_CERT_FILE`, and `SSL_CERT_DIR` values, disables redirects, and
uses the compiled system trust-store paths. The bundled MCP path described
below also ignores ambient proxy and custom-CA configuration. Those environment
settings are therefore outside the Remem transport trust boundary and do not
receive its authorization header or payload by default.

## Routing and authorization

The neutral routes are:

- `recall`: read from zero or more configured sources;
- `memory`: write selected durable conversation memory to one destination or
  turn that automatic behavior off; and
- `sessions`: write checkpoints and rollups to one destination or turn that
  automatic behavior off.

The simple built-in routes use `primary/@readable` for recall and
`primary/@default` for both writes. `@readable` delegates readable namespace
scope to the selected key. `@default` omits an explicit namespace so Remem
uses that key's current server default.

API-key grants and the server default are configured in Remem. Local routes
can narrow intent but cannot expand a key's access. A `401` or `403` remains a
credential or API-key scope error and never causes a write to fall back to
another namespace or connection.

For a truly read-only Claude setup, enter a separate read-only Remem API key at
the hidden prompt as a separate connection and configure the complete client
override:

```bash
remem-memory connections add read-only
remem-memory routes set recall --from read-only/@readable --client claude
remem-memory routes set memory --to off --client claude
remem-memory routes set sessions --to off --client claude
remem-memory connections use read-only --client claude
```

The API key is the hard permission boundary for explicit calls. The two `off`
routes are required: they prevent automatic writes from inheriting the
writable global `primary` route. `recall-only` is not a permission boundary.

Routing configuration is versioned, non-secret, and atomically replaced.
Inspect it with `remem-memory routes show`, restore the simple behavior with
`remem-memory routes use-default`, and check the complete local setup with
`remem-memory doctor`.

## Bundled MCP execution

The audited MCP snapshot is shipped at `plugins/remem-memory/mcp`; runtime does
not fetch a private source repository. `PROVENANCE.json` records upstream
commit `759a57af927908315a3a4f6e4c73a935faf8d56f`, the original file hashes, and
the local hardening. Before execution, the launcher rejects a changed source
file, unexpected source file, symlinked bundle component, or hash mismatch.
Generated `__pycache__` bytecode is ignored and never enters the isolated,
non-editable runtime.

Only `uv` is required. Preparation runs
`uv sync --no-config --locked --no-editable --no-install-project` into a
private, content-addressed cache. The local MCP project has no build backend
and is never built or installed. `uv.lock` fixes the complete dependency graph
and artifact hashes; the exact direct dependencies are `httpx==0.28.1` and
`mcp==1.26.0`. A fresh setup or first direct-plugin start may fetch the locked
PyPI artifacts. Manual checkpoint, rollup, and recall helpers use only
Python's standard library and do not require a repository environment.

Preparation and the installer probe use a dummy credential through the same
descriptor path, so package preparation never receives the user's key. Once
the cached Python interpreter is verified as executable, the real API key
reaches only the direct cached Python process through a one-use anonymous file
descriptor. The environment contains only its descriptor number, not the key.
The server reads and closes the descriptor before importing third-party
modules.

The hardened server disables redirects and constructs its HTTP client with
`trust_env=False`. Ambient proxy and CA environment settings are not forwarded,
so proxies cannot receive the Remem authorization header by default. The
credential-bearing process also bypasses `uv`; package installation code never
runs with the real key. Document and entity IDs are validated as canonical
UUIDs before they are inserted into API paths. The remaining supply-chain
boundary includes this public repository, the installed `uv` executable, and
the locked PyPI artifacts downloaded during keyless preparation.

There is no setup wizard, no local web server, and no daemon. MCP exists only
as a host-launched stdio process while the client uses it.

## Modes, manual actions, and fail-open behavior

The persistent automatic modes are:

- `auto`: bounded recall plus selective `memory` and `sessions` writes;
- `recall-only`: recall with no automatic writes; and
- `off`: no automatic recall or writes.

Sensitivity controls only automatic durable capture. Explicit
checkpoint, rollup, and recall helpers plus explicit MCP calls are separate
operations and do not mechanically inherit all automatic controls. The skill
therefore requires a `remem-memory status` preflight before explicit/manual
memory: `auto` permits eligible reads and writes, `recall-only` permits
read-only MCP tools or manual recall with `--no-log` but no write MCP tools,
and `off` permits neither. Write MCP tools include `remem_ingest` and
`remem_extract_facts`; they require explicit user intent in `auto`, unavailable
automatic capture, and no duplicate write. Off-record overrides all modes.

The optional `remem-memory codex` launcher is automatic rather than an
explicit helper. It mechanically rechecks the persisted mode before each
checkpoint and final rollup, suppresses off-record boundaries, and permanently
disables transcript/model summaries after an off-record marker within that
wrapped session. A normal prompt can resume deterministic checkpoints after
the private file baseline has been advanced.

Hooks fail open: timeouts, missing credentials, Keychain failures, network
errors, invalid responses, or local state errors do not block the user's main
Claude Code or Codex workflow. The tradeoff is that a recall, capture,
checkpoint, or rollup may be skipped. `remem-memory status` checks local setup;
it does not prove that every future network request will succeed.

For a hard local pause, use `remem-memory mode off`. Removing the plugin or
revoking the Remem key provides a stronger boundary against an independent
manual caller.

## Update and rollback

Update only a clean checkout with `git pull --ff-only`; preserve and report a
dirty checkout instead of forcing it. The installer verifies the new plugin
before legacy cleanup and stops on credential conflicts.

The verified rollback boundary in 0.4.0 is non-destructive: pause memory and
keep the current checkout, Keychain item, Remem cloud data, project `.remem/`
logs, and both client registrations. Version downgrade is intentionally not
automated. An older checkout's installer can update an existing canonical Git
marketplace back to current remote head, and source replacement is not
transactional across both clients. Do not run an older installer or manually
remove one registration. A downgrade requires a tested exact-source procedure
that verifies both clients, MCP, commands, aliases, and skill identities before
re-enabling the plugin.

The pre-unification `remem-dev-sessions` hooks do not read the new persisted
mode. Restoring that implementation is manual legacy recovery, not the unified
rollback path. Keep its client process under
`REMEM_MEMORY_AUTO_ENABLED=0` until its old Codex MCP, Claude plugin, and
aliases have all been restored and verified.

This release performs no Remem data migration. It makes no Remem API changes
and no Remem portal changes; all changes are local plugin, command, hook,
credential, and client-registration behavior on the configured host.
