# Remem Memory

Automatic recall, durable memory, and session continuity for Claude Code and Codex.

Remem Memory is one plugin with one secure credential model. On a configured
Mac, its hooks recall useful context, selectively retain durable preferences
and decisions, and preserve session checkpoints and rollups.

```text
Claude Code or Codex on your Mac
        │
        ├─ prompt ──> bounded, safe recall ──> answer context
        └─ events ──> durable memory + session continuity
                              │
                         Remem cloud
```

Setup and controls are CLI-based. There is no setup wizard, no local web
server, and no daemon. The MCP server is a host-launched stdio child that runs
only while a compatible client needs it.

## Supported surfaces

| Surface | Support |
| --- | --- |
| Claude Code on the configured Mac | Plugin skills, hooks, commands, and MCP |
| Codex CLI and the Codex desktop app on the configured Mac | Plugin skills, hooks, commands, and MCP |
| Codex Remote | Works when the remote task executes on that configured Mac host |
| Ordinary ChatGPT mobile chat | Does not load this local plugin |
| IDE extension | Not a supported plugin surface |
| Codex Cloud or a different SSH host | Needs its own installation and credential |

The plugin may appear in the Codex desktop Plugins list after installation.
That list is for the host plugin; it does not make ordinary ChatGPT mobile
conversations use Remem Memory.

## Quick install

Ask Codex or Claude Code on the target Mac:

```text
Fetch and follow instructions from https://raw.githubusercontent.com/asimgilani/remem-memory/refs/heads/master/.codex/INSTALL.md
```

## Finish activation

The installer safely installs and verifies the plugin. Complete these local
activation steps:

1. Check the canonical Keychain credential:

   ```bash
   env -u REMEM_API_KEY ~/.local/bin/remem-memory status
   ```

   If it reports `credential: missing`, get a least-privilege API key from your
   [Remem account](https://app.remem.io), then enter it only in the hidden
   prompt:

   ```bash
   ~/.local/bin/remem-memory auth
   ```

   Never paste the key into chat, a command argument, or a configuration file.
2. Finish activation for each installed client:

| Surface | What to do |
| --- | --- |
| Codex Desktop | Restart Codex Desktop, then open **Plugins → Remem Memory → Hooks**, choose **Review**, inspect the five hooks, and trust them. |
| Codex CLI | Start interactive Codex, enter `/hooks`, select **Remem Memory**, inspect the five hooks, then approve them. |
| Claude Code | Run `/reload-plugins`, or restart Claude Code and begin a new session. Claude has no separate Codex-style hook approval; its `/hooks` view is read-only and can verify that the plugin hooks loaded. |

Codex approval is local to that installation/configuration and bound to the
exact hook hash. Review again on a new Mac/configuration or after hook content
changes. Codex skips those hooks until they are trusted, so automatic recall,
durable capture, and session checkpoints do not run before approval. MCP
tools, skills, and manual CLI commands can still work before hook trust. After
any new or changed hook version, run `/hooks` and re-review it.

3. Run the non-destructive checks in this order:

   ```bash
   ~/.local/bin/remem-memory status
   ~/.local/bin/remem-memory doctor
   ```

Most users need no routing configuration. One key, the namespaces it can read,
and its server default are enough.

Setup is active when the canonical status command above reports the intended
mode and sensitivity plus `credential: configured`; every installed client
reports Remem Memory enabled at version `0.4.0`; if Codex is installed, it
shows all five Remem Memory hooks trusted; and a fresh supported-client session
can use automatic memory.

If activation does not work:

- Missing credential: run the hidden `auth` prompt above.
- Plugin not listed: update a clean checkout and rerun the installer.
- Codex automation absent: review its local hook trust.
- Claude still shows old plugin state: fetch and install the update as
  described under **Updating** below, then run `/reload-plugins`.

The installer detects Codex and Claude Code, installs the same
`remem-memory` plugin into each available harness, and verifies version
`0.4.0` before retiring an older active identity.

## Requirements

- macOS, because the supported credential store is macOS Keychain
- Git and Python 3.10+
- `uv` on `PATH` before setup starts
- Codex, Claude Code, or both
- A Remem API key

Install `uv` with the Mac's trusted package manager if it is missing. With
Homebrew, use:

```bash
brew install uv
```

The installer does not bootstrap package managers and makes no changes when a
required preflight fails. Manual checkpoint, rollup, and recall helpers use
only Python's standard library. The bundled MCP environment stays in a private
cache. Nothing is installed globally.

## Manual setup

For a new installation:

```bash
git clone https://github.com/asimgilani/remem-memory.git ~/.codex/remem-memory
cd ~/.codex/remem-memory
./install-codex-skill.sh
command -v remem-memory
```

The command is installed at `~/.local/bin/remem-memory`. If
`command -v remem-memory` returns nothing, use that full path for the `auth`,
`status`, `mode`, and `sensitivity` examples. Setup intentionally does not edit
`PATH` or shell startup files.

```bash
remem-memory auth
remem-memory status
```

`remem-memory auth` uses a hidden terminal prompt and stores the key as the
macOS Keychain generic password `io.remem.memory` / `default`. The key is not
placed in plugin manifests, shell startup files, or Codex configuration.
To verify Keychain rather than an environment override, run
`env -u REMEM_API_KEY ~/.local/bin/remem-memory status`.

For client-specific reload and trust steps, see [Finish activation](#finish-activation).

The audited MCP snapshot is bundled at `plugins/remem-memory/mcp`; no private
repository fetch is needed. Its provenance records upstream commit
`759a57af927908315a3a4f6e4c73a935faf8d56f`. Setup validates the exact source
files and prepares a locked, non-editable runtime from `uv.lock` with
`uv sync --no-config --locked --no-editable --no-install-project`. The local
MCP project is never built or installed. Generated
`__pycache__` files are excluded from that runtime. The direct
dependencies are `httpx==0.28.1` and `mcp==1.26.0`. Setup—or the first start
after a direct plugin install—may fetch the locked PyPI artifacts.

Runtime preparation uses a dummy credential. The real API key reaches only the
direct cached Python process through a one-use anonymous file descriptor. The
server consumes and closes it before third-party imports; HTTP redirects and
ambient proxies are disabled.

## Daily behavior and controls

The default mode is `auto`:

- relevant prompts can receive bounded automatic recall;
- lasting preferences and decisions can receive selective durable capture;
- meaningful work creates session checkpoints and rollups; and
- “off the record” or `/remem off-record` suppresses memory for that turn.

Use the CLI to change persistent behavior:

```bash
remem-memory mode auto
remem-memory mode recall-only
remem-memory mode off

remem-memory sensitivity conservative
remem-memory sensitivity balanced
remem-memory sensitivity aggressive

remem-memory status
```

`recall-only` permits automatic reads but disables the automatic `memory` and
`sessions` writes. `off` disables automatic reads and writes. Sensitivity
changes durable-capture selectivity, not recall or checkpoint cadence.

Explicit session helpers remain available for a boundary or a host without
hooks:

```bash
remem-memory checkpoint --help
remem-memory rollup --help
remem-memory recall --help
```

Do not use explicit writes to duplicate a successful automatic hook. The
checkpoint, rollup, and recall helpers do not mechanically enforce the
automatic mode, so do not invoke them while memory is `off`, `recall-only`, or
off the record.

The optional `remem-memory codex` launcher is different: it is an automatic
Codex lifecycle wrapper. It mechanically rechecks the persisted mode before
every checkpoint and final rollup, including changes made while Codex is
running. It also suppresses an off-record boundary and advances its file
baseline so private-turn changes cannot leak into a later checkpoint. After
any off-record marker, transcript/model summaries stay disabled for that
wrapped session; deterministic checkpoints can resume after a normal prompt.
Run `remem-memory codex --help` for its launch options.

Before any explicit MCP call or manual workflow, run `remem-memory status`.
`auto` allows eligible read-only MCP tools and write MCP tools. `recall-only`
allows read-only MCP tools or manual recall with `--no-log`, but never write
MCP tools such as `remem_ingest` or `remem_extract_facts`; `off` allows neither.
Use a write tool only for explicit user intent when automatic Stop capture is
unavailable, and never duplicate a successful automatic write. Off-record
overrides every mode for that turn.

## Session continuity

The installed hooks preserve the existing coding workflow: meaningful
write/edit/shell activity feeds interval checkpoints, Stop and PreCompact
create milestone boundaries, and Claude Code's SessionEnd creates the final
rollup. Codex releases that do not emit SessionEnd still preserve every Stop
milestone; PreCompact creates a versioned rolling rollup, and the optional
`remem-memory codex` wrapper creates a final rollup when its Codex process
exits. This avoids a duplicate rollup on every Codex turn. Defaults are four
meaningful tool events and a 20-minute interval target.

Optional session tuning remains available:

```bash
export REMEM_MEMORY_PROJECT="my-project"
export REMEM_MEMORY_INTERVAL_SECONDS="1200"
export REMEM_MEMORY_MIN_EVENTS="4"
export REMEM_MEMORY_ROLLUP_ON_SESSION_END="1"
export REMEM_MEMORY_SUMMARY_ENABLED="1"
```

By default, optional summaries stay with the invoking harness: Claude Code uses
its Claude CLI and Codex uses its Codex CLI. Cross-provider summarization occurs
only when `REMEM_MEMORY_SUMMARY_PROVIDER` explicitly selects `claude_cli`,
`codex_cli`, `anthropic`, or `openai`. See the security guide before sending
transcript-derived material across that boundary.

## Advanced routing

The plugin has three neutral behavior routes:

| Route | Direction | Purpose |
| --- | --- | --- |
| `recall` | read | Context searched before an answer |
| `memory` | write | Durable preferences, decisions, facts, and other selected conversation memory |
| `sessions` | write | Checkpoints, milestone summaries, and rollups |

The built-in simple routes are `primary/@readable` for `recall` and
`primary/@default` for both writes. `@readable` means every namespace the
selected key can read. `@default` delegates the write destination to that
key's current server default. Restore this simple behavior or inspect it with:

```bash
remem-memory routes use-default
remem-memory routes show
remem-memory routes show --client codex
remem-memory routes show --client claude
```

Advanced users can replace individual global routes. Substitute actual
namespace keys from Remem when using explicit destinations:

```bash
remem-memory routes set recall --from primary/@readable
remem-memory routes set memory --to primary/@default
remem-memory routes set sessions --to primary/@default
remem-memory routes set recall --from primary/NAMESPACE_KEY primary/OTHER_NAMESPACE_KEY
```

Add `--client codex` or `--client claude` to create an override. For example:

```bash
remem-memory routes set sessions --to primary/NAMESPACE_KEY --client codex
remem-memory routes set memory --to off --client claude
```

An `off` route disables that automatic behavior; it does not restrict explicit
MCP tools. Global routes otherwise apply to both clients.

Most users never need another connection. For a second workspace, account, or
least-privilege key, choose a local label and use the hidden prompt:

```bash
remem-memory connections add secondary
remem-memory connections list
remem-memory routes set recall --from secondary/@readable --client codex
remem-memory routes set sessions --to secondary/NAMESPACE_KEY --client codex
remem-memory connections use secondary --client codex
```

`connections use` selects that client's explicit MCP credential. Automatic
routes change only through `routes set`.

API-key grants and the server default are configured in Remem. The plugin
selects a connection and namespace route; it never grants access. For a truly
read-only Claude setup, enter a separate read-only Remem API key at the hidden
prompt as a separate connection and configure the complete client override:

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

## Updating from remem-dev-sessions

The repository and data stay in place; this is an update to one canonical
product identity. Command aliases: `remem-dev-sessions`,
`remem-session-memory`, and `remem-codex`. Skill aliases:
`remem-dev-sessions`, `remem-session-memory`, and `session-memory`. There is no
`session-memory` command and no `remem-codex` skill. All remain compatibility
aliases to `remem-memory`; they do not run a second memory engine.

For an existing clean checkout:

```bash
git status --short
git pull --ff-only
./install-codex-skill.sh
remem-memory status
remem-memory doctor
```

If `git status --short` shows changes, stop and preserve them. Never reset or
delete a dirty checkout to update this plugin.

During the one-time transition, setup accepts only one exact legacy Codex
`REMEM_API_KEY` basic string from the old Remem MCP environment block. It
copies that value to the canonical Keychain item, reads it back, and verifies
it before the new Codex plugin can replace the legacy block. A mismatch fails
closed and leaves the legacy configuration untouched. Claude's new plugin is
also verified enabled before its older identity is disabled and removed.

The installer never edits shell startup files. A pre-existing
`REMEM_API_KEY` environment variable continues to override macOS Keychain. Once
Keychain setup is verified, remove any old startup-file export yourself and
run `unset REMEM_API_KEY` in the current shell if you want Keychain to become
the active source.

No Remem data is migrated, copied, renamed, or deleted. There are no Remem API
changes and no Remem portal changes.

For Claude Code, a restart or `/reload-plugins` loads an already-installed
version; restarting alone does not fetch a new version. The installer performs
the appropriate update. An operator managing Claude directly must update the
marketplace and then update or reinstall the plugin as appropriate:

```bash
claude plugin marketplace update remem-memory
claude plugin update remem-memory@remem-memory
```

If the plugin is not installed, use the documented marketplace install flow
instead of the update command:

```bash
claude plugin install remem-memory@remem-memory
```

Then reload or restart Claude Code.

## Safe pause and rollback

Pause all automatic memory immediately:

```bash
remem-memory mode off
```

The verified rollback boundary in this release is the immediate `mode off`
pause. Keep the current checkout, Keychain item, cloud data, `.remem/` files,
and both client registrations intact while investigating.

Version downgrade is intentionally not automated in 0.4.0. Running an older
checkout's installer is not a pin: an existing canonical Git marketplace can
update back to its current remote head. Replacing that marketplace source is
client-specific and is not transactional across Codex and Claude Code. Do not
run an older installer or manually remove only one client registration; either
can create a mixed installation. Restore an older unified version only with a
tested procedure that pins the exact local source in both clients and verifies
MCP, commands, aliases, and matching skill identities before re-enabling it.

Returning to the pre-unification `remem-dev-sessions` implementation is also a
manual legacy recovery, not an automated rollback path. Its hooks do not read the new
persisted `mode off` setting. Keep the unified plugin paused and do not enable
legacy automation unless the legacy client process is explicitly started with
`REMEM_MEMORY_AUTO_ENABLED=0`; restore its old Codex MCP, Claude plugin, and
aliases from a known-good backup and verify all of them before removing the
unified plugin. No rollback requires deleting cloud data, Keychain data, or
project `.remem/` logs.

See [the Codex guide](docs/README.codex.md) for host-specific use and
[the security guide](docs/SECURITY.md) for the data and trust boundary.
