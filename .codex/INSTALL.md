# Install Remem Memory

Install one `remem-memory` plugin for the compatible clients present on this
Mac. These instructions are for an agent operating the target host.

## Safety rules

- Work only in the Remem Memory checkout.
- Preserve an existing checkout, virtual environment, `.remem/` logs, and
  credential state.
- If an existing checkout is dirty, stop and tell the user. Do not reset,
  overwrite, or delete it.
- Never request that the user paste an API key into chat, a command argument,
  a configuration file, or a shell startup file.
- Leave the Remem portal and every Remem API service unchanged.

## 1. Verify prerequisites

This release supports macOS because it stores the credential in macOS
Keychain. Require Git, Python 3.10+, and `uv`. At least one of Codex or Claude
Code should also be installed.

Run non-mutating version checks. If `uv` is missing, install it through the
host's trusted package manager before continuing. For a Mac with Homebrew:

```bash
brew install uv
```

Do not use an unreviewed network bootstrap script. The Remem installer itself
must not run until `uv --version` succeeds; its preflight intentionally makes
no changes otherwise.

## 2. Choose or update the checkout

Prefer an existing checkout, including the older
`~/.codex/remem-dev-sessions` directory name. The directory name does not
change the installed product identity.

Change into the selected checkout before inspecting or updating it. For
example, use `cd ~/.codex/remem-memory` for the new path or
`cd ~/.codex/remem-dev-sessions` for an existing older path. Then run:

```bash
git status --short
git remote get-url origin
git pull --ff-only
```

Continue only when status is clean, the remote is the expected
`asimgilani/remem-memory` repository, and the fast-forward update succeeds.

For a new checkout:

```bash
git clone https://github.com/asimgilani/remem-memory.git ~/.codex/remem-memory
cd ~/.codex/remem-memory
```

## 3. Run contained setup

From the repository root:

```bash
./install-codex-skill.sh
command -v remem-memory
```

The setup:

- uses standard-library-only local helpers and prepares the private,
  content-addressed MCP cache;
- installs the canonical command and compatibility aliases;
- installs and verifies `remem-memory` version `0.4.0` in available Codex and
  Claude Code clients;
- keeps the older Claude plugin active until the replacement is verified;
- can bridge one narrowly recognized legacy Codex credential to Keychain; and
- removes old Codex and Claude identities only after the Keychain copy, new
  plugin, and bundled MCP runtime are verified.

Setup does not migrate Remem data and makes no Remem portal or Remem API
changes.

The command is installed at `~/.local/bin/remem-memory`. If
`command -v remem-memory` returns nothing, use that full path for every
remaining Remem Memory control. Do not modify `PATH` or shell startup files
automatically.

## 4. Configure the credential

Check the canonical Keychain source without allowing an old environment
override to mask it:

```bash
env -u REMEM_API_KEY ~/.local/bin/remem-memory status
```

If it reports `credential: missing`, run:

```bash
~/.local/bin/remem-memory auth
env -u REMEM_API_KEY ~/.local/bin/remem-memory status
```

Let the user enter the API key into the hidden terminal prompt. Do not capture
or repeat it. The canonical macOS Keychain item is the generic password
`io.remem.memory` / `default`.

Credential precedence is:

1. a non-empty `REMEM_API_KEY` in the current process environment;
2. the canonical Keychain item.

The installer never edits shell startup files. If an existing startup file
exports `REMEM_API_KEY`, it continues to override Keychain. After verifying
Keychain, ask the user before removing that old export, then run
`unset REMEM_API_KEY` in the current shell.

## 5. Verify and restart

Run:

```bash
remem-memory status
remem-memory doctor
codex plugin list --json
claude plugin list --json
```

Skip a client-specific command if that client is not installed. Confirm that
each installed client reports `remem-memory` enabled at `0.4.0`. Confirm the
old Claude identity is absent or disabled and the old Codex Remem MCP block is
absent only after the verified bridge.

Restart each installed client, then finish activation for the applicable
surface:

- **Codex Desktop:** open **Plugins → Remem Memory → Hooks**, choose
  **Review**, inspect the five hooks, and let the user trust them.
- **Codex CLI:** start interactive Codex, enter `/hooks`, select
  **Remem Memory**, inspect the five hooks, and let the user approve them.
- **Claude Code:** run `/reload-plugins`, or restart Claude Code and begin a
  new session. Claude has no separate Codex-style hook approval; its `/hooks`
  view is read-only and can verify that the plugin hooks loaded.

The agent may verify plugin state with the commands above, but may not approve
Codex hooks for the user. Codex approval is local to that
installation/configuration and bound to the exact hook hash. Codex skips those
hooks until they are trusted, so automatic recall, durable capture, and
session checkpoints do not run before approval. MCP tools, skills, and
manual CLI commands can still work before hook trust. After any new or changed
hook version, run `/hooks` and re-review it.

The audited MCP snapshot is bundled at `plugins/remem-memory/mcp`; it is not
fetched from a private repository. Its provenance records upstream commit
`759a57af927908315a3a4f6e4c73a935faf8d56f`. Setup validates the exact source
files and hashes, excludes generated `__pycache__` files, then uses
`uv sync --no-config --locked --no-editable --no-install-project` with a dummy
credential to prepare and probe a private, content-addressed cache. It does
not build or install the local MCP project.
`uv.lock` locks the full environment, including direct dependencies
`httpx==0.28.1` and `mcp==1.26.0`. A fresh setup or first direct-plugin start
may fetch the locked PyPI artifacts. A failed probe stops setup and preserves
the legacy identities.

The real API key reaches only the direct cached Python process through a one-use
anonymous file descriptor; it is not placed in arguments or an environment
value. The bundled server consumes and closes it before third-party imports.
HTTP redirects and ambient proxies are disabled. MCP runs as a host-launched
stdio child. There is no setup wizard, no local web server, and no daemon.

## 6. Confirm simple behavior

Default behavior is `auto` with `balanced` durable capture:

```bash
remem-memory mode auto
remem-memory mode recall-only
remem-memory mode off
remem-memory sensitivity conservative
remem-memory sensitivity balanced
remem-memory sensitivity aggressive
remem-memory routes show
```

Most users need no routing configuration. The built-in routes read through
`primary/@readable` and send the `memory` and `sessions` behaviors through
`primary/@default`.

API-key grants and the server default are configured in Remem. The plugin
selects a connection and namespace route; it never grants access. Do not change
Remem grants, defaults, namespaces, or cloud data during installation.

Advanced routing is optional and CLI-only:

```bash
remem-memory routes use-default
remem-memory routes set recall --from primary/@readable
remem-memory routes set memory --to primary/@default
remem-memory routes set sessions --to primary/@default
remem-memory routes show --client codex
remem-memory routes show --client claude
```

Custom namespace destinations use their exact Remem namespace keys after the
connection label. Add `--client codex` or `--client claude` to set a client
override. `off` is valid for automatic write routes:

```bash
remem-memory routes set memory --to off --client claude
```

Additional named connections use a hidden credential prompt:

```bash
remem-memory connections add secondary
remem-memory connections list
remem-memory connections use secondary --client codex
```

True read-only isolation requires a separate read-only Remem API key stored as
a separate connection and selected for the client's recall and MCP process.
`recall-only` is not a permission boundary.

## Surface boundary

This local plugin works in Codex desktop/CLI and Claude Code on this Mac host.
Codex Remote benefits when its task executes on this configured Mac host.
Ordinary ChatGPT mobile chat, native Claude mobile chat, and an IDE extension
do not load the plugin.
Codex Cloud or a different SSH host needs its own installation and credential.
The installed plugin may appear in the desktop Plugins list.

## Update and rollback

For future updates, require a clean checkout, run `git pull --ff-only`, rerun
`./install-codex-skill.sh`, and re-verify both clients with `status` and
`doctor`. Never discard local changes to force an update.

Claude Code must fetch and install a new plugin version before reload. The
installer does this. When managing Claude directly, use marketplace update and
plugin update, or reinstall when the plugin is absent:

```bash
claude plugin marketplace update remem-memory
claude plugin update remem-memory@remem-memory
```

If the plugin is absent, use
`claude plugin install remem-memory@remem-memory` instead of the update
command. Then run `/reload-plugins` or restart Claude Code. Restarting alone
does not fetch a new version.

To pause without uninstalling:

```bash
remem-memory mode off
```

The verified rollback boundary in 0.4.0 is `remem-memory mode off`. Keep Remem
cloud data, Keychain data, project `.remem/` logs, the current checkout, and
both client registrations intact. Version downgrade is intentionally not
automated: an older checkout's installer can update an existing canonical Git
marketplace back to current remote head, and marketplace replacement is not
transactional across both clients. Do not run an older installer or remove one
registration. An older unified version requires a tested exact-source
procedure that verifies both clients, MCP, commands, aliases, and matching
skill identities before re-enabling it.

The pre-unification `remem-dev-sessions` hooks do not honor the new persisted
`mode off`. Treat restoration of that implementation as manual legacy
recovery, keep its client process under
`REMEM_MEMORY_AUTO_ENABLED=0`, and verify its old Codex MCP, Claude plugin, and
aliases before removing the unified plugin.
