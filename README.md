# remem-dev-sessions

API-first coding-session memory workflows for Remem.

This repository is still hosted as `remem-memory`, but the toolkit name is now `remem-dev-sessions`.

## What this package contains

- Claude marketplace manifest: `.claude-plugin/marketplace.json`
- Claude plugin source: `plugins/remem-memory`
  - Skill: `session-memory`
  - Hooks: `hooks/hooks.json`
  - Hook runner: `scripts/auto_memory_hook.py`
  - Optional bundled MCP config: `.mcp.json`
- Codex skills:
  - `codex/skills/remem-dev-sessions` (canonical)
  - `codex/skills/remem-session-memory` (legacy alias)
- Helper scripts:
  - `scripts/remem_dev_sessions.py` (unified CLI)
  - `scripts/remem_codex_wrapper.py` (Codex wrapper with auto checkpoints)
  - `scripts/remem_checkpoint.py`
  - `scripts/remem_rollup.py`
  - `scripts/remem_recall.py`

## Prerequisites

- Python 3.10+
- `httpx` installed
- A Remem API key (`vlt_...`)
- Environment variables:

```bash
export REMEM_API_URL="https://api.remem.io"
export REMEM_API_KEY="vlt_your_key"
```

Install dependency:

```bash
python -m pip install -r requirements.txt
```

## Install in Claude Code (local marketplace)

From this repository root:

1. Add marketplace:

```text
/plugin marketplace add .
```

2. Install plugin:

```text
/plugin install remem-dev-sessions@remem-dev-sessions
```

3. Restart Claude Code.

## Claude Auto Checkpoints

When enabled, hooks automatically run:

- `PostToolUse` (`Write|Edit|MultiEdit|Bash`) for interval checkpoints
- `Stop` for milestone checkpoints
- `SessionEnd` for final rollup

If `REMEM_API_KEY` is unset, hooks still write local checkpoint logs and skip API ingest.

Optional tuning env vars:

```bash
export REMEM_MEMORY_PROJECT="my-project"          # default: current folder name
export REMEM_MEMORY_INTERVAL_SECONDS="1200"       # default: 20 minutes
export REMEM_MEMORY_MIN_EVENTS="4"                # default: 4 tool events
export REMEM_MEMORY_ROLLUP_ON_SESSION_END="1"     # default: enabled
export REMEM_MEMORY_AUTO_ENABLED="1"              # default: enabled
```

## Install in Codex

From this repository root:

```bash
./install-codex-skill.sh
```

This installs:

- Skill symlink: `~/.agents/skills/remem-dev-sessions`
- Legacy alias skill: `~/.agents/skills/remem-session-memory` (if present)
- Helper commands:
  - `~/.local/bin/remem-dev-sessions`
  - `~/.local/bin/remem-dev-sessions-codex`
  - `~/.local/bin/remem-dev-sessions-checkpoint`
  - `~/.local/bin/remem-dev-sessions-rollup`
  - `~/.local/bin/remem-dev-sessions-recall`
- Legacy aliases:
  - `~/.local/bin/remem-memory-codex`
  - `~/.local/bin/remem-memory-checkpoint`
  - `~/.local/bin/remem-memory-rollup`
  - `~/.local/bin/remem-memory-recall`

Restart Codex after installation.

## API-First Commands

Use these after running `./install-codex-skill.sh` (or otherwise placing scripts on your PATH).

## Codex Automatic Mode (Wrapper)

Launch Codex through the wrapper:

```bash
remem-dev-sessions codex --
```

Equivalent shortcut:

```bash
remem-dev-sessions-codex
```

Behavior:

- Starts a new session ID (unless `REMEM_MEMORY_SESSION_ID` is set).
- Runs interval checkpoints in the background (default every 20 minutes).
- Captures a milestone checkpoint on Codex exit if git changes are detected.
- Writes a final rollup after exit (unless `--no-rollup`).

Useful flags:

```bash
remem-dev-sessions codex --interval-seconds 900 --checkpoint-on-start -- --model gpt-5
```

- `--interval-seconds`: checkpoint cadence
- `--checkpoint-on-start`: emit first checkpoint immediately
- `--always-checkpoint`: emit even if git status has not changed
- `--no-rollup`: disable final rollup
- `--dry-run`: log payloads without ingesting

If `REMEM_API_KEY` is not set, wrapper still writes local logs and skips API ingest.

Checkpoint:

```bash
remem-dev-sessions checkpoint \
  --project my-project \
  --session-id 2026-02-13-session-a \
  --kind interval \
  --summary "Implemented auth middleware refactor" \
  --decision "Keep API key auth behavior unchanged" \
  --next-action "Add regression tests" \
  --ingest
```

Rollup:

```bash
remem-dev-sessions rollup \
  --project my-project \
  --session-id 2026-02-13-session-a \
  --summary "Completed middleware refactor and tests" \
  --ingest
```

Recall:

```bash
remem-dev-sessions recall \
  --query "What did we decide about auth middleware?" \
  --mode rich \
  --synthesize \
  --checkpoint-project my-project \
  --checkpoint-session 2026-02-13-session-a
```

## MCP: Optional Add-On

This toolkit does not require MCP for ingest or recall.

If you want in-chat tool-based recall (`remem_query`), keep MCP enabled. The Claude plugin includes a `.mcp.json` server config that uses:

- `REMEM_API_URL` (default `https://api.remem.io`)
- `REMEM_API_KEY` (required)

If you only installed the Claude plugin and not the CLI commands, use MCP tools or direct API calls (`curl`) for recall queries.

## Verify Setup

Dry-run checkpoint:

```bash
remem-dev-sessions checkpoint --project smoke --session-id test --summary "ok" --dry-run --no-log
```

Dry-run rollup:

```bash
remem-dev-sessions rollup --project smoke --session-id test --dry-run --no-log
```

Dry-run recall:

```bash
remem-dev-sessions recall --query "smoke test" --dry-run --no-log
```
