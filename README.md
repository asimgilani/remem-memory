# remem-dev-sessions

API-first coding-session memory workflows for Remem.

This repository is still hosted as `remem-memory`, but the toolkit name is now `remem-dev-sessions`.

## Codex Quick Install

Tell Codex:

```text
Fetch and follow instructions from https://raw.githubusercontent.com/asimgilani/remem-memory/refs/heads/master/.codex/INSTALL.md
```

Detailed Codex guide: `docs/README.codex.md`

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
  - `scripts/install_codex_mcp.py` (writes Codex MCP config)

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
- `PreCompact` for milestone checkpoints before context compaction
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

Optional LLM-backed summaries (recommended):

- Produces narrative summaries plus populated `decisions`, `open_questions`, and `next_actions`.
- Default provider order: Claude CLI (`claude`) -> Codex CLI (`codex`) -> Anthropic API -> OpenAI API.

```bash
export REMEM_MEMORY_SUMMARY_ENABLED="1"           # default: enabled; requires claude/codex CLI or API key
export REMEM_MEMORY_SUMMARY_PROVIDER="claude_cli" # claude_cli|codex_cli|anthropic|openai
export REMEM_MEMORY_SUMMARY_MODEL="haiku"         # provider-specific model id/alias
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
  - `~/.local/bin/remem-codex`
  - `~/.local/bin/remem-dev-sessions-checkpoint`
  - `~/.local/bin/remem-dev-sessions-rollup`
  - `~/.local/bin/remem-dev-sessions-recall`
- Legacy aliases:
  - `~/.local/bin/remem-memory-codex`
  - `~/.local/bin/remem-memory-checkpoint`
  - `~/.local/bin/remem-memory-rollup`
  - `~/.local/bin/remem-memory-recall`
- Codex MCP config block in `~/.codex/config.toml` (`mcp_servers.remem`)

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

Short alias:

```bash
remem-codex
```

Behavior:

- Starts a new session ID (unless `REMEM_MEMORY_SESSION_ID` is set).
- Runs interval checkpoints in the background (default every 20 minutes).
- Captures a milestone checkpoint on Codex exit if git changes are detected.
- Writes a final rollup after exit (unless `--no-rollup`).
- Reads Codex session transcripts and generates structured checkpoint/rollup summaries
  (`summary`, `decisions`, `open_questions`, `next_actions`) using Codex CLI.

Codex summary tuning:

```bash
export REMEM_MEMORY_SUMMARY_ENABLED="1"             # default: enabled
export REMEM_MEMORY_SUMMARY_PROVIDER="codex_cli"    # wrapper supports codex_cli
export REMEM_MEMORY_SUMMARY_MODEL="gpt-5.3-codex-spark"
export REMEM_MEMORY_SUMMARY_TIMEOUT_SECONDS="15"    # default: 15
```

Optional transcript discovery override:

```bash
export REMEM_MEMORY_CODEX_SESSIONS_DIR="$HOME/.codex/sessions"
```

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

## MCP in Codex and Claude

- Claude plugin bundles `.mcp.json` in `plugins/remem-memory`.
- Codex install now writes `mcp_servers.remem` into `~/.codex/config.toml` via `scripts/install_codex_mcp.py`.

For Codex, verify MCP config after install:

```bash
rg -n "mcp_servers.remem" ~/.codex/config.toml
```

If you change `REMEM_API_KEY` later, rerun `./install-codex-skill.sh` to refresh the Codex MCP env block.

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
