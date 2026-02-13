# remem-memory

Reusable session-memory workflows for Remem users, distributed independently from the private Remem backend repository.

## What this package contains

- Claude marketplace manifest: `.claude-plugin/marketplace.json`
- Claude plugin: `plugins/remem-memory`
  - Skill: `session-memory`
  - Hooks: `hooks/hooks.json`
  - Hook runner: `scripts/auto_memory_hook.py`
- Codex skill: `codex/skills/remem-session-memory`
- Helper scripts:
  - `scripts/remem_checkpoint.py`
  - `scripts/remem_rollup.py`

## Prerequisites

- Python 3.10+
- `httpx` installed
- A Remem API key (`vlt_...`)
- Environment variables:

```bash
export REMEM_API_URL="https://api.remem.io"
export REMEM_API_KEY="vlt_your_key"
```

Install Python dependency:

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
/plugin install remem-memory@remem-memory
```

3. Restart Claude Code.

## Claude Auto Checkpoints

The Claude plugin now runs automatic hooks:

- `PostToolUse` (`Write|Edit|MultiEdit|Bash`) for interval checkpoints
- `TaskCompleted` for milestone checkpoints
- `SessionEnd` for final rollup

If `REMEM_API_KEY` is unset, hooks still write local checkpoint logs but skip API ingest.

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

- Skill symlink: `~/.agents/skills/remem-session-memory`
- Helper commands:
  - `~/.local/bin/remem-memory-checkpoint`
  - `~/.local/bin/remem-memory-rollup`

Restart Codex after installation.

## Codex Behavior

Codex installation is different from Claude plugins:

- Codex uses local skills + helper commands (no Claude plugin marketplace).
- The installed skill guides checkpoint/rollup workflow.
- Automatic timed/background checkpoints are not native in Codex skill loading; use helper commands explicitly, or schedule with your own automation (for example cron/launchd or Codex app automations).

## Checkpoint examples

Periodic checkpoint:

```bash
remem-memory-checkpoint \
  --project my-project \
  --session-id 2026-02-13-session-a \
  --kind interval \
  --summary "Implemented auth middleware refactor" \
  --decision "Keep API key auth behavior unchanged" \
  --next-action "Add regression tests" \
  --ingest
```

End-of-session rollup:

```bash
remem-memory-rollup \
  --project my-project \
  --session-id 2026-02-13-session-a \
  --summary "Completed middleware refactor and tests" \
  --ingest
```

## Verify setup

Dry-run checkpoint (no API write):

```bash
remem-memory-checkpoint --project smoke --session-id test --summary "ok" --dry-run --no-log
```

Dry-run rollup:

```bash
remem-memory-rollup --project smoke --session-id test --dry-run --no-log
```
