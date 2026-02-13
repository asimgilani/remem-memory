# remem-memory

Reusable session-memory workflows for Remem users, designed to be shared independently from the private Remem backend repo.

## What this package contains

- Claude plugin marketplace entry (`.claude-plugin/marketplace.json`)
- Claude plugin (`plugins/remem-memory`)
  - Skill: `session-memory`
- Codex skill (`codex/skills/remem-session-memory`)
- Portable checkpoint scripts:
  - `scripts/remem_checkpoint.py`
  - `scripts/remem_rollup.py`

## Prerequisites

- A Remem API key (`vlt_...`)
- Environment variables:

```bash
export REMEM_API_URL="https://api.remem.io"
export REMEM_API_KEY="vlt_your_key"
```

- Remem MCP configured in your agent environment if you want direct `remem_query` / `remem_ingest` tool usage.

## Install in Claude Code (local marketplace)

From the Remem repo root:

1. Add marketplace:

```text
/plugin marketplace add ./remem-memory
```

2. Install plugin:

```text
/plugin install remem-memory@remem-memory
```

3. Restart Claude Code.

## Install in Codex

Run:

```bash
./remem-memory/install-codex-skill.sh
```

Then restart Codex.

## Checkpoint examples

Periodic checkpoint:

```bash
python remem-memory/scripts/remem_checkpoint.py \
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
python remem-memory/scripts/remem_rollup.py \
  --project my-project \
  --session-id 2026-02-13-session-a \
  --summary "Completed middleware refactor and tests" \
  --ingest
```

## Publishing as its own repo

This directory is intentionally self-contained. To publish:

1. Copy `remem-memory/` into a new git repository.
2. Update plugin `repository` URL in `plugins/remem-memory/.claude-plugin/plugin.json`.
3. Tag versions (for example `v0.1.0`).
4. Share installation instructions from this README.
