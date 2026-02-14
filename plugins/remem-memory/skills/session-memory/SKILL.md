---
name: session-memory
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Session Memory

Use this skill to store progress snapshots in Remem so future sessions can recover context quickly.

## Prerequisites

- Set `REMEM_API_KEY` (and optionally `REMEM_API_URL`) in your shell environment.
- MCP is optional. Automatic checkpoints and rollups run through direct API calls.

## Automatic Mode (Claude Hooks)

When this plugin is enabled, hooks automatically:

1. Capture interval checkpoints from `Write`, `Edit`, `MultiEdit`, and `Bash` tool activity.
2. Capture milestone checkpoints on `Stop`.
3. Generate a final rollup on `SessionEnd`.

Tune behavior with environment variables:

- `REMEM_MEMORY_PROJECT`: override project key (default: current folder name).
- `REMEM_MEMORY_INTERVAL_SECONDS`: minimum seconds between interval checkpoints (default: 1200).
- `REMEM_MEMORY_MIN_EVENTS`: minimum tool events before interval checkpoint (default: 4).
- `REMEM_MEMORY_ROLLUP_ON_SESSION_END`: `1`/`0` toggle for final rollup.
- `REMEM_MEMORY_AUTO_ENABLED`: `1`/`0` global toggle.

If `REMEM_API_KEY` is not set, hooks keep local logs but skip ingest calls.

## Workflow

1. During active coding, create a checkpoint every 20-30 minutes or after major decisions.
2. Store each checkpoint with metadata keys:
   - `project`
   - `session_id`
   - `checkpoint_kind` (`interval`, `milestone`, `final`, `manual`)
3. At session end, create one rollup summary and ingest it as `checkpoint_kind: final`.

## Checkpoint Content Template

- What changed
- Key decisions
- Open questions
- Next actions
- Files touched

## Recall Pattern

Use raw API recall via helper command:

```bash
remem-dev-sessions recall \
  --query "What did we decide about query filters?" \
  --mode rich \
  --synthesize \
  --checkpoint-project my-project \
  --checkpoint-session 2026-02-13-session-a
```

If MCP `remem_query` is available, use the same filters:

```json
{
  "query": "What did we decide about query filters?",
  "mode": "rich",
  "synthesize": true,
  "filters": {
    "checkpoint_project": ["my-project"],
    "checkpoint_session": ["2026-02-13-session-a"]
  }
}
```

## Common Mistakes

- Missing `project` or `session_id` metadata.
- Writing checkpoints without decisions and next actions.
- Reusing session IDs across unrelated work.
