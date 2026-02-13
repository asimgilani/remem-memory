---
name: session-memory
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Session Memory

Use this skill to store progress snapshots in Remem so future sessions can recover context quickly.

## Prerequisites

- Remem MCP server configured and available in Claude Code.
- `remem_ingest` and `remem_query` tools available.

## Workflow

1. During active coding, create a checkpoint every 20-30 minutes or after major decisions.
2. Store each checkpoint using `remem_ingest` with metadata keys:
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

Use `remem_query` with filters:

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
