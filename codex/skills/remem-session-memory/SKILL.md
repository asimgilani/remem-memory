---
name: remem-session-memory
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Remem Session Memory

Use this skill to persist coding-session progress into Remem so context survives memory resets across future sessions.

## Checkpoint Workflow

Run periodic checkpoints:

```bash
python remem-memory/scripts/remem_checkpoint.py \
  --project remem \
  --session-id 2026-02-13-mcp-memory \
  --kind interval \
  --summary "Added metadata merge and MCP filters for checkpoint recall." \
  --decision "Store user metadata in encrypted document metadata." \
  --next-action "Update docs-site and skill docs." \
  --ingest
```

## Rollup Workflow

At session end, run:

```bash
python remem-memory/scripts/remem_rollup.py \
  --project remem \
  --session-id 2026-02-13-mcp-memory \
  --summary "Implemented session-memory MVP with checkpoint metadata filters." \
  --ingest
```

## Recall Pattern

Use `remem_query` filters:

```json
{
  "query": "What did we decide about checkpoint metadata?",
  "mode": "rich",
  "synthesize": true,
  "filters": {
    "checkpoint_project": ["remem"],
    "checkpoint_session": ["2026-02-13-mcp-memory"]
  }
}
```
