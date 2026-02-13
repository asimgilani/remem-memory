---
name: remem-session-memory
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Remem Session Memory

Use this skill to persist coding-session progress into Remem so context survives memory resets across future sessions.

## Prerequisites

- `REMEM_API_URL` and `REMEM_API_KEY` must be set.
- Run `./install-codex-skill.sh` from the `remem-memory` repository first.
- This skill does not create timed background checkpoints by itself; invoke helper commands during work or from your own scheduler.

## Checkpoint Workflow

Run periodic checkpoints:

```bash
remem-memory-checkpoint \
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
remem-memory-rollup \
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
