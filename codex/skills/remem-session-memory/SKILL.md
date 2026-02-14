---
name: remem-session-memory
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Remem Session Memory

Legacy alias skill. Prefer `remem-dev-sessions` for new installs.

Use this workflow to persist coding-session progress into Remem so context survives memory resets across future sessions.

## Prerequisites

- `REMEM_API_URL` and `REMEM_API_KEY` must be set.
- Run `./install-codex-skill.sh` from this repository first.
- Use the Codex wrapper for automatic checkpoints.

## Recommended Launch

```bash
remem-dev-sessions codex --
```

This runs periodic interval checkpoints, emits a milestone checkpoint on exit when changes exist, and writes a final rollup.

## Checkpoint Workflow

Manual checkpoints are still available:

```bash
remem-dev-sessions checkpoint \
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
remem-dev-sessions rollup \
  --project remem \
  --session-id 2026-02-13-mcp-memory \
  --summary "Implemented session-memory MVP with checkpoint metadata filters." \
  --ingest
```

## Recall Pattern

Use raw API recall (MCP optional):

```bash
remem-dev-sessions recall \
  --query "What did we decide about checkpoint metadata?" \
  --mode rich \
  --synthesize \
  --checkpoint-project remem \
  --checkpoint-session 2026-02-13-mcp-memory
```

If MCP `remem_query` is available, use the same filters:

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
