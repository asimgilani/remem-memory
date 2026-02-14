---
name: remem-dev-sessions
description: Use when coding sessions need periodic checkpoints and end-of-session rollups persisted to Remem with project/session metadata for later recall.
---

# Remem Dev Sessions

Use this skill to persist coding-session progress into Remem so context survives memory resets across future sessions.

## Prerequisites

- `REMEM_API_URL` and `REMEM_API_KEY` must be set.
- Run `./install-codex-skill.sh` from this repository first.
- MCP is optional. This workflow works via raw API commands.

## Checkpoint Workflow

Run periodic checkpoints:

```bash
remem-dev-sessions checkpoint \
  --project remem \
  --session-id 2026-02-13-mcp-memory \
  --kind interval \
  --summary "Added metadata merge and checkpoint query filters." \
  --decision "Store user metadata in encrypted document metadata." \
  --next-action "Update docs-site and migration notes." \
  --ingest
```

## Rollup Workflow

At session end, run:

```bash
remem-dev-sessions rollup \
  --project remem \
  --session-id 2026-02-13-mcp-memory \
  --summary "Implemented session-memory workflow and docs updates." \
  --ingest
```

## Recall Workflow (Raw API)

```bash
remem-dev-sessions recall \
  --query "What did we decide about checkpoint metadata?" \
  --mode rich \
  --synthesize \
  --checkpoint-project remem \
  --checkpoint-session 2026-02-13-mcp-memory
```

## MCP Recall (Optional)

If `remem_query` is available via MCP, you can use the same filter keys:

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
