# Remem Dev Sessions for Codex

Guide for using Remem session memory with OpenAI Codex.

## Quick Install (Agent-Driven)

Tell Codex:

```text
Fetch and follow instructions from https://raw.githubusercontent.com/asimgilani/remem-memory/refs/heads/master/.codex/INSTALL.md
```

## Manual Install

See `.codex/INSTALL.md` for full steps.

## Launch

Start Codex from your project folder:

```bash
remem-codex
```

This wrapper creates interval checkpoints and a final rollup automatically.

## Required Environment Variables

- `REMEM_API_URL` (usually `https://api.remem.io`)
- `REMEM_API_KEY` (`vlt_...`)

Without `REMEM_API_KEY`, local checkpoint logs still write, but API ingest is skipped.

## MCP in Codex

Codex MCP config is installed automatically by `./install-codex-skill.sh`.

Verify:

```bash
rg -n "mcp_servers.remem" ~/.codex/config.toml
```

After restarting Codex, `remem_query` should be available in Codex MCP tooling.
