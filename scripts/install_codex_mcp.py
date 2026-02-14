#!/usr/bin/env python3
"""Install or update Remem MCP server configuration for Codex."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

DEFAULT_API_URL = "https://api.remem.io"
DEFAULT_MCP_REF = "git+https://github.com/asimgilani/remem.git@master#subdirectory=packages/remem-mcp"


def _escape_toml(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _strip_server_blocks(text: str, server_name: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    skip = False
    pat = re.compile(rf"^\[mcp_servers\.{re.escape(server_name)}(?:\.env)?\]\s*$")

    for line in lines:
        if pat.match(line):
            skip = True
            continue
        if skip and line.startswith("["):
            skip = False
        if not skip:
            out.append(line)

    while out and not out[-1].strip():
        out.pop()

    return ("\n".join(out) + "\n") if out else ""


def build_block(server_name: str, api_url: str, api_key: str, mcp_ref: str) -> str:
    url = _escape_toml(api_url.strip() or DEFAULT_API_URL)
    key = _escape_toml(api_key.strip() or "vlt_your_key_here")
    ref = _escape_toml(mcp_ref)

    return (
        f"[mcp_servers.{server_name}]\n"
        'command = "uvx"\n'
        f'args = ["-q", "--from", "{ref}", "remem-mcp"]\n\n'
        f"[mcp_servers.{server_name}.env]\n"
        f'REMEM_API_URL = "{url}"\n'
        f'REMEM_API_KEY = "{key}"\n'
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-name", default="remem", help="MCP server name in ~/.codex/config.toml")
    parser.add_argument(
        "--config",
        default=os.path.expanduser("~/.codex/config.toml"),
        help="Path to Codex config.toml",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("REMEM_API_URL", DEFAULT_API_URL),
        help="Remem API URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("REMEM_API_KEY", ""),
        help="Remem API key",
    )
    parser.add_argument(
        "--mcp-ref",
        default=DEFAULT_MCP_REF,
        help="uvx --from reference for remem-mcp",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    cleaned = _strip_server_blocks(existing, args.server_name)
    block = build_block(args.server_name, args.api_url, args.api_key, args.mcp_ref)

    new_text = (cleaned + "\n" + block).lstrip("\n")
    config_path.write_text(new_text, encoding="utf-8")

    key_set = bool(args.api_key.strip())
    print(f"Updated Codex MCP config: {config_path}")
    print(f"Server: {args.server_name}")
    print("API key source:", "REMEM_API_KEY env" if key_set else "placeholder (set REMEM_API_KEY and rerun install)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
