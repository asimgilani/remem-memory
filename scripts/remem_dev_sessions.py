#!/usr/bin/env python3
"""Unified CLI for Remem coding-session memory workflows."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_COMMAND_TO_SCRIPT = {
    "checkpoint": "remem_checkpoint.py",
    "rollup": "remem_rollup.py",
    "recall": "remem_recall.py",
}


def parse_args(argv: list[str]) -> tuple[str, list[str]]:
    parser = argparse.ArgumentParser(
        prog="remem-dev-sessions",
        description="Run checkpoint, rollup, and recall workflows for Remem session memory.",
    )
    parser.add_argument("command", choices=sorted(_COMMAND_TO_SCRIPT.keys()))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)
    remaining = list(ns.args)
    if remaining and remaining[0] == "--":
        remaining = remaining[1:]
    return str(ns.command), remaining


def run_command(command: str, forwarded_args: list[str]) -> int:
    script_name = _COMMAND_TO_SCRIPT[command]
    script_path = Path(__file__).resolve().with_name(script_name)
    if not script_path.exists():
        print(f"error: missing helper script: {script_path}", file=sys.stderr)
        return 2
    result = subprocess.run([sys.executable, str(script_path), *forwarded_args], check=False)
    return int(result.returncode)


def main(argv: list[str] | None = None) -> int:
    command, forwarded_args = parse_args(argv or sys.argv[1:])
    return run_command(command, forwarded_args)


if __name__ == "__main__":
    raise SystemExit(main())
