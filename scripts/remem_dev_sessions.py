#!/usr/bin/env python3
"""Backward-compatible alias for the canonical Remem Memory CLI."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from scripts import remem_memory
except ImportError:
    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import remem_memory


def main(argv=None) -> int:
    return remem_memory.main(
        list(sys.argv[1:] if argv is None else argv)
    )


if __name__ == "__main__":
    raise SystemExit(main())
