#!/usr/bin/env python3
"""Compatibility entrypoint for secure Remem Memory setup."""

from __future__ import annotations

import sys
from typing import Optional, Sequence

if __package__:
    from .install_remem_memory import main as _secure_installer_main
else:
    from install_remem_memory import main as _secure_installer_main


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Delegate without retaining any legacy plaintext-key options."""

    arguments = sys.argv[1:] if argv is None else argv
    return _secure_installer_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
