#!/usr/bin/env python3
"""Run the repository tests without access to ambient Remem credentials."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _UnavailableCredentialStore:
    def read(self, service: str, account: str | None = None) -> None:
        del service, account
        return None

    def write(self, service: str, account: str, value: str) -> None:
        del service, account, value
        raise AssertionError("unexpected platform credential-store write")


def _remove_ambient_credential_sources() -> None:
    for name in (
        "REMEM_API_KEY",
        "REMEM_API_KEY_FD",
        "REMEM_API_KEY_FILE",
    ):
        os.environ.pop(name, None)


def _block_default_credential_stores() -> None:
    for module in tuple(sys.modules.values()):
        path = getattr(module, "__file__", "") or ""
        if path.endswith("/remem_api.py") and hasattr(
            module,
            "default_keychain",
        ):
            module.default_keychain = _UnavailableCredentialStore


def main() -> int:
    _remove_ambient_credential_sources()
    names = [
        f"tests.{path.stem}"
        for path in sorted((ROOT / "tests").glob("test_*.py"))
    ]
    suite = unittest.TestLoader().loadTestsFromNames(names)
    _block_default_credential_stores()
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(
        "TEST_RESULT "
        f"tests={result.testsRun} "
        f"failures={len(result.failures)} "
        f"errors={len(result.errors)} "
        f"skipped={len(result.skipped)}"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
