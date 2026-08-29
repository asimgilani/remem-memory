from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SCRIPTS = ROOT / "plugins" / "remem-memory" / "scripts"
if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

import remem_api  # noqa: E402


CANARY = "remem-linux-credential-canary"


class RecordingRunner:
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        self.result = result
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        return self.result


class LinuxSecretServiceTests(unittest.TestCase):
    def test_runtime_read_uses_locked_search_without_secret_in_process_data(
        self,
    ) -> None:
        runner = RecordingRunner(
            subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "[/org/freedesktop/secrets/collection/login/1]\n"
                    "label = Remem Memory\n"
                    f"secret = {CANARY}\n"
                    "attribute.account = default\n"
                    "attribute.service = io.remem.memory\n"
                ),
                stderr="",
            )
        )
        environment = {
            "PATH": "/usr/bin",
            "HOME": "/home/tester",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
            "LD_PRELOAD": CANARY,
            "REMEM_API_KEY": CANARY,
        }
        store = remem_api.LinuxSecretServiceKeychain(
            runner=runner,
            environment=environment,
            executable="/usr/bin/secret-tool",
        )

        self.assertEqual(
            store.read(remem_api.KEYCHAIN_SERVICE, remem_api.KEYCHAIN_ACCOUNT),
            CANARY,
        )
        self.assertEqual(len(runner.calls), 1)
        command, options = runner.calls[0]
        self.assertEqual(
            command,
            [
                "/usr/bin/secret-tool",
                "search",
                "service",
                "io.remem.memory",
                "account",
                "default",
            ],
        )
        self.assertNotIn("--unlock", command)
        self.assertNotIn("lookup", command)
        self.assertNotIn(CANARY, command)
        self.assertTrue(options["capture_output"])
        self.assertTrue(options["text"])
        self.assertNotIn("LD_PRELOAD", options["env"])
        self.assertNotIn("REMEM_API_KEY", options["env"])
        self.assertNotIn(CANARY, repr(options["env"]))

    def test_runtime_read_rejects_ambiguous_search_results(self) -> None:
        runner = RecordingRunner(
            subprocess.CompletedProcess(
                [],
                0,
                stdout=f"secret = {CANARY}\nsecret = second-canary\n",
                stderr="",
            )
        )
        store = remem_api.LinuxSecretServiceKeychain(
            runner=runner,
            environment={"PATH": "/usr/bin"},
            executable="/usr/bin/secret-tool",
        )

        with self.assertRaisesRegex(
            remem_api.RememKeychainError,
            "Remem credential lookup failed",
        ):
            store.read(remem_api.KEYCHAIN_SERVICE, remem_api.KEYCHAIN_ACCOUNT)

    def test_runtime_read_treats_locked_or_missing_collection_as_absent(
        self,
    ) -> None:
        runner = RecordingRunner(
            subprocess.CompletedProcess(
                [],
                1,
                stdout="",
                stderr="The collection is locked\n",
            )
        )
        store = remem_api.LinuxSecretServiceKeychain(
            runner=runner,
            environment={"PATH": "/usr/bin"},
            executable="/usr/bin/secret-tool",
        )

        self.assertIsNone(
            store.read(remem_api.KEYCHAIN_SERVICE, remem_api.KEYCHAIN_ACCOUNT)
        )

    def test_deliberate_write_passes_secret_only_over_stdin(self) -> None:
        runner = RecordingRunner(
            subprocess.CompletedProcess([], 0, stdout="", stderr="")
        )
        store = remem_api.LinuxSecretServiceKeychain(
            runner=runner,
            environment={"PATH": "/usr/bin"},
            executable="/usr/bin/secret-tool",
        )

        store.write(
            remem_api.KEYCHAIN_SERVICE,
            remem_api.KEYCHAIN_ACCOUNT,
            CANARY,
        )

        command, options = runner.calls[0]
        self.assertEqual(
            command[0:3],
            [
                "/usr/bin/secret-tool",
                "store",
                "--label=Remem Memory",
            ],
        )
        self.assertEqual(
            command[-4:],
            ["service", "io.remem.memory", "account", "default"],
        )
        self.assertNotIn(CANARY, command)
        self.assertEqual(options["input"], CANARY)
        self.assertNotIn(CANARY, repr(options["env"]))

    def test_default_store_is_selected_by_platform(self) -> None:
        with mock.patch.object(remem_api.sys, "platform", "linux"):
            self.assertIsInstance(
                remem_api.default_keychain(),
                remem_api.LinuxSecretServiceKeychain,
            )
        with mock.patch.object(remem_api.sys, "platform", "darwin"):
            self.assertIsInstance(
                remem_api.default_keychain(),
                remem_api.MacOSKeychain,
            )


class SystemdCredentialFileTests(unittest.TestCase):
    def _credential_file(self, root: str, value: str = CANARY) -> Path:
        directory = Path(root) / "credentials"
        directory.mkdir(mode=0o700)
        path = directory / "remem-api-key"
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_secure_systemd_credential_file_is_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root)
            environment = {
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }

            self.assertEqual(
                remem_api.consume_explicit_api_key(environment),
                CANARY,
            )
            self.assertNotIn("REMEM_API_KEY_FILE", environment)

    def test_precedence_is_fd_then_environment_then_file_then_store(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root, "file-canary")
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"fd-canary")
            os.close(write_fd)
            environment = {
                "REMEM_API_KEY_FD": str(read_fd),
                "REMEM_API_KEY": "environment-canary",
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }
            store = mock.Mock()
            store.read.return_value = "store-canary"

            self.assertEqual(
                remem_api.resolve_api_key(environment, keychain=store),
                "fd-canary",
            )
            store.read.assert_not_called()

            environment = {
                "REMEM_API_KEY": "environment-canary",
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }
            self.assertEqual(
                remem_api.resolve_api_key(environment, keychain=store),
                "environment-canary",
            )
            store.read.assert_not_called()

            environment = {
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }
            self.assertEqual(
                remem_api.resolve_api_key(environment, keychain=store),
                "file-canary",
            )
            store.read.assert_not_called()

            self.assertEqual(
                remem_api.resolve_api_key({}, keychain=store),
                "store-canary",
            )

    def test_file_override_applies_only_to_primary_connection(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root, "file-canary")
            environment = {
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }
            primary = remem_api.Connection(
                "primary",
                "Primary",
                remem_api.KEYCHAIN_ACCOUNT,
                True,
            )
            named_account = "connection:" + ("a" * 32)
            named = remem_api.Connection(
                "conn_" + ("a" * 32),
                "Named",
                named_account,
                True,
            )
            store = mock.Mock()
            store.read.return_value = "named-store-canary"

            self.assertEqual(
                remem_api.resolve_connection_api_key(
                    primary,
                    environment=environment,
                    keychain=store,
                ),
                "file-canary",
            )
            store.read.assert_not_called()
            self.assertEqual(
                remem_api.resolve_connection_api_key(
                    named,
                    environment=environment,
                    keychain=store,
                ),
                "named-store-canary",
            )
            store.read.assert_called_once_with(
                remem_api.KEYCHAIN_SERVICE,
                named_account,
            )

    def test_requested_but_insecure_file_fails_closed_before_store(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root)
            path.chmod(0o644)
            store = mock.Mock()
            store.read.return_value = "store-canary"
            environment = {
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }

            self.assertIsNone(
                remem_api.resolve_api_key(environment, keychain=store)
            )
            store.read.assert_not_called()

    def test_shared_credential_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root)
            path.parent.chmod(0o755)
            environment = {
                "CREDENTIALS_DIRECTORY": str(path.parent),
                "REMEM_API_KEY_FILE": str(path),
            }

            self.assertIsNone(
                remem_api.consume_explicit_api_key(environment)
            )

    def test_file_must_be_direct_child_without_symlink_or_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root)
            outside = Path(root) / "outside"
            outside.write_text(CANARY, encoding="utf-8")
            outside.chmod(0o600)
            symlink = path.parent / "linked-key"
            symlink.symlink_to(outside)
            cases = (str(outside), str(symlink), str(path.parent / ".." / "outside"))
            for candidate in cases:
                with self.subTest(candidate=candidate):
                    environment = {
                        "CREDENTIALS_DIRECTORY": str(path.parent),
                        "REMEM_API_KEY_FILE": candidate,
                    }
                    self.assertIsNone(
                        remem_api.consume_explicit_api_key(environment)
                    )

    def test_non_regular_and_oversized_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = self._credential_file(root)
            directory = path.parent
            oversized = directory / "oversized"
            oversized.write_bytes(b"x" * (16 * 1024 + 1))
            oversized.chmod(0o600)
            nested = directory / "nested"
            nested.mkdir(mode=0o700)
            for candidate in (oversized, nested):
                with self.subTest(candidate=candidate):
                    environment = {
                        "CREDENTIALS_DIRECTORY": str(directory),
                        "REMEM_API_KEY_FILE": str(candidate),
                    }
                    self.assertIsNone(
                        remem_api.consume_explicit_api_key(environment)
                    )


if __name__ == "__main__":
    unittest.main()
