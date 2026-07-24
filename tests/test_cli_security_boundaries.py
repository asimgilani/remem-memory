import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import (
    remem_checkpoint,
    remem_memory,
    remem_recall,
    remem_rollup,
)


class CanonicalDispatchSecurityTests(unittest.TestCase):
    def test_anonymous_payload_rejects_oversize_before_pipe_creation(
        self,
    ) -> None:
        with mock.patch.object(remem_memory.os, "pipe") as pipe:
            with self.assertRaises(ValueError):
                remem_memory._write_anonymous_payload(
                    b"x" * (remem_memory._MAX_PIPE_PAYLOAD_BYTES + 1)
                )
        pipe.assert_not_called()

    def test_anonymous_payload_rejects_zero_byte_write(self) -> None:
        with mock.patch.object(
            remem_memory.os,
            "pipe",
            return_value=(70, 71),
        ):
            with mock.patch.object(
                remem_memory.os,
                "write",
                return_value=0,
            ):
                with mock.patch.object(
                    remem_memory.os,
                    "close",
                ) as close:
                    with self.assertRaises(OSError):
                        remem_memory._write_anonymous_payload(b"secret")
        self.assertEqual(
            [call.args[0] for call in close.call_args_list],
            [70, 71],
        )

    def test_rejects_non_remem_origin_before_credential_or_child(self) -> None:
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_API_URL": "https://attacker.example",
            },
            clear=True,
        ):
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_api_key",
            ) as resolver:
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                ) as run:
                    with contextlib.redirect_stderr(stderr):
                        result = remem_memory.run_command(
                            "recall",
                            ["--query", "history"],
                        )

        self.assertEqual(result, 2)
        resolver.assert_not_called()
        run.assert_not_called()
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: invalid Remem API URL",
        )

    def test_loopback_never_falls_back_to_keychain(self) -> None:
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "REMEM_API_URL": "http://127.0.0.1:8000",
                "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
            },
            clear=True,
        ):
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_api_key",
            ) as resolver:
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                ) as run:
                    with contextlib.redirect_stderr(stderr):
                        result = remem_memory.run_command(
                            "recall",
                            ["--query", "history"],
                        )

        self.assertEqual(result, 2)
        resolver.assert_not_called()
        run.assert_not_called()
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: invalid Remem API URL",
        )

    def test_explicit_key_crosses_to_network_helper_only_by_anonymous_fd(
        self,
    ) -> None:
        canary = "vlt_explicit-fd-canary"
        captured = {}

        def run(arguments, **kwargs):
            environment = kwargs["env"]
            descriptor = int(environment["REMEM_API_KEY_FD"])
            captured["credential"] = os.read(descriptor, 4096).decode()
            captured["arguments"] = list(arguments)
            captured["environment"] = dict(environment)
            captured["pass_fds"] = tuple(kwargs["pass_fds"])
            return subprocess.CompletedProcess(arguments, 0)

        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/test/bin",
                "HOME": "/test/home",
                "REMEM_API_KEY": canary,
                "REMEM_API_URL": "https://api.remem.io",
            },
            clear=True,
        ):
            with mock.patch.object(
                remem_memory.subprocess,
                "run",
                side_effect=run,
            ):
                self.assertEqual(
                    remem_memory.run_command(
                        "recall",
                        ["--query", "history"],
                    ),
                    0,
                )

        self.assertEqual(captured["credential"], canary)
        self.assertNotIn("REMEM_API_KEY", captured["environment"])
        self.assertNotIn(canary, json.dumps(captured["arguments"]))
        self.assertEqual(
            captured["pass_fds"],
            (int(captured["environment"]["REMEM_API_KEY_FD"]),),
        )

    def test_selected_named_connection_crosses_only_by_anonymous_fd(
        self,
    ) -> None:
        named_account = "connection:0123456789abcdef0123456789abcdef"
        named_connection = remem_memory.remem_api.Connection(
            "conn_0123456789abcdef0123456789abcdef",
            "Named",
            named_account,
            True,
        )
        keychain = {
            (remem_memory.remem_api.KEYCHAIN_SERVICE, named_account): "named-key"
        }

        class LocalKeychain:
            def read(self, service, account=None):
                return keychain.get((service, account))

            def write(self, service, account, value):
                keychain[(service, account)] = value

        selected = remem_memory.remem_api.resolve_connection_api_key(
            named_connection,
            environment={"REMEM_API_KEY": "primary-ambient-key"},
            keychain=LocalKeychain(),
        )
        descriptor = remem_memory._write_anonymous_payload(
            selected.encode("utf-8")
        )
        child_environment = {"REMEM_API_KEY_FD": str(descriptor)}

        try:
            received = remem_memory.remem_api.consume_explicit_api_key(
                child_environment
            )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

        self.assertEqual(received, "named-key")
        self.assertNotIn("REMEM_API_KEY_FD", child_environment)
        self.assertNotEqual(received, "primary-ambient-key")

    def test_local_only_workflow_never_transports_or_resolves_credential(
        self,
    ) -> None:
        canary = "vlt_unused-local-canary"
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/test/bin",
                "HOME": "/test/home",
                "REMEM_API_KEY": canary,
            },
            clear=True,
        ):
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_api_key",
            ) as resolver:
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
                    self.assertEqual(
                        remem_memory.run_command(
                            "checkpoint",
                            ["--dry-run"],
                        ),
                        0,
                    )

        resolver.assert_not_called()
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("REMEM_API_KEY", child_environment)
        self.assertNotIn("REMEM_API_KEY_FD", child_environment)
        self.assertNotIn("pass_fds", run.call_args.kwargs)

    def test_rejects_all_api_key_option_prefixes_without_echoing_value(
        self,
    ) -> None:
        canary = "vlt_plaintext-prefix-canary"
        for option in ("--api-k", "--api-ke", "--api-key"):
            with self.subTest(option=option):
                stderr = io.StringIO()
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                ) as run:
                    with contextlib.redirect_stderr(stderr):
                        result = remem_memory.run_command(
                            "recall",
                            ["--query", "history", option, canary],
                        )
                self.assertEqual(result, 2)
                run.assert_not_called()
                self.assertNotIn(canary, stderr.getvalue())
                self.assertEqual(
                    stderr.getvalue().strip(),
                    (
                        "error: --api-key is not supported; "
                        "use remem-memory auth"
                    ),
                )


class RoutingCliSecurityTests(unittest.TestCase):
    def test_doctor_plugin_checks_use_a_secret_free_bounded_environment(
        self,
    ) -> None:
        canary = "vlt-doctor-plugin-env-secret"
        observed = []

        def run(arguments, **kwargs):
            observed.append((list(arguments), dict(kwargs["env"])))
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout=(
                    '{"plugins":[{"name":"remem-memory",'
                    '"enabled":true}]}'
                ),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "state"
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                {},
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": directory,
                    "PATH": "/test/bin",
                    "REMEM_MEMORY_DATA_DIR": str(data_dir),
                    "REMEM_API_KEY": canary,
                    "AWS_SECRET_ACCESS_KEY": canary,
                },
                clear=True,
            ):
                with mock.patch(
                    "shutil.which",
                    side_effect=lambda command, path=None: f"/test/{command}",
                ):
                    with mock.patch.object(
                        remem_memory.subprocess,
                        "run",
                        side_effect=run,
                    ):
                        with mock.patch.object(
                            remem_memory.remem_api,
                            "resolve_connection_api_key",
                            return_value="available",
                        ):
                            with contextlib.redirect_stdout(io.StringIO()):
                                remem_memory.main(["doctor", "--json"])

        self.assertEqual(len(observed), 2)
        for arguments, environment in observed:
            self.assertEqual(
                arguments[1:],
                ["plugin", "list", "--json"],
            )
            self.assertNotIn(canary, json.dumps(environment))
            self.assertNotIn("REMEM_API_KEY", environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)

    def test_named_key_never_enters_arguments_environment_routes_or_output(
        self,
    ) -> None:
        canary = "vlt-routing-cli-secret-canary"
        captured = {}
        stdout = io.StringIO()
        stderr = io.StringIO()

        def store(account, value):
            captured["account"] = account
            captured["value"] = value
            captured["argv"] = list(os.sys.argv)
            captured["environment"] = dict(os.environ)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {
                    "REMEM_MEMORY_DATA_DIR": directory,
                    "REMEM_API_KEY": "primary-only",
                },
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory.getpass,
                    "getpass",
                    return_value=canary,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "store_keychain_api_key",
                        side_effect=store,
                    ):
                        with mock.patch.object(
                            remem_memory.remem_api,
                            "resolve_keychain_api_key",
                            return_value=canary,
                        ):
                            with contextlib.redirect_stdout(stdout):
                                with contextlib.redirect_stderr(stderr):
                                    result = remem_memory.main(
                                        ["connections", "add", "Private"]
                                    )
            routes = (
                Path(directory) / "routes.json"
            ).read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertEqual(captured["value"], canary)
        self.assertNotIn(canary, json.dumps(captured["argv"]))
        self.assertNotIn(canary, json.dumps(captured["environment"]))
        self.assertEqual(
            captured["environment"]["REMEM_API_KEY"],
            "primary-only",
        )
        self.assertNotIn(canary, routes)
        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())

    def test_connection_add_suppresses_secret_bearing_exception(self) -> None:
        canary = "vlt-routing-cli-error-canary"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_DATA_DIR": directory},
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory.getpass,
                    "getpass",
                    return_value=canary,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "store_keychain_api_key",
                        side_effect=RuntimeError(canary),
                    ):
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                result = remem_memory.main(
                                    ["connections", "add", "Private"]
                                )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "error: unable to configure Remem connection\n",
        )
        self.assertNotIn(canary, stderr.getvalue())


class DirectHelperSecurityTests(unittest.TestCase):
    def test_direct_helpers_reject_api_key_abbreviations_without_echo(
        self,
    ) -> None:
        canary = "vlt_direct-plaintext-canary"
        cases = (
            (
                remem_recall,
                ["--query", "history"],
            ),
            (
                remem_checkpoint,
                ["--project", "p", "--session-id", "s"],
            ),
            (
                remem_rollup,
                ["--project", "p", "--session-id", "s"],
            ),
        )
        for module, base_arguments in cases:
            for option in ("--api-k", "--api-ke", "--api-key"):
                with self.subTest(
                    module=module.__name__,
                    option=option,
                ):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        result = module.main(
                            [*base_arguments, option, canary]
                        )
                    self.assertEqual(result, 2)
                    self.assertNotIn(canary, stderr.getvalue())
                    self.assertEqual(
                        stderr.getvalue().strip(),
                        (
                            "error: --api-key is not supported; "
                            "use remem-memory auth"
                        ),
                    )

    def test_dry_run_helpers_never_resolve_a_credential(self) -> None:
        cases = (
            (
                remem_recall,
                ["--query", "history", "--dry-run", "--no-log"],
            ),
            (
                remem_checkpoint,
                [
                    "--project",
                    "p",
                    "--session-id",
                    "s",
                    "--dry-run",
                    "--no-log",
                ],
            ),
            (
                remem_rollup,
                [
                    "--project",
                    "p",
                    "--session-id",
                    "s",
                    "--dry-run",
                    "--no-log",
                ],
            ),
        )
        for module, arguments in cases:
            with self.subTest(module=module.__name__):
                stdout = io.StringIO()
                with mock.patch.object(
                    module.remem_api,
                    "resolve_api_access",
                ) as resolve:
                    with contextlib.redirect_stdout(stdout):
                        self.assertEqual(module.main(arguments), 0)
                resolve.assert_not_called()

    def test_recall_resolves_validated_access_only_when_networking(
        self,
    ) -> None:
        with mock.patch.object(
            remem_recall.remem_api,
            "resolve_api_access",
            return_value=(
                "https://api.remem.io",
                "in-process-key",
            ),
        ) as resolve:
            with mock.patch.object(
                remem_recall,
                "query_remem",
                return_value={"results": []},
            ) as query:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        remem_recall.main(
                            [
                                "--query",
                                "history",
                                "--no-log",
                            ]
                        ),
                        0,
                    )

        resolve.assert_called_once()
        query.assert_called_once_with(
            api_url="https://api.remem.io",
            api_key="in-process-key",
            payload={
                "query": "history",
                "mode": "fast",
                "max_results": 10,
            },
        )
