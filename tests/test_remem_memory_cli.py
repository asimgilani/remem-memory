import asyncio
import contextlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN_SCRIPTS = _ROOT / "plugins" / "remem-memory" / "scripts"
sys.path.insert(0, str(_PLUGIN_SCRIPTS))

import remem_routing  # noqa: E402
from scripts import remem_dev_sessions, remem_memory  # noqa: E402
from tests.test_mcp_identifier_security import (  # noqa: E402
    _SERVER as bundled_mcp_server,
)


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


remem_api = load_script("remem_api_cli_tests", _PLUGIN_SCRIPTS / "remem_api.py")
launcher = load_script(
    "remem_mcp_launcher_tests",
    _PLUGIN_SCRIPTS / "remem_mcp_launcher.py",
)


class CanonicalCliTests(unittest.TestCase):
    def test_canonical_cli_routes_existing_workflows(self):
        expected = {
            "checkpoint": "remem_checkpoint.py",
            "rollup": "remem_rollup.py",
            "recall": "remem_recall.py",
            "codex": "remem_codex_wrapper.py",
        }

        for command, script_name in expected.items():
            with self.subTest(command=command):
                self.assertEqual(
                    remem_memory.resolve_command(command).name,
                    script_name,
                )

    def test_legacy_cli_uses_canonical_dispatch(self):
        with mock.patch.object(
            remem_dev_sessions.remem_memory,
            "main",
            return_value=17,
        ) as canonical:
            self.assertEqual(
                remem_dev_sessions.main(["recall", "--query", "x"]),
                17,
            )
        canonical.assert_called_once_with(["recall", "--query", "x"])

    def test_all_legacy_alias_basenames_infer_the_canonical_workflow(self):
        expected = {
            "remem-dev-sessions-codex": "codex",
            "remem-codex": "codex",
            "remem-memory-codex": "codex",
            "remem-dev-sessions-checkpoint": "checkpoint",
            "remem-memory-checkpoint": "checkpoint",
            "remem-session-memory-checkpoint": "checkpoint",
            "remem-dev-sessions-rollup": "rollup",
            "remem-memory-rollup": "rollup",
            "remem-session-memory-rollup": "rollup",
            "remem-dev-sessions-recall": "recall",
            "remem-memory-recall": "recall",
            "remem-session-memory-recall": "recall",
        }
        for basename, command in expected.items():
            with self.subTest(basename=basename):
                self.assertEqual(
                    remem_memory.infer_alias_command(basename),
                    command,
                )

    def test_workflow_helpers_ignore_a_repository_virtual_environment(self):
        completed = subprocess.CompletedProcess([], 0)
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            candidate = repository_root / ".venv" / "bin" / "python"
            candidate.parent.mkdir(parents=True)
            candidate.touch()
            with mock.patch.object(
                remem_memory,
                "_REPOSITORY_ROOT",
                repository_root,
            ):
                with mock.patch.object(
                    remem_memory.sys,
                    "executable",
                    "/test/system/python",
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_api_key",
                        return_value=None,
                    ):
                        with mock.patch.object(
                            remem_memory.subprocess,
                            "run",
                            return_value=completed,
                        ) as run:
                            self.assertEqual(
                                remem_memory.run_command(
                                    "recall",
                                    ["--query", "x"],
                                ),
                                0,
                            )

        invocation = run.call_args.args[0]
        self.assertEqual(invocation[0], "/test/system/python")
        self.assertEqual(invocation[1], "-I")
        self.assertEqual(Path(invocation[2]).name, "remem_recall.py")
        self.assertEqual(invocation[3:], ["--query", "x"])

    def test_workflow_helpers_fall_back_without_a_repository_venv(self):
        completed = subprocess.CompletedProcess([], 0)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                remem_memory,
                "_REPOSITORY_ROOT",
                Path(directory),
            ):
                with mock.patch.object(
                    remem_memory.sys,
                    "executable",
                    "/test/system/python",
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_api_key",
                        return_value=None,
                    ):
                        with mock.patch.object(
                            remem_memory.subprocess,
                            "run",
                            return_value=completed,
                        ) as run:
                            self.assertEqual(
                                remem_memory.run_command("checkpoint", []),
                                0,
                            )

        invocation = run.call_args.args[0]
        self.assertEqual(invocation[0], "/test/system/python")
        self.assertEqual(invocation[1], "-I")
        self.assertEqual(Path(invocation[2]).name, "remem_checkpoint.py")

    def test_manual_workflows_transport_explicit_key_only_by_descriptor(
        self,
    ):
        canary = "vlt_manual-keychain-secret-canary"
        parent_environment = {
            "PATH": "/test/bin",
            "HOME": "/test/home",
            "REMEM_API_KEY": canary,
            "REMEM_MEMORY_PROJECT": "preserved-project",
            "UNRELATED_SETTING": "not-forwarded",
            "SSH_AUTH_SOCK": "/test/agent.sock",
            "AWS_PROFILE": "engineering",
            "PYTHONPATH": "/untrusted/python",
            "PYTHONINSPECT": "1",
            "DYLD_INSERT_LIBRARIES": "/untrusted/capture.dylib",
            "LD_PRELOAD": "/untrusted/capture.so",
            "GIT_CONFIG_GLOBAL": "/untrusted/gitconfig",
        }
        completed = subprocess.CompletedProcess([], 0)
        observed_credentials = []
        observed_calls = []
        stdout = io.StringIO()
        stderr = io.StringIO()

        def run_helper(arguments, **kwargs):
            child_environment = kwargs["env"]
            descriptor_value = child_environment.get(
                "REMEM_API_KEY_FD",
            )
            if descriptor_value is not None:
                observed_credentials.append(
                    os.read(
                        int(descriptor_value),
                        8192,
                    ).decode("utf-8")
                )
            observed_calls.append(
                (
                    list(arguments),
                    dict(child_environment),
                    tuple(kwargs.get("pass_fds", ())),
                )
            )
            return completed

        with mock.patch.dict(
            os.environ,
            parent_environment,
            clear=True,
        ):
            original_environment = dict(os.environ)
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_api_key",
            ) as resolve:
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    side_effect=run_helper,
                ) as run:
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            for command in (
                                "checkpoint",
                                "rollup",
                                "recall",
                                "codex",
                            ):
                                self.assertEqual(
                                    remem_memory.run_command(command, []),
                                    0,
                                )
            self.assertEqual(dict(os.environ), original_environment)

        resolve.assert_not_called()
        self.assertEqual(run.call_count, 4)
        self.assertEqual(observed_credentials, [canary, canary])
        for arguments, child_environment, pass_fds in observed_calls:
            self.assertNotIn("REMEM_API_KEY", child_environment)
            self.assertEqual(
                child_environment["REMEM_API_URL"],
                "https://api.remem.io",
            )
            self.assertEqual(
                child_environment["REMEM_MEMORY_PROJECT"],
                "preserved-project",
            )
            self.assertNotIn("PYTHONPATH", child_environment)
            self.assertNotIn("PYTHONINSPECT", child_environment)
            self.assertNotIn(
                "DYLD_INSERT_LIBRARIES",
                child_environment,
            )
            self.assertNotIn("LD_PRELOAD", child_environment)
            self.assertEqual(arguments[1], "-I")
            helper_name = Path(arguments[2]).name
            if helper_name == "remem_codex_wrapper.py":
                self.assertEqual(
                    set(pass_fds),
                    {
                        int(
                            child_environment[
                                "REMEM_API_KEY_FD"
                            ]
                        ),
                        int(
                            child_environment[
                                "REMEM_MEMORY_RUNTIME_ENV_FD"
                            ]
                        ),
                    },
                )
                self.assertEqual(
                    child_environment["UNRELATED_SETTING"],
                    "not-forwarded",
                )
                self.assertEqual(
                    child_environment["SSH_AUTH_SOCK"],
                    "/test/agent.sock",
                )
                self.assertEqual(
                    child_environment["AWS_PROFILE"],
                    "engineering",
                )
                self.assertEqual(
                    child_environment["GIT_CONFIG_GLOBAL"],
                    "/untrusted/gitconfig",
                )
            elif helper_name == "remem_recall.py":
                self.assertEqual(
                    pass_fds,
                    (
                        int(
                            child_environment[
                                "REMEM_API_KEY_FD"
                            ]
                        ),
                    ),
                )
            else:
                self.assertNotIn(
                    "REMEM_API_KEY_FD",
                    child_environment,
                )
                self.assertEqual(pass_fds, ())
                self.assertNotIn(
                    "UNRELATED_SETTING",
                    child_environment,
                )
                self.assertNotIn("SSH_AUTH_SOCK", child_environment)
                self.assertNotIn("AWS_PROFILE", child_environment)
                self.assertNotIn(
                    "GIT_CONFIG_GLOBAL",
                    child_environment,
                )
            self.assertNotIn(canary, json.dumps(arguments))
        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())

    def test_manual_workflows_reject_plaintext_api_key_arguments(self):
        canary = "vlt_plaintext-argument-secret-canary"
        for arguments in (
            ["--api-key", canary],
            [f"--api-key={canary}"],
        ):
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(
                    remem_memory.remem_api,
                    "resolve_api_key",
                ) as resolve:
                    with mock.patch.object(
                        remem_memory.subprocess,
                        "run",
                    ) as run:
                        with contextlib.redirect_stdout(stdout):
                            with contextlib.redirect_stderr(stderr):
                                result = remem_memory.run_command(
                                    "recall",
                                    arguments,
                                )

                self.assertEqual(result, 2)
                resolve.assert_not_called()
                run.assert_not_called()
                self.assertNotIn(canary, stdout.getvalue())
                self.assertNotIn(canary, stderr.getvalue())
                self.assertEqual(
                    stderr.getvalue().strip(),
                    (
                        "error: --api-key is not supported; "
                        "use remem-memory auth"
                    ),
                )

    def test_canonical_cli_is_executable_through_its_installed_basename(self):
        script = _ROOT / "scripts" / "remem_memory.py"
        self.assertTrue(script.stat().st_mode & stat.S_IXUSR)
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / "remem-memory"
            installed.symlink_to(script)

            completed = subprocess.run(
                [str(installed), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage: remem-memory", completed.stdout)

    def test_alias_invocation_forwards_options_without_an_explicit_subcommand(
        self,
    ):
        with mock.patch.object(
            remem_memory,
            "run_command",
            return_value=19,
        ) as run:
            result = remem_memory.main(
                ["--query", "history"],
                program="remem-memory-recall",
            )

        self.assertEqual(result, 19)
        run.assert_called_once_with("recall", ["--query", "history"])

    def test_mode_and_sensitivity_write_only_bounded_secure_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            settings_path.write_text(
                json.dumps(
                    {
                        "mode": "invalid",
                        "sensitivity": "invalid",
                        "secret": "must-not-survive",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"REMEM_MEMORY_DATA_DIR": directory},
                clear=False,
            ):
                self.assertEqual(remem_memory.main(["mode", "off"]), 0)
                self.assertEqual(remem_memory.load_settings()["mode"], "off")
                self.assertEqual(
                    remem_memory.main(["sensitivity", "aggressive"]),
                    0,
                )
                self.assertEqual(
                    remem_memory.load_settings()["sensitivity"],
                    "aggressive",
                )

            self.assertEqual(
                json.loads(settings_path.read_text(encoding="utf-8")),
                {"mode": "off", "sensitivity": "aggressive"},
            )
            self.assertEqual(stat.S_IMODE(settings_path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(settings_path.parent.stat().st_mode),
                0o700,
            )

    def test_status_never_prints_key_or_keychain_password(self):
        canary = "vlt_status-secret-canary"
        stdout = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {"REMEM_API_KEY": canary},
            clear=False,
        ):
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(remem_memory.main(["status"]), 0)

        rendered = stdout.getvalue()
        self.assertIn("credential: configured", rendered)
        self.assertNotIn(canary, rendered)
        self.assertNotIn("sha256", rendered)

    def test_status_finds_user_uv_install_when_desktop_path_is_narrow(self):
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            uv = Path(directory) / ".local" / "bin" / "uv"
            uv.parent.mkdir(parents=True)
            uv.write_text("#!/bin/sh\n", encoding="utf-8")
            uv.chmod(0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": directory,
                    "PATH": "/usr/bin:/bin",
                },
                clear=True,
            ):
                with mock.patch.object(
                    remem_memory.remem_api,
                    "resolve_api_key",
                    return_value=None,
                ):
                    with contextlib.redirect_stdout(stdout):
                        self.assertEqual(
                            remem_memory.main(["status"]),
                            0,
                        )

        self.assertIn("uv: available", stdout.getvalue())

    def test_auth_passes_hidden_input_to_keychain_without_printing_it(self):
        canary = "vlt_auth-secret-canary"
        stdout = io.StringIO()
        with mock.patch.object(
            remem_memory.getpass,
            "getpass",
            return_value=canary,
        ):
            with mock.patch.object(remem_memory.remem_api, "store_api_key") as store:
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(remem_memory.main(["auth"]), 0)

        store.assert_called_once_with(canary)
        self.assertNotIn(canary, stdout.getvalue())

    def test_auth_suppresses_exception_details_and_secret_material(self):
        canary = "vlt_auth-error-secret-canary"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            remem_memory.getpass,
            "getpass",
            return_value=canary,
        ):
            with mock.patch.object(
                remem_memory.remem_api,
                "store_api_key",
                side_effect=RuntimeError(canary),
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        self.assertEqual(remem_memory.main(["auth"]), 2)

        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: unable to store Remem credential",
        )


class RoutingCliTests(unittest.TestCase):
    def _run(self, arguments, *, environment=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        selected = environment or {}
        with mock.patch.dict(os.environ, selected, clear=False):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    result = remem_memory.main(arguments)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_routes_show_has_stable_fully_qualified_default_output(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr = self._run(
                ["routes", "show"],
                environment={"REMEM_MEMORY_DATA_DIR": directory},
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            stdout,
            (
                "mode: auto\n"
                "migration write block: off\n"
                "Global routes\n"
                "  recall: primary/@readable\n"
                "  memory: primary/@default\n"
                "  sessions: primary/@default\n"
                "Codex routes\n"
                "  recall: inherit -> primary/@readable\n"
                "  memory: inherit -> primary/@default\n"
                "  sessions: inherit -> primary/@default\n"
                "Claude routes\n"
                "  recall: inherit -> primary/@readable\n"
                "  memory: inherit -> primary/@default\n"
                "  sessions: inherit -> primary/@default\n"
                "Connections\n"
                "  Primary: configured; credential missing\n"
                "Last API results\n"
                "  none\n"
            ),
        )

    def test_routes_show_json_is_deterministic_and_client_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = [
                "routes",
                "show",
                "--client",
                "codex",
                "--json",
            ]
            first = self._run(
                arguments,
                environment={"REMEM_MEMORY_DATA_DIR": directory},
            )
            second = self._run(
                arguments,
                environment={"REMEM_MEMORY_DATA_DIR": directory},
            )

        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)
        payload = json.loads(first[1])
        self.assertEqual(list(payload["clients"]), ["codex"])
        self.assertEqual(
            payload["global_routes"]["recall"],
            ["primary/@readable"],
        )
        self.assertEqual(payload["clients"]["codex"]["memory"]["source"], "inherit")
        self.assertNotIn("keychain_account", first[1])

    def test_route_summaries_apply_global_mode_without_changing_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            self._run(
                ["routes", "set", "recall", "--from", "history"],
                environment=environment,
            )
            self._run(
                ["routes", "set", "memory", "--to", "personal"],
                environment=environment,
            )
            self._run(
                ["mode", "off"],
                environment=environment,
            )
            shown = self._run(
                ["routes", "show", "--json"],
                environment=environment,
            )
            status = self._run(["status"], environment=environment)
            stored = remem_memory.remem_routing.load_routing(
                Path(directory)
            )

        payload = json.loads(shown[1])
        self.assertEqual(
            payload["global_routes"],
            {"memory": [], "recall": [], "sessions": []},
        )
        for client in ("codex", "claude"):
            for behavior in ("recall", "memory", "sessions"):
                self.assertEqual(
                    payload["clients"][client][behavior]["routes"],
                    [],
                )
        self.assertIn(
            "routes: recall=off memory=off sessions=off",
            status[1],
        )
        self.assertEqual(
            stored.global_routes.routes["recall"][0].namespace,
            "history",
        )

    def test_routes_show_reports_credential_health_and_fixed_migration_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "REMEM_MEMORY_DATA_DIR": directory,
                "REMEM_DEFAULT_NAMESPACE": "must-not-be-routed",
            }
            config = remem_memory.remem_routing.load_or_initialize_routing(
                Path(directory),
                environment,
            )
            remem_memory.remem_routing.record_route_health(
                remem_memory.remem_routing.RouteHealthRecord(
                    "codex",
                    "recall",
                    "primary",
                    "@readable",
                    "permission_error",
                    "read_denied",
                    "2026-07-24T12:34:56Z",
                ),
                Path(directory),
            )
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_connection_api_key",
                return_value=None,
            ):
                result, stdout, stderr = self._run(
                    [
                        "routes",
                        "show",
                        "--client",
                        "codex",
                        "--json",
                    ],
                    environment=environment,
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(
            payload["connections"],
            [
                {
                    "configured": True,
                    "credential": "missing",
                    "name": "Primary",
                }
            ],
        )
        self.assertEqual(
            payload["deprecations"],
            ["REMEM_DEFAULT_NAMESPACE is deprecated"],
        )
        self.assertEqual(
            payload["last_api_results"],
            [
                {
                    "behavior": "recall",
                    "client": "codex",
                    "detail_code": "read_denied",
                    "observed_at": "2026-07-24T12:34:56Z",
                    "route": "primary/@readable",
                    "status": "permission_error",
                }
            ],
        )
        self.assertNotIn("must-not-be-routed", stdout)
        self.assertTrue(config.legacy_namespace_migration_completed)

    def test_route_set_forms_validate_targets_and_apply_client_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            accepted = (
                ["routes", "set", "recall", "--from", "team-a", "team-b"],
                ["routes", "set", "memory", "--to", "personal"],
                ["routes", "set", "sessions", "--to", "off"],
                [
                    "routes",
                    "set",
                    "recall",
                    "--off",
                    "--client",
                    "codex",
                ],
                [
                    "routes",
                    "set",
                    "memory",
                    "--to",
                    "codex-memory",
                    "--client",
                    "codex",
                ],
                [
                    "routes",
                    "set",
                    "sessions",
                    "--to",
                    "off",
                    "--client",
                    "claude",
                ],
            )
            for arguments in accepted:
                with self.subTest(arguments=arguments):
                    result, _stdout, stderr = self._run(
                        arguments,
                        environment=environment,
                    )
                    self.assertEqual(result, 0)
                    self.assertEqual(stderr, "")

            result, stdout, stderr = self._run(
                ["routes", "show", "--json"],
                environment=environment,
            )
            invalid = (
                ["routes", "set", "recall", "--from"],
                ["routes", "set", "recall", "--to", "primary/x"],
                ["routes", "set", "memory", "--from", "primary/x"],
                ["routes", "set", "memory", "--to", "unknown/x"],
                ["routes", "set", "sessions", "--to", "primary/@readable"],
                ["routes", "set", "recall", "--off", "--client", "other"],
                ["routes", "set", "memory", "--to", "x", "--json"],
            )
            invalid_results = [
                self._run(arguments, environment=environment)
                for arguments in invalid
            ]

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(
            payload["global_routes"],
            {
                "memory": ["primary/personal"],
                "recall": ["primary/team-a", "primary/team-b"],
                "sessions": [],
            },
        )
        self.assertEqual(
            payload["clients"]["codex"]["recall"],
            {"routes": [], "source": "override"},
        )
        self.assertEqual(
            payload["clients"]["codex"]["memory"],
            {
                "routes": ["primary/codex-memory"],
                "source": "override",
            },
        )
        self.assertEqual(
            payload["clients"]["claude"]["memory"],
            {
                "routes": ["primary/personal"],
                "source": "inherit",
            },
        )
        for invalid_result, _stdout, invalid_stderr in invalid_results:
            self.assertEqual(invalid_result, 2)
            self.assertEqual(
                invalid_stderr,
                "error: invalid routes command\n",
            )

    def test_client_recall_from_is_an_explicit_supported_override(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            result = self._run(
                [
                    "routes",
                    "set",
                    "recall",
                    "--from",
                    "client-a",
                    "client-b",
                    "--client",
                    "claude",
                ],
                environment=environment,
            )
            shown = self._run(
                [
                    "routes",
                    "show",
                    "--client",
                    "claude",
                    "--json",
                ],
                environment=environment,
            )

        self.assertEqual(result[0], 0)
        self.assertEqual(
            json.loads(shown[1])["clients"]["claude"]["recall"],
            {
                "routes": [
                    "primary/client-a",
                    "primary/client-b",
                ],
                "source": "override",
            },
        )

    def test_global_write_choices_release_migration_block_only_when_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "REMEM_MEMORY_DATA_DIR": directory,
                "REMEM_MEMORY_PERSONAL_NAMESPACE": "personal",
            }
            routing = remem_memory.remem_routing
            routing.initialize_routing(
                Path(directory),
                environment,
                routing.LegacyDiscovery(
                    2,
                    {"memory": ("personal",)},
                ),
            )

            client_result = self._run(
                [
                    "routes",
                    "set",
                    "memory",
                    "--to",
                    "client-only",
                    "--client",
                    "codex",
                ],
                environment=environment,
            )
            after_client = routing.load_routing(Path(directory))
            memory_result = self._run(
                ["routes", "set", "memory", "--to", "chosen"],
                environment=environment,
            )
            after_memory = routing.load_routing(Path(directory))
            sessions_result = self._run(
                ["routes", "set", "sessions", "--to", "off"],
                environment=environment,
            )
            after_sessions = routing.load_routing(Path(directory))

        self.assertEqual(client_result[0], 0)
        self.assertTrue(after_client.migration_write_blocked)
        self.assertEqual(memory_result[0], 0)
        self.assertTrue(after_memory.migration_write_blocked)
        self.assertEqual(sessions_result[0], 0)
        self.assertFalse(after_sessions.migration_write_blocked)

    def test_connections_add_recovers_unconfigured_record_then_use_is_client_only(self):
        canary = "vlt-named-connection-secret"
        keychain = {}

        def store(account, value):
            keychain[account] = value

        def resolve(account):
            return keychain.get(account)

        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
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
                    interrupted = self._run(
                        ["connections", "add", "Work"],
                        environment=environment,
                    )
                pending = remem_memory.remem_routing.load_routing(
                    Path(directory)
                )
                with mock.patch.object(
                    remem_memory.remem_api,
                    "store_keychain_api_key",
                    side_effect=store,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_keychain_api_key",
                        side_effect=resolve,
                    ):
                        resumed = self._run(
                            ["connections", "add", "Work"],
                            environment=environment,
                        )
            used = self._run(
                ["connections", "use", "Work", "--client", "codex"],
                environment=environment,
            )
            config = remem_memory.remem_routing.load_routing(Path(directory))
            listed = self._run(
                ["connections", "list", "--json"],
                environment=environment,
            )

        self.assertEqual(interrupted[0], 1)
        self.assertEqual(len(pending.connections), 2)
        self.assertFalse(pending.connections[1].configured)
        self.assertEqual(resumed, (0, "connection: Work configured\n", ""))
        self.assertEqual(used, (0, "codex MCP connection: Work\n", ""))
        self.assertEqual(
            config.mcp_connections,
            {"codex": config.connections[1].id},
        )
        self.assertEqual(
            json.loads(listed[1]),
            {
                "connections": [
                    {
                        "configured": True,
                        "mcp_clients": ["claude"],
                        "name": "Primary",
                    },
                    {
                        "configured": True,
                        "mcp_clients": ["codex"],
                        "name": "Work",
                    },
                ]
            },
        )
        for rendered in (
            interrupted[1],
            interrupted[2],
            resumed[1],
            resumed[2],
            used[1],
            used[2],
            listed[1],
            listed[2],
        ):
            self.assertNotIn(canary, rendered)
            self.assertNotIn(
                pending.connections[1].keychain_account,
                rendered,
            )

    def test_routing_rejects_pending_connection_and_default_reset_preserves_it(self):
        canary = "vlt-pending-secret"
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
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
                    self._run(
                        ["connections", "add", "Pending"],
                        environment=environment,
                    )
            rejected = self._run(
                ["routes", "set", "memory", "--to", "Pending/private"],
                environment=environment,
            )
            reset = self._run(
                ["routes", "use-default"],
                environment=environment,
            )
            config = remem_memory.remem_routing.load_routing(Path(directory))

        self.assertEqual(
            rejected,
            (2, "", "error: invalid routes command\n"),
        )
        self.assertEqual(reset, (0, "routes: default\n", ""))
        self.assertEqual(len(config.connections), 2)
        self.assertTrue(config.legacy_namespace_migration_completed)

    def test_connection_add_rejects_an_existing_pending_internal_id_as_label(self):
        token = "0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            config = remem_memory.remem_routing.load_or_initialize_routing(
                Path(directory),
                environment,
            )
            remem_memory.remem_routing.update_routing(
                lambda current: replace(
                    current,
                    connections=(
                        *current.connections,
                        remem_memory.remem_routing.Connection(
                            f"conn_{token}",
                            "Pending",
                            f"connection:{token}",
                            False,
                        ),
                    ),
                ),
                Path(directory),
            )
            with mock.patch.object(
                remem_memory.getpass,
                "getpass",
                return_value="must-not-be-written",
            ) as prompt:
                result = self._run(
                    ["connections", "add", f"conn_{token}"],
                    environment=environment,
                )
            stored = remem_memory.remem_routing.load_routing(
                Path(directory)
            )

        self.assertEqual(
            result,
            (2, "", "error: invalid connections command\n"),
        )
        prompt.assert_not_called()
        self.assertFalse(stored.connections[1].configured)
        self.assertEqual("Pending", stored.connections[1].label)

    def test_default_reset_commits_only_the_final_state_once(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            config = remem_memory.remem_routing.load_or_initialize_routing(
                Path(directory),
                environment,
            )
            configured = replace(
                config,
                revision=10,
                global_routes=remem_memory.remem_routing.RouteLayer(
                    {
                        "memory": (
                            remem_memory.remem_routing.RouteTarget(
                                "primary",
                                "personal",
                            ),
                        ),
                        "sessions": (),
                    }
                ),
                client_routes={
                    "codex": remem_memory.remem_routing.RouteLayer(
                        {"recall": ()}
                    )
                },
                migration_write_blocked=True,
            )
            remem_memory.remem_routing.store_routing(
                configured,
                Path(directory),
            )

            result = self._run(
                ["routes", "use-default"],
                environment=environment,
            )
            reset = remem_memory.remem_routing.load_routing(
                Path(directory)
            )

        self.assertEqual(result, (0, "routes: default\n", ""))
        self.assertEqual(11, reset.revision)
        self.assertEqual({}, dict(reset.global_routes.routes))
        self.assertEqual({}, dict(reset.client_routes))
        self.assertFalse(reset.migration_write_blocked)

    def test_status_extends_legacy_controls_with_compact_secret_free_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr = self._run(
                ["status"],
                environment={"REMEM_MEMORY_DATA_DIR": directory},
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn("mode: auto\n", stdout)
        self.assertIn("sensitivity: balanced\n", stdout)
        self.assertIn("routing: valid\n", stdout)
        self.assertIn("routes: recall=primary/@readable", stdout)
        self.assertIn(
            "codex routes: recall=primary/@readable "
            "memory=primary/@default sessions=primary/@default\n",
            stdout,
        )
        self.assertIn(
            "claude routes: recall=primary/@readable "
            "memory=primary/@default sessions=primary/@default\n",
            stdout,
        )
        self.assertIn("connections: 1 configured, 0 missing\n", stdout)
        self.assertNotIn("keychain_account", stdout)

    def test_status_includes_connection_health_and_latest_fixed_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            remem_memory.remem_routing.load_or_initialize_routing(
                Path(directory),
                environment,
            )
            remem_memory.remem_routing.record_route_health(
                remem_memory.remem_routing.RouteHealthRecord(
                    "codex",
                    "recall",
                    "primary",
                    "@readable",
                    "permission_error",
                    "read_denied",
                    "2026-07-24T12:34:56Z",
                ),
                Path(directory),
            )
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_connection_api_key",
                return_value=None,
            ):
                result, stdout, stderr = self._run(
                    ["status"],
                    environment=environment,
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "connection Primary: configured; credential missing\n",
            stdout,
        )
        self.assertIn(
            "last API result: primary/@readable recall (codex): "
            "permission_error [read_denied]\n",
            stdout,
        )
        self.assertNotIn("connection:", stdout)
        self.assertNotIn("keychain_account", stdout)

    def test_status_reports_permanent_request_health_as_request_error(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            data_dir = Path(directory)
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                environment,
            )
            remem_memory.remem_routing.record_route_health(
                remem_memory.remem_routing.RouteHealthRecord(
                    "codex",
                    "recall",
                    "primary",
                    "@readable",
                    "request_error",
                    "request_invalid",
                    "2026-07-24T12:34:56Z",
                ),
                data_dir,
            )
            with mock.patch.object(
                remem_memory.remem_api,
                "resolve_connection_api_key",
                return_value=None,
            ):
                result, stdout, stderr = self._run(
                    ["status"],
                    environment=environment,
                )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "last API result: primary/@readable recall (codex): "
            "request_error [request_invalid]\n",
            stdout,
        )

    def test_status_orders_fractional_rfc3339_timestamps_chronologically(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            data_dir = Path(directory)
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                environment,
            )
            for client, status, detail_code, observed_at in (
                (
                    "codex",
                    "permission_error",
                    "earlier_denied",
                    "2026-07-24T12:34:56Z",
                ),
                (
                    "claude",
                    "ok",
                    "later_allowed",
                    "2026-07-24T12:34:56.9Z",
                ),
            ):
                remem_memory.remem_routing.record_route_health(
                    remem_memory.remem_routing.RouteHealthRecord(
                        client,
                        "recall",
                        "primary",
                        "@readable",
                        status,
                        detail_code,
                        observed_at,
                    ),
                    data_dir,
                )

            result, stdout, stderr = self._run(
                ["status"],
                environment=environment,
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "last API result: primary/@readable recall (claude): "
            "ok [later_allowed]\n",
            stdout,
        )
        self.assertNotIn("earlier_denied", stdout)

    def test_status_preserves_submicrosecond_precision_per_route(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            data_dir = Path(directory)
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                environment,
            )
            for status, detail_code, observed_at in (
                (
                    "ok",
                    "newer_same_route",
                    "2026-07-24T12:34:56.1234568Z",
                ),
                (
                    "permission_error",
                    "older_same_route",
                    "2026-07-24T12:34:56.1234567Z",
                ),
            ):
                remem_memory.remem_routing.record_route_health(
                    remem_memory.remem_routing.RouteHealthRecord(
                        "codex",
                        "recall",
                        "primary",
                        "@readable",
                        status,
                        detail_code,
                        observed_at,
                    ),
                    data_dir,
                )

            result, stdout, stderr = self._run(
                ["status"],
                environment=environment,
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "last API result: primary/@readable recall (codex): "
            "ok [newer_same_route]\n",
            stdout,
        )
        self.assertNotIn("older_same_route", stdout)

    def test_status_preserves_submicrosecond_precision_in_final_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMEM_MEMORY_DATA_DIR": directory}
            data_dir = Path(directory)
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                environment,
            )
            for client, status, detail_code, observed_at in (
                (
                    "claude",
                    "permission_error",
                    "older_other_route",
                    "2026-07-24T12:34:56.1234567Z",
                ),
                (
                    "codex",
                    "ok",
                    "newer_other_route",
                    "2026-07-24T12:34:56.1234568Z",
                ),
            ):
                remem_memory.remem_routing.record_route_health(
                    remem_memory.remem_routing.RouteHealthRecord(
                        client,
                        "recall",
                        "primary",
                        "@readable",
                        status,
                        detail_code,
                        observed_at,
                    ),
                    data_dir,
                )

            result, stdout, stderr = self._run(
                ["status"],
                environment=environment,
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "last API result: primary/@readable recall (codex): "
            "ok [newer_other_route]\n",
            stdout,
        )
        self.assertNotIn("older_other_route", stdout)

    def test_doctor_missing_storage_and_unsafe_modes_are_strictly_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            missing = parent / "missing"
            parent_before = parent.stat()
            with mock.patch("shutil.which", return_value=None):
                missing_result = self._run(
                    ["doctor", "--json"],
                    environment={"REMEM_MEMORY_DATA_DIR": str(missing)},
                )
            parent_after = parent.stat()

            self.assertEqual(missing_result[0], 1)
            self.assertFalse(missing.exists())
            self.assertEqual(parent_before.st_ino, parent_after.st_ino)
            self.assertEqual(parent_before.st_mtime_ns, parent_after.st_mtime_ns)

            data_dir = parent / "existing"
            remem_memory.remem_routing.store_routing(
                remem_memory.remem_routing.load_or_initialize_routing(
                    parent / "seed",
                    {},
                ),
                data_dir,
            )
            route_path = data_dir / "routes.json"
            data_dir.chmod(0o750)
            route_path.chmod(0o640)
            directory_before = data_dir.stat()
            file_before = route_path.stat()

            with mock.patch("shutil.which", return_value=None):
                unsafe_result = self._run(
                    ["doctor", "--json"],
                    environment={"REMEM_MEMORY_DATA_DIR": str(data_dir)},
                )
            directory_after = data_dir.stat()
            file_after = route_path.stat()

        self.assertEqual(unsafe_result[0], 1)
        self.assertEqual(
            (
                directory_before.st_ino,
                directory_before.st_mtime_ns,
                stat.S_IMODE(directory_before.st_mode),
                file_before.st_ino,
                file_before.st_mtime_ns,
                stat.S_IMODE(file_before.st_mode),
            ),
            (
                directory_after.st_ino,
                directory_after.st_mtime_ns,
                stat.S_IMODE(directory_after.st_mode),
                file_after.st_ino,
                file_after.st_mtime_ns,
                stat.S_IMODE(file_after.st_mode),
            ),
        )

    def test_doctor_rejects_plugin_home_and_launcher_false_positives(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".codex").mkdir()
            (home / ".claude").mkdir()
            data_dir = home / "state"
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                {},
            )
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout='{"plugins":[]}',
                stderr="",
            )
            with mock.patch(
                "shutil.which",
                side_effect=lambda command, path=None: f"/test/{command}",
            ):
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    return_value=completed,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="available",
                    ):
                        with mock.patch.object(
                            remem_memory,
                            "_uv_available",
                            return_value=True,
                        ):
                            result = self._run(
                                ["doctor", "--json"],
                                environment={
                                    "HOME": str(home),
                                    "REMEM_MEMORY_DATA_DIR": str(data_dir),
                                },
                            )

        payload = json.loads(result[1])
        checks = {item["name"]: item for item in payload["checks"]}
        self.assertEqual(
            checks["client_registrations"],
            {
                "detail_code": "plugin_missing",
                "name": "client_registrations",
                "status": "failed",
            },
        )
        self.assertEqual(
            checks["mcp_startup"],
            {
                "detail_code": "no_read_only_probe",
                "name": "mcp_startup",
                "status": "warning",
            },
        )

    def test_doctor_verifies_exact_installed_plugin_records(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "state"
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                {},
            )
            payloads = {
                "/test/codex": {
                    "plugins": [
                        {
                            "name": "remem-memory",
                            "enabled": True,
                        }
                    ]
                },
                "/test/claude": {
                    "installed": [
                        {
                            "name": "remem-memory@remem-memory",
                            "status": "enabled",
                        }
                    ]
                },
            }

            def run(arguments, **_kwargs):
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    stdout=json.dumps(payloads[arguments[0]]),
                    stderr="",
                )

            with mock.patch(
                "shutil.which",
                side_effect=lambda command, path=None: f"/test/{command}",
            ):
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    side_effect=run,
                ) as plugin_list:
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="available",
                    ):
                        result = self._run(
                            ["doctor", "--json"],
                            environment={
                                "REMEM_MEMORY_DATA_DIR": str(data_dir)
                            },
                        )

        checks = {
            item["name"]: item
            for item in json.loads(result[1])["checks"]
        }
        self.assertEqual(
            checks["client_registrations"]["status"],
            "ok",
        )
        self.assertEqual(
            checks["client_registrations"]["detail_code"],
            "verified",
        )
        self.assertEqual(
            checks["hook_presence"],
            {
                "detail_code": "installed_plugin_enabled",
                "name": "hook_presence",
                "status": "ok",
            },
        )
        self.assertEqual(plugin_list.call_count, 2)

    def test_doctor_hook_presence_does_not_trust_checkout_only_manifest(self):
        cases = (
            (
                {"plugins": []},
                "plugin_missing",
            ),
            (
                {
                    "plugins": [
                        {
                            "name": "remem-memory",
                            "enabled": False,
                        }
                    ]
                },
                "plugin_disabled",
            ),
        )
        for plugin_payload, registration_detail in cases:
            with self.subTest(registration_detail=registration_detail):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory) / "state"
                    remem_memory.remem_routing.load_or_initialize_routing(
                        data_dir,
                        {},
                    )
                    completed = subprocess.CompletedProcess(
                        [],
                        0,
                        stdout=json.dumps(plugin_payload),
                        stderr="",
                    )
                    with mock.patch(
                        "shutil.which",
                        side_effect=lambda command, path=None: (
                            f"/test/{command}"
                        ),
                    ):
                        with mock.patch.object(
                            remem_memory.subprocess,
                            "run",
                            return_value=completed,
                        ):
                            with mock.patch.object(
                                remem_memory.remem_api,
                                "resolve_connection_api_key",
                                return_value="available",
                            ):
                                result = self._run(
                                    ["doctor", "--json"],
                                    environment={
                                        "REMEM_MEMORY_DATA_DIR": str(
                                            data_dir
                                        )
                                    },
                                )

                checks = {
                    item["name"]: item
                    for item in json.loads(result[1])["checks"]
                }
                self.assertEqual(
                    checks["client_registrations"]["detail_code"],
                    registration_detail,
                )
                self.assertEqual(
                    checks["hook_presence"],
                    {
                        "detail_code": "trust_unverified",
                        "name": "hook_presence",
                        "status": "warning",
                    },
                )

    def test_doctor_warning_has_tri_state_summary_and_success_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            remem_memory.remem_routing.load_or_initialize_routing(
                data_dir,
                {},
            )
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps(
                    {
                        "plugins": [
                            {
                                "name": "remem-memory",
                                "enabled": True,
                            }
                        ]
                    }
                ),
                stderr="",
            )
            with mock.patch(
                "shutil.which",
                side_effect=lambda command, path=None: f"/test/{command}",
            ):
                with mock.patch.object(
                    remem_memory.subprocess,
                    "run",
                    return_value=completed,
                ):
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="available",
                    ):
                        with mock.patch.object(
                            remem_memory,
                            "_uv_available",
                            return_value=True,
                        ):
                            json_result = self._run(
                                ["doctor", "--json"],
                                environment={
                                    "REMEM_MEMORY_DATA_DIR": str(data_dir)
                                },
                            )
                            human_result = self._run(
                                ["doctor"],
                                environment={
                                    "REMEM_MEMORY_DATA_DIR": str(data_dir)
                                },
                            )

        payload = json.loads(json_result[1])
        self.assertEqual(json_result[0], 0)
        self.assertEqual(payload["status"], "warning")
        self.assertIs(payload["healthy"], False)
        self.assertEqual(human_result[0], 0)
        self.assertTrue(human_result[1].startswith("doctor: warning\n"))

    def test_doctor_failed_checks_take_precedence_over_warning_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with mock.patch("shutil.which", return_value=None):
                with mock.patch.object(
                    remem_memory,
                    "_uv_available",
                    return_value=True,
                ):
                    json_result = self._run(
                        ["doctor", "--json"],
                        environment={
                            "REMEM_MEMORY_DATA_DIR": str(missing)
                        },
                    )
                    human_result = self._run(
                        ["doctor"],
                        environment={
                            "REMEM_MEMORY_DATA_DIR": str(missing)
                        },
                    )

        payload = json.loads(json_result[1])
        self.assertEqual(json_result[0], 1)
        self.assertEqual(payload["status"], "failed")
        self.assertIs(payload["healthy"], False)
        self.assertEqual(human_result[0], 1)
        self.assertTrue(human_result[1].startswith("doctor: failed\n"))

    def test_doctor_readability_ignores_successful_and_failed_write_health(self):
        cases = (
            ("memory", "ok", "ok"),
            ("sessions", "permission_error", "write_denied"),
        )
        for behavior, status, detail_code in cases:
            with self.subTest(behavior=behavior, status=status):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory)
                    remem_memory.remem_routing.load_or_initialize_routing(
                        data_dir,
                        {},
                    )
                    remem_memory.remem_routing.record_route_health(
                        remem_memory.remem_routing.RouteHealthRecord(
                            "codex",
                            behavior,
                            "primary",
                            "@default",
                            status,
                            detail_code,
                            "2026-07-24T12:34:56Z",
                        ),
                        data_dir,
                    )
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="available",
                    ):
                        with mock.patch("shutil.which", return_value=None):
                            result = self._run(
                                ["doctor", "--json"],
                                environment={
                                    "REMEM_MEMORY_DATA_DIR": str(data_dir)
                                },
                            )

                checks = {
                    item["name"]: item
                    for item in json.loads(result[1])["checks"]
                }
                self.assertEqual(
                    checks["namespace_readability"],
                    {
                        "detail_code": "no_prior_read",
                        "name": "namespace_readability",
                        "status": "info",
                    },
                )

    def test_doctor_distinguishes_recall_failure_categories(self):
        cases = (
            "auth_error",
            "permission_error",
            "namespace_error",
            "request_error",
            "transient_error",
        )
        for status in cases:
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory)
                    remem_memory.remem_routing.load_or_initialize_routing(
                        data_dir,
                        {},
                    )
                    remem_memory.remem_routing.record_route_health(
                        remem_memory.remem_routing.RouteHealthRecord(
                            "codex",
                            "recall",
                            "primary",
                            "@readable",
                            status,
                            "fixed_detail",
                            "2026-07-24T12:34:56Z",
                        ),
                        data_dir,
                    )
                    with mock.patch.object(
                        remem_memory.remem_api,
                        "resolve_connection_api_key",
                        return_value="available",
                    ):
                        with mock.patch("shutil.which", return_value=None):
                            result = self._run(
                                ["doctor", "--json"],
                                environment={
                                    "REMEM_MEMORY_DATA_DIR": str(data_dir)
                                },
                            )

                checks = {
                    item["name"]: item
                    for item in json.loads(result[1])["checks"]
                }
                self.assertEqual(
                    checks["namespace_readability"],
                    {
                        "detail_code": status,
                        "name": "namespace_readability",
                        "status": "failed",
                    },
                )

    def test_doctor_is_deterministic_read_only_and_emits_no_query_content(self):
        canary = "vlt-doctor-recalled-content"
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "REMEM_MEMORY_DATA_DIR": directory,
                "REMEM_DEFAULT_NAMESPACE": "must-not-be-routed",
            }
            remem_memory.remem_routing.load_or_initialize_routing(
                Path(directory),
                environment,
            )
            before = {
                path.name: path.read_bytes()
                for path in Path(directory).iterdir()
                if path.is_file()
            }
            with mock.patch.object(
                remem_memory.remem_api.RememAPI,
                "query",
                return_value={"results": [{"content": canary}]},
            ) as query:
                with mock.patch.object(
                    remem_memory.remem_api.RememAPI,
                    "ingest",
                ) as ingest:
                    with mock.patch("shutil.which", return_value=None):
                        first = self._run(
                            ["doctor", "--json"],
                            environment=environment,
                        )
                        second = self._run(
                            ["doctor", "--json"],
                            environment=environment,
                        )
            after = {
                path.name: path.read_bytes()
                for path in Path(directory).iterdir()
                if path.is_file()
            }

        self.assertEqual(first, second)
        self.assertIn(first[0], (0, 1))
        self.assertEqual(before, after)
        query.assert_not_called()
        ingest.assert_not_called()
        self.assertNotIn(canary, first[1])
        payload = json.loads(first[1])
        self.assertEqual(payload["read_only"], True)
        self.assertEqual(
            payload["migration_diagnostics"],
            ["REMEM_DEFAULT_NAMESPACE is deprecated"],
        )
        self.assertNotIn("must-not-be-routed", first[1])
        self.assertEqual(
            [item["name"] for item in payload["checks"]],
            sorted(item["name"] for item in payload["checks"]),
        )

    def test_new_command_families_reject_unlisted_argument_shapes(self):
        invalid = (
            ["routes"],
            ["routes", "show", "--client"],
            ["routes", "show", "--client", "codex", "--client", "claude"],
            ["routes", "use-default", "--json"],
            ["connections"],
            ["connections", "list", "--client", "codex"],
            ["connections", "add", "Name", "credential"],
            ["connections", "add", "bad/name"],
            ["connections", "add", "--api-key"],
            ["connections", "use", "primary"],
            ["doctor", "--client", "codex"],
        )
        with tempfile.TemporaryDirectory() as directory:
            results = [
                self._run(
                    arguments,
                    environment={"REMEM_MEMORY_DATA_DIR": directory},
                )
                for arguments in invalid
            ]

        for result, _stdout, stderr in results:
            self.assertEqual(result, 2)
            self.assertTrue(stderr.startswith("error:"))


class MCPLauncherTests(unittest.TestCase):
    def setUp(self):
        self._real_cache_environment = launcher._cache_environment
        self._real_run_probe = launcher._run_probe
        self._cache = tempfile.TemporaryDirectory()
        self.addCleanup(self._cache.cleanup)
        self._cache_environment = str(
            Path(self._cache.name) / "environment"
        )
        entrypoint = (
            Path(self._cache_environment)
            / "bin"
            / "python"
        )
        entrypoint.parent.mkdir(parents=True)
        entrypoint.write_text("#!/bin/sh\n", encoding="utf-8")
        entrypoint.chmod(0o700)
        patcher = mock.patch.object(
            launcher,
            "_cache_environment",
            return_value=self._cache_environment,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        probe_patcher = mock.patch.object(
            launcher,
            "_run_probe",
            return_value=0,
        )
        self._probe = probe_patcher.start()
        self.addCleanup(probe_patcher.stop)
        self._routing = tempfile.TemporaryDirectory()
        self.addCleanup(self._routing.cleanup)
        self._routing_config = remem_routing.load_or_initialize_routing(
            Path(self._routing.name),
            {},
        )
        routing_patcher = mock.patch.object(
            remem_routing,
            "load_routing",
            return_value=self._routing_config,
        )
        routing_patcher.start()
        self.addCleanup(routing_patcher.stop)

    def _mcp_server(self):
        config = json.loads(
            (_ROOT / "plugins" / "remem-memory" / ".mcp.json").read_text(
                encoding="utf-8"
            )
        )
        return config["mcpServers"]["remem"]

    def _run_mcp_bootstrap(self, plugin_root, cwd):
        server = self._mcp_server()
        bootstrap = server["args"][2]
        observed = {}

        def capture_run_path(*args, **kwargs):
            observed["argv"] = list(sys.argv)

        run_path = mock.Mock(side_effect=capture_run_path)
        run_path.observed = observed
        with mock.patch.object(
            sys,
            "argv",
            ["-c", plugin_root],
        ):
            with mock.patch.object(sys, "path", list(sys.path)) as path:
                with mock.patch.object(
                    os,
                    "getcwd",
                    return_value=cwd,
                ) as getcwd:
                    with mock.patch("runpy.run_path", run_path):
                        exec(
                            compile(
                                bootstrap,
                                "<remem-mcp-bootstrap>",
                                "exec",
                            ),
                            {},
                        )
        return run_path, getcwd, path

    def test_launcher_prepares_locked_runtime_then_execs_direct_fd_child(self):
        class ExecIntercept(Exception):
            pass

        original = {
            "PATH": "/test/bin",
            "HOME": "/test/home",
            "TMPDIR": "/test/tmp",
            "LANG": "en_CA.UTF-8",
            "SSL_CERT_FILE": "/test/cert.pem",
            "REMEM_API_URL": "https://api.remem.io",
            "REMEM_DEFAULT_NAMESPACE": "engineering",
            "UNRELATED_SECRET": "vlt_unrelated-secret-canary",
            "AWS_SECRET_ACCESS_KEY": "vlt_aws-secret-canary",
            "PYTHONPATH": "/untrusted/python",
            "UV_INDEX_URL": "https://vlt_uv-secret-canary@example.test",
            "GIT_CONFIG_GLOBAL": "/untrusted/gitconfig",
        }
        child = {}

        def execvpe(executable, arguments, environment):
            child["executable"] = executable
            child["arguments"] = list(arguments)
            child["environment"] = dict(environment)
            descriptor = int(environment["REMEM_API_KEY_FD"])
            child["credential"] = os.read(descriptor, 8192).decode(
                "utf-8"
            )
            raise ExecIntercept()

        with self.assertRaises(ExecIntercept):
            launcher.main(
                ["--client", "codex"],
                environment=original,
                resolver=lambda **kwargs: "vlt_child-only-canary",
                which=lambda command: "/test/bin/uv",
                execvpe=execvpe,
            )

        self.assertNotIn("REMEM_API_KEY", original)
        expected_entrypoint = str(
            Path(self._cache_environment) / "bin" / "python"
        )
        self.assertEqual(child["executable"], expected_entrypoint)
        self.assertEqual(
            child["arguments"][0:3],
            [expected_entrypoint, "-I", "-c"],
        )
        self.assertIn("remem_mcp.server", child["arguments"][3])
        self.assertEqual(
            child["arguments"][4],
            str(
                (
                    _ROOT
                    / "plugins"
                    / "remem-memory"
                    / "mcp"
                ).resolve()
            ),
        )
        self.assertEqual(child["credential"], "vlt_child-only-canary")
        self.assertNotIn("REMEM_API_KEY", child["environment"])
        self.assertTrue(child["environment"]["REMEM_API_KEY_FD"].isdigit())
        self.assertEqual(
            child["environment"],
            {
                "PATH": "/test/bin",
                "HOME": "/test/home",
                "TMPDIR": "/test/tmp",
                "LANG": "en_CA.UTF-8",
                "REMEM_API_URL": "https://api.remem.io",
                "PYTHONDONTWRITEBYTECODE": "1",
                "REMEM_API_KEY_FD": mock.ANY,
            },
        )
        self.assertNotIn(
            "vlt_child-only-canary",
            json.dumps(child["environment"]),
        )
        self._probe.assert_called_once()
        self.assertNotIn("UNRELATED_SECRET", child["environment"])
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", child["environment"])
        self.assertNotIn("PYTHONPATH", child["environment"])
        self.assertNotIn("UV_INDEX_URL", child["environment"])
        self.assertNotIn("GIT_CONFIG_GLOBAL", child["environment"])
        self.assertNotIn("SSL_CERT_FILE", child["environment"])

    def test_launcher_reports_missing_uv_without_claiming_mcp_health(self):
        stderr = io.StringIO()
        resolver = mock.Mock(return_value="configured")
        with mock.patch.object(
            launcher,
            "_uv_fallback_paths",
            return_value=("/definitely/missing/remem-memory-test-uv",),
        ):
            with contextlib.redirect_stderr(stderr):
                result = launcher.main(
                    ["--client", "codex"],
                    environment={},
                    resolver=resolver,
                    which=lambda command: None,
                    execvpe=mock.Mock(),
                )

        self.assertEqual(result, 2)
        resolver.assert_not_called()
        self.assertIn("uv is required", stderr.getvalue())
        self.assertNotIn("healthy", stderr.getvalue().lower())

    def test_launcher_finds_user_uv_install_when_desktop_path_is_narrow(self):
        with tempfile.TemporaryDirectory() as directory:
            uv = Path(directory) / ".local" / "bin" / "uv"
            uv.parent.mkdir(parents=True)
            uv.write_text("#!/bin/sh\n", encoding="utf-8")
            uv.chmod(0o700)

            resolved = launcher._find_uv(
                {
                    "HOME": directory,
                    "PATH": "/usr/bin:/bin",
                },
                lambda command: None,
            )

        self.assertEqual(resolved, str(uv.resolve()))

    def test_uv_fallbacks_cover_homebrew_and_user_installers(self):
        with tempfile.TemporaryDirectory() as directory:
            candidates = launcher._uv_fallback_paths(
                {"HOME": directory},
            )

        self.assertIn("/opt/homebrew/bin/uv", candidates)
        self.assertIn("/usr/local/bin/uv", candidates)
        self.assertIn(
            str(Path(directory) / ".local" / "bin" / "uv"),
            candidates,
        )
        self.assertIn(
            str(Path(directory) / ".cargo" / "bin" / "uv"),
            candidates,
        )

    def test_uv_fallbacks_never_search_relative_home_from_plugin_cwd(self):
        candidates = launcher._uv_fallback_paths(
            {"HOME": "attacker-controlled-relative-home"},
        )

        self.assertTrue(
            all(Path(candidate).is_absolute() for candidate in candidates)
        )
        self.assertNotIn(
            "attacker-controlled-relative-home/.local/bin/uv",
            candidates,
        )

    def test_launcher_canonicalizes_executable_uv_fallback_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            target = Path(directory) / "uv-target"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(0o700)
            candidate = home / ".local" / "bin" / "uv"
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(target)

            resolved = launcher._find_uv(
                {
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                },
                lambda command: None,
            )

        self.assertEqual(resolved, str(target.resolve()))

    def test_launcher_canonicalizes_uv_found_on_inherited_path(self):
        with tempfile.TemporaryDirectory() as directory:
            uv = Path(directory) / "bin" / "uv"
            uv.parent.mkdir(parents=True)
            uv.write_text("#!/bin/sh\n", encoding="utf-8")
            uv.chmod(0o700)
            with mock.patch.object(
                launcher.shutil,
                "which",
                return_value=str(uv),
            ):
                resolved = launcher._find_uv(
                    {"PATH": str(uv.parent)},
                    None,
                )

        self.assertEqual(resolved, str(uv.resolve()))

    def test_launcher_skips_symlink_loop_before_valid_uv_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            loop = home / ".local" / "bin" / "uv"
            loop.parent.mkdir(parents=True)
            loop.symlink_to(loop)
            valid = home / ".cargo" / "bin" / "uv"
            valid.parent.mkdir(parents=True)
            valid.write_text("#!/bin/sh\n", encoding="utf-8")
            valid.chmod(0o700)

            real_resolve = Path.resolve

            def resolve(path, *, strict=False):
                if path == loop:
                    raise RuntimeError("simulated Python 3.9 symlink loop")
                return real_resolve(path, strict=strict)

            with mock.patch.object(Path, "resolve", resolve):
                resolved = launcher._find_uv(
                    {
                        "HOME": str(home),
                        "PATH": "/usr/bin:/bin",
                    },
                    lambda command: None,
                )

        self.assertEqual(resolved, str(valid.resolve()))

    def test_launcher_rejects_relative_uv_found_on_inherited_path(self):
        with tempfile.TemporaryDirectory() as directory:
            malicious = Path(directory) / "uv"
            malicious.write_text("#!/bin/sh\n", encoding="utf-8")
            malicious.chmod(0o700)
            safe = Path(directory) / "safe-uv"
            safe.write_text("#!/bin/sh\n", encoding="utf-8")
            safe.chmod(0o700)
            relative = os.path.relpath(malicious, Path.cwd())

            with mock.patch.object(
                launcher.shutil,
                "which",
                return_value=relative,
            ):
                with mock.patch.object(
                    launcher,
                    "_uv_fallback_paths",
                    return_value=(str(safe),),
                ):
                    resolved = launcher._find_uv(
                        {"PATH": ".:/usr/bin:/bin"},
                        None,
                    )

        self.assertEqual(resolved, str(safe.resolve()))

    def test_launcher_supplies_api_origin_without_namespace_default(self):
        class ExecIntercept(Exception):
            pass

        child = {}

        def execvpe(executable, arguments, environment):
            del executable, arguments
            child.update(environment)
            raise ExecIntercept()

        with self.assertRaises(ExecIntercept):
            launcher.main(
                ["--client", "codex"],
                environment={"PATH": "/test/bin"},
                resolver=lambda **kwargs: "configured",
                which=lambda command: "/test/bin/uv",
                execvpe=execvpe,
            )

        self.assertEqual(
            child["REMEM_API_URL"],
            "https://api.remem.io",
        )
        self.assertNotIn("REMEM_DEFAULT_NAMESPACE", child)

    def test_launcher_missing_key_error_is_fixed_and_non_secret(self):
        canary = "vlt_launcher-secret-canary"
        stderr = io.StringIO()

        def failing_resolver(**kwargs):
            raise RuntimeError(canary)

        with contextlib.redirect_stderr(stderr):
            result = launcher.main(
                ["--client", "codex"],
                environment={},
                resolver=failing_resolver,
                which=lambda command: "/test/bin/uv",
                execvpe=mock.Mock(),
            )

        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: Remem credential is not configured",
        )
        self.assertNotIn(canary, stderr.getvalue())

    def test_launcher_exec_error_is_fixed_and_non_secret(self):
        canary = "vlt_launcher-exec-secret-canary"
        stderr = io.StringIO()

        def failing_execvpe(executable, arguments, environment):
            del executable, arguments, environment
            raise OSError(canary)

        with contextlib.redirect_stderr(stderr):
            result = launcher.main(
                ["--client", "codex"],
                environment={"PATH": "/test/bin"},
                resolver=lambda **kwargs: canary,
                which=lambda command: "/test/bin/uv",
                execvpe=failing_execvpe,
            )

        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: unable to start the Remem MCP server",
        )
        self.assertNotIn(canary, stderr.getvalue())

    def test_launcher_rejects_unsafe_api_origins_before_resolving_key(self):
        invalid = (
            "http://api.remem.io",
            "https://attacker.example",
            "https://user@example.test",
            "https://api.remem.io/path",
            "https://api.remem.io?key=value",
        )
        for api_url in invalid:
            with self.subTest(api_url=api_url):
                resolver = mock.Mock(return_value="configured")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = launcher.main(
                        ["--client", "codex"],
                        environment={
                            "PATH": "/test/bin",
                            "HOME": "/test/home",
                            "REMEM_API_URL": api_url,
                        },
                        resolver=resolver,
                        which=lambda command: "/test/bin/uv",
                        execvpe=mock.Mock(),
                    )

                self.assertEqual(result, 2)
                resolver.assert_not_called()
                self.assertEqual(
                    stderr.getvalue().strip(),
                    "error: invalid Remem API URL",
                )

    def test_launcher_validates_bundled_files_before_resolving_key(self):
        resolver = mock.Mock(return_value="configured")
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(stderr):
                result = launcher.main(
                    ["--client", "codex"],
                    environment={
                        "PATH": "/test/bin",
                        "HOME": "/test/home",
                    },
                    resolver=resolver,
                    which=lambda command: "/test/bin/uv",
                    execvpe=mock.Mock(),
                    bundle_root=Path(directory),
                )

        self.assertEqual(result, 2)
        resolver.assert_not_called()
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: bundled Remem MCP failed integrity validation",
        )

    def test_bundle_validation_rejects_symlinked_package_directory(self):
        source = _ROOT / "plugins" / "remem-memory" / "mcp"
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "mcp"
            shutil.copytree(
                source,
                bundle,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            package = bundle / "remem_mcp"
            moved = bundle / "package-source"
            package.rename(moved)
            package.symlink_to(moved, target_is_directory=True)

            with self.assertRaises(launcher._LauncherError):
                launcher._validate_bundle(bundle)

    def test_bundle_validation_rejects_unmanifested_extra_files(self):
        source = _ROOT / "plugins" / "remem-memory" / "mcp"
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "mcp"
            shutil.copytree(
                source,
                bundle,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            (bundle / "unexpected.py").write_text(
                "raise RuntimeError('must not load')\n",
                encoding="utf-8",
            )

            with self.assertRaises(launcher._LauncherError):
                launcher._validate_bundle(bundle)

    def test_bundle_validation_ignores_generated_python_cache_artifacts(
        self,
    ):
        source = _ROOT / "plugins" / "remem-memory" / "mcp"
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "mcp"
            shutil.copytree(
                source,
                bundle,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            cache = bundle / "remem_mcp" / "__pycache__"
            cache.mkdir()
            (cache / "server.cpython-314.pyc").write_bytes(
                b"ignored-bytecode"
            )

            validated, digest = launcher._validate_bundle(bundle)

        self.assertEqual(validated, bundle.resolve())
        self.assertEqual(len(digest), 64)

    def test_loopback_origin_never_falls_back_to_keychain_resolver(self):
        resolver = mock.Mock(return_value="vlt_keychain-canary")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = launcher.main(
                ["--client", "codex"],
                environment={
                    "PATH": "/test/bin",
                    "HOME": "/test/home",
                    "REMEM_API_URL": "http://127.0.0.1:8000",
                },
                resolver=resolver,
                which=lambda command: "/test/bin/uv",
                execvpe=mock.Mock(),
            )

        self.assertEqual(result, 2)
        resolver.assert_not_called()
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: invalid Remem API URL",
        )

    def test_loopback_origin_accepts_only_explicit_environment_key(self):
        class ExecIntercept(Exception):
            pass

        observed = {}

        def execvpe(executable, arguments, environment):
            del executable, arguments
            descriptor = int(environment["REMEM_API_KEY_FD"])
            observed["credential"] = os.read(
                descriptor,
                8192,
            ).decode("utf-8")
            raise ExecIntercept()

        resolver = mock.Mock(side_effect=AssertionError("must not run"))
        with self.assertRaises(ExecIntercept):
            launcher.main(
                ["--client", "codex"],
                environment={
                    "PATH": "/test/bin",
                    "HOME": "/test/home",
                    "REMEM_API_URL": "http://localhost:8000/",
                    "REMEM_API_KEY": "vlt_loopback-explicit",
                    "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                },
                resolver=resolver,
                which=lambda command: "/test/bin/uv",
                execvpe=execvpe,
            )

        resolver.assert_not_called()
        self.assertEqual(
            observed["credential"],
            "vlt_loopback-explicit",
        )

    def test_named_connection_cannot_route_any_credential_to_loopback(self):
        named = remem_routing.Connection(
            "conn_0123456789abcdef0123456789abcdef",
            "Work",
            "connection:0123456789abcdef0123456789abcdef",
            True,
        )
        config = replace(
            self._routing_config,
            connections=(*self._routing_config.connections, named),
            mcp_connections={"codex": named.id},
        )
        resolver = mock.Mock(return_value="vlt_named-must-not-cross")
        execvpe = mock.Mock()
        stderr = io.StringIO()

        with mock.patch.object(
            remem_routing,
            "load_routing",
            return_value=config,
        ):
            with contextlib.redirect_stderr(stderr):
                result = launcher.main(
                    ["--client", "codex"],
                    environment={
                        "PATH": "/test/bin",
                        "HOME": "/test/home",
                        "REMEM_API_URL": "http://localhost:8000",
                        "REMEM_API_KEY": "vlt_primary-local-only",
                        "REMEM_MEMORY_ALLOW_LOCAL_DEV": "1",
                    },
                    resolver=resolver,
                    which=lambda command: "/test/bin/uv",
                    execvpe=execvpe,
                )

        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue().strip(),
            "error: Remem credential is not configured",
        )
        resolver.assert_not_called()
        execvpe.assert_not_called()

    def test_launcher_creates_private_content_addressed_cache(self):
        self._cache_environment = None
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            lock_digest = "a" * 64
            with mock.patch.object(
                launcher,
                "_cache_environment",
                wraps=self._real_cache_environment,
            ) as cache_factory:
                cache_path = cache_factory(
                    {"HOME": str(home)},
                    lock_digest,
                )
            cache_dir = Path(cache_path).parent
            self.assertEqual(
                cache_dir,
                home / ".cache" / "remem-memory" / "mcp" / ("a" * 16),
            )
            self.assertEqual(
                stat.S_IMODE(cache_dir.stat().st_mode),
                0o700,
            )

    def test_runtime_probe_exercises_uv_descriptor_inheritance_with_dummy(self):
        observed = {"calls": []}

        def runner(arguments, **kwargs):
            observed["calls"].append((list(arguments), dict(kwargs)))
            environment = kwargs["env"]
            if arguments[1] == "sync":
                self.assertNotIn("REMEM_API_KEY_FD", environment)
                self.assertEqual(kwargs.get("pass_fds", ()), ())
                return mock.Mock(returncode=0)
            descriptor = int(environment["REMEM_API_KEY_FD"])
            observed["credential"] = os.read(
                descriptor,
                8192,
            ).decode("utf-8")
            observed["arguments"] = list(arguments)
            observed["pass_fds"] = kwargs["pass_fds"]
            self.assertNotIn("REMEM_API_KEY", environment)
            self.assertNotIn(
                "vlt_real-key-canary",
                json.dumps(environment),
            )
            return mock.Mock(returncode=0)

        result = self._real_run_probe(
            "/test/bin/uv",
            _ROOT / "plugins" / "remem-memory" / "mcp",
            {
                "PATH": "/test/bin",
                "UV_PROJECT_ENVIRONMENT": self._cache_environment,
            },
            runner=runner,
        )

        self.assertEqual(result, 0)
        self.assertEqual(
            observed["credential"],
            "remem-mcp-runtime-probe",
        )
        self.assertIn("import remem_mcp.server", " ".join(observed["arguments"]))
        self.assertEqual(
            observed["arguments"][0],
            str(Path(self._cache_environment) / "bin" / "python"),
        )
        sync_arguments = observed["calls"][0][0]
        self.assertEqual(sync_arguments[0:2], ["/test/bin/uv", "sync"])
        self.assertIn("--no-editable", sync_arguments)
        self.assertIn("--no-install-project", sync_arguments)
        self.assertIn("--locked", sync_arguments)
        self.assertIn("--no-config", sync_arguments)
        self.assertEqual(len(observed["pass_fds"]), 1)

    def test_mcp_bootstrap_uses_claude_substituted_absolute_root(self):
        plugin_root = "/opt/claude/plugins/remem-memory"

        run_path, getcwd, path = self._run_mcp_bootstrap(
            plugin_root,
            "/wrong/current/directory",
        )

        getcwd.assert_not_called()
        self.assertEqual(path[0], f"{plugin_root}/scripts")
        run_path.assert_called_once_with(
            f"{plugin_root}/scripts/remem_mcp_launcher.py",
            run_name="__main__",
        )
        self.assertEqual(
            run_path.observed["argv"][-2:],
            ["--client", "claude"],
        )

    def test_mcp_bootstrap_uses_cwd_for_codex_literal_root(self):
        plugin_root = "/opt/codex/plugins/remem-memory"

        run_path, getcwd, path = self._run_mcp_bootstrap(
            "${CLAUDE_PLUGIN_ROOT}",
            plugin_root,
        )

        getcwd.assert_called_once_with()
        self.assertEqual(path[0], f"{plugin_root}/scripts")
        run_path.assert_called_once_with(
            f"{plugin_root}/scripts/remem_mcp_launcher.py",
            run_name="__main__",
        )
        self.assertEqual(
            run_path.observed["argv"][-2:],
            ["--client", "codex"],
        )

    def test_mcp_bootstrap_runs_from_isolated_codex_plugin_root(self):
        server = self._mcp_server()
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory)
            scripts = plugin_root / "scripts"
            scripts.mkdir()
            (scripts / "remem_mcp_launcher.py").write_text(
                (
                    "import json, os, sys\n"
                    "print(json.dumps({"
                    "'cwd': os.getcwd(), 'path0': sys.path[0]}))\n"
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [sys.executable, *server["args"]],
                cwd=plugin_root,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed["cwd"], str(plugin_root.resolve()))
        self.assertEqual(observed["path0"], str(scripts.resolve()))

    def test_launcher_requires_known_client_before_resolving_credentials(self):
        for arguments in (
            [],
            ["--client"],
            ["--client", "other"],
            ["--client", "codex", "--client", "claude"],
        ):
            with self.subTest(arguments=arguments):
                resolver = mock.Mock(return_value="configured")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = launcher.main(
                        arguments,
                        environment={"PATH": "/test/bin"},
                        resolver=resolver,
                        which=lambda command: "/test/bin/uv",
                        execvpe=mock.Mock(),
                    )

                self.assertEqual(result, 2)
                self.assertEqual(
                    stderr.getvalue().strip(),
                    "error: invalid Remem MCP client",
                )
                resolver.assert_not_called()

    def test_launcher_resolves_only_the_selected_client_connection(self):
        class ExecIntercept(Exception):
            pass

        named = remem_routing.Connection(
            "conn_0123456789abcdef0123456789abcdef",
            "Work",
            "connection:0123456789abcdef0123456789abcdef",
            True,
        )
        config = replace(
            self._routing_config,
            connections=(*self._routing_config.connections, named),
            mcp_connections={"codex": named.id, "claude": "primary"},
        )
        observed = []

        def resolver(**kwargs):
            connection = kwargs["connection"]
            observed.append(connection.id)
            return {
                "primary": "vlt_primary-must-not-cross",
                named.id: "vlt_named-selected",
            }[connection.id]

        def execvpe(executable, arguments, environment):
            del executable, arguments
            descriptor = int(environment["REMEM_API_KEY_FD"])
            observed.append(os.read(descriptor, 8192).decode("utf-8"))
            raise ExecIntercept()

        with mock.patch.object(
            remem_routing,
            "load_routing",
            return_value=config,
        ):
            with self.assertRaises(ExecIntercept):
                launcher.main(
                    ["--client", "codex"],
                    environment={"PATH": "/test/bin"},
                    resolver=resolver,
                    which=lambda command: "/test/bin/uv",
                    execvpe=execvpe,
                )

        self.assertEqual(observed, [named.id, "vlt_named-selected"])
        self.assertNotIn("vlt_primary-must-not-cross", json.dumps(observed))

    def test_bundled_mcp_omits_unspecified_namespaces(self):
        request = mock.AsyncMock(
            side_effect=(
                {"ok": True},
                {"ok": True},
                {"results": []},
                {"results": []},
            )
        )
        with mock.patch.dict(
            os.environ,
            {"REMEM_DEFAULT_NAMESPACE": "legacy-must-not-route"},
            clear=False,
        ):
            with mock.patch.object(
                bundled_mcp_server,
                "_request",
                request,
            ):
                asyncio.run(
                    bundled_mcp_server.call_tool(
                        "remem_ingest",
                        {
                            "content": "first",
                            "source_id": "source-one",
                        },
                    )
                )
                asyncio.run(
                    bundled_mcp_server.call_tool(
                        "remem_ingest",
                        {
                            "content": "second",
                            "source_id": "source-two",
                            "namespace": "explicit-write",
                        },
                    )
                )
                asyncio.run(
                    bundled_mcp_server.call_tool(
                        "remem_query",
                        {"query": "all readable"},
                    )
                )
                asyncio.run(
                    bundled_mcp_server.call_tool(
                        "remem_query",
                        {
                            "query": "selected",
                            "namespaces": ["one", "two"],
                        },
                    )
                )

        omitted_write = request.await_args_list[0].kwargs["json_body"]
        explicit_write = request.await_args_list[1].kwargs["json_body"]
        omitted_read = request.await_args_list[2].kwargs["json_body"]
        explicit_read = request.await_args_list[3].kwargs["json_body"]
        self.assertNotIn("namespace", omitted_write)
        self.assertEqual(explicit_write["namespace"], "explicit-write")
        self.assertNotIn("namespaces", omitted_read)
        self.assertEqual(explicit_read["namespaces"], ["one", "two"])

    def test_bundled_mcp_schema_rejects_explicit_empty_namespace_intent(self):
        tools = {
            tool.name: tool
            for tool in asyncio.run(bundled_mcp_server.list_tools())
        }
        write_schema = tools["remem_ingest"].inputSchema["properties"][
            "namespace"
        ]
        read_schema = tools["remem_query"].inputSchema["properties"][
            "namespaces"
        ]

        self.assertEqual(write_schema.get("minLength"), 1)
        self.assertEqual(write_schema.get("pattern"), r".*\S.*")
        self.assertEqual(read_schema.get("minItems"), 1)
        self.assertEqual(read_schema["items"].get("minLength"), 1)
        self.assertEqual(read_schema["items"].get("pattern"), r".*\S.*")

    def test_bundled_mcp_explicit_empty_namespace_never_calls_api(self):
        cases = (
            (
                "remem_ingest",
                {"content": "write", "namespace": ""},
            ),
            (
                "remem_ingest",
                {"content": "write", "namespace": "   "},
            ),
            (
                "remem_query",
                {"query": "read", "namespaces": []},
            ),
            (
                "remem_query",
                {"query": "read", "namespaces": [""]},
            ),
            (
                "remem_query",
                {"query": "read", "namespaces": ["   "]},
            ),
            (
                "remem_query",
                {"query": "read", "namespaces": ["valid", ""]},
            ),
        )
        for tool, arguments in cases:
            with self.subTest(tool=tool, arguments=arguments):
                request = mock.AsyncMock(return_value={"ok": True})
                with mock.patch.object(
                    bundled_mcp_server,
                    "_request",
                    request,
                ):
                    result = asyncio.run(
                        bundled_mcp_server.call_tool(tool, arguments)
                    )

                request.assert_not_awaited()
                self.assertEqual(
                    result[0].text,
                    (
                        "Remem request failed: "
                        "status=unavailable kind=request"
                    ),
                )
                self.assertNotIn("valid", result[0].text)

    def test_bundled_mcp_retries_only_fixed_transient_matrix(self):
        class Response:
            def __init__(self, status, *, body="vlt_response-body-canary"):
                self.status_code = status
                self.text = body

            def json(self):
                return {"ok": True}

            def raise_for_status(self):
                if not 200 <= self.status_code < 300:
                    error = bundled_mcp_server.httpx.HTTPStatusError()
                    error.response = self
                    raise error

        class Client:
            def __init__(self, outcomes, calls):
                self.outcomes = outcomes
                self.calls = calls

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                outcome = self.outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        bundled_mcp_server.httpx.TimeoutException = type(
            "TimeoutException",
            (Exception,),
            {},
        )
        bundled_mcp_server.httpx.NetworkError = type(
            "NetworkError",
            (Exception,),
            {},
        )
        cases = (
            (400, "request"),
            (401, "auth"),
            (403, "permission"),
            (404, "namespace"),
            (422, "request"),
        )
        for status, kind in cases:
            with self.subTest(status=status):
                calls = []
                sleeps = mock.AsyncMock()
                with mock.patch.object(
                    bundled_mcp_server.httpx,
                    "AsyncClient",
                    return_value=Client([Response(status)], calls),
                ):
                    with mock.patch.object(
                        bundled_mcp_server,
                        "_get_api_key",
                        return_value="vlt_test-key",
                    ):
                        with mock.patch.object(
                            bundled_mcp_server,
                            "_sleep",
                            sleeps,
                            create=True,
                        ):
                            with self.assertRaises(Exception) as caught:
                                asyncio.run(
                                    bundled_mcp_server._request(
                                        "POST",
                                        "/v1/query",
                                        json_body={"query": "fixed"},
                                    )
                                )

                self.assertEqual(
                    str(caught.exception),
                    f"Remem request failed: status={status} kind={kind}",
                )
                self.assertEqual(len(calls), 1)
                sleeps.assert_not_awaited()
                self.assertNotIn(
                    "response-body-canary",
                    str(caught.exception),
                )

        for status in (429, 500, 502, 503, 504):
            with self.subTest(status=status):
                calls = []
                sleeps = mock.AsyncMock()
                with mock.patch.object(
                    bundled_mcp_server.httpx,
                    "AsyncClient",
                    return_value=Client(
                        [Response(status), Response(status), Response(200)],
                        calls,
                    ),
                ):
                    with mock.patch.object(
                        bundled_mcp_server.uuid,
                        "uuid4",
                        return_value="stable-idempotency",
                    ):
                        with mock.patch.object(
                            bundled_mcp_server,
                            "_get_api_key",
                            return_value="vlt_test-key",
                        ):
                            with mock.patch.object(
                                bundled_mcp_server,
                                "_sleep",
                                sleeps,
                                create=True,
                            ):
                                try:
                                    result = asyncio.run(
                                        bundled_mcp_server._request(
                                            "POST",
                                            "/v1/query",
                                            json_body={
                                                "query": "stable",
                                                "source_id": "stable-source",
                                                "namespace": "fixed-destination",
                                            },
                                        )
                                    )
                                except Exception as error:
                                    result = error

                self.assertEqual(result, {"ok": True})
                self.assertEqual(len(calls), 3)
                self.assertTrue(
                    all(call[0] == calls[0][0] for call in calls)
                )
                self.assertEqual(
                    [call.args[0] for call in sleeps.await_args_list],
                    [0.25, 0.5],
                )
                self.assertEqual(
                    {json.dumps(call[1], sort_keys=True, default=str) for call in calls},
                    {json.dumps(calls[0][1], sort_keys=True, default=str)},
                )
                self.assertEqual(
                    {
                        call[1]["headers"].get("Idempotency-Key")
                        for call in calls
                    },
                    {"stable-idempotency"},
                )

        for exception_type in (
            bundled_mcp_server.httpx.TimeoutException,
            bundled_mcp_server.httpx.NetworkError,
        ):
            with self.subTest(exception=exception_type.__name__):
                calls = []
                sleeps = mock.AsyncMock()
                with mock.patch.object(
                    bundled_mcp_server.httpx,
                    "AsyncClient",
                    return_value=Client(
                        [
                            exception_type("vlt_network-canary"),
                            exception_type("vlt_network-canary"),
                            Response(200),
                        ],
                        calls,
                    ),
                ):
                    with mock.patch.object(
                        bundled_mcp_server,
                        "_get_api_key",
                        return_value="vlt_test-key",
                    ):
                        with mock.patch.object(
                            bundled_mcp_server,
                            "_sleep",
                            sleeps,
                            create=True,
                        ):
                            result = asyncio.run(
                                bundled_mcp_server._request(
                                    "GET",
                                    "/v1/entities",
                                    params={"limit": 10},
                                )
                            )

                self.assertEqual(result, {"ok": True})
                self.assertEqual(len(calls), 3)
                self.assertEqual(
                    [call.args[0] for call in sleeps.await_args_list],
                    [0.25, 0.5],
                )

    def test_bundled_mcp_retry_keeps_request_and_redacts_response(self):
        class Response:
            status_code = 403
            text = "vlt_response-body-canary"

            def json(self):
                return {"must": "not return"}

            def raise_for_status(self):
                error = bundled_mcp_server.httpx.HTTPStatusError()
                error.response = self
                raise error

        class Client:
            def __init__(self):
                self.calls = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return Response()

        client = Client()
        with mock.patch.object(
            bundled_mcp_server.httpx,
            "AsyncClient",
            return_value=client,
        ):
            with mock.patch.object(
                bundled_mcp_server,
                "_get_api_key",
                return_value="vlt_test-key",
            ):
                result = asyncio.run(
                    bundled_mcp_server.call_tool(
                        "remem_ingest",
                        {
                            "content": "stable content",
                            "source_id": "stable-source",
                            "namespace": "fixed-destination",
                        },
                    )
                )

        self.assertEqual(
            result[0].text,
            "Remem request failed: status=403 kind=permission",
        )
        self.assertEqual(len(client.calls), 1)
        self.assertNotIn("response-body-canary", result[0].text)

    def test_mcp_config_uses_cross_loader_and_contains_no_secret(self):
        server = self._mcp_server()
        serialized = json.dumps(server)

        self.assertEqual(server["command"], "python3")
        self.assertEqual(server["cwd"], ".")
        self.assertEqual(server["args"][0:2], ["-I", "-c"])
        self.assertIn("sys.path.insert", server["args"][2])
        self.assertIn("runpy.run_path", server["args"][2])
        self.assertEqual(server["args"][3], "${CLAUDE_PLUGIN_ROOT}")
        self.assertNotIn("env", server)
        self.assertNotIn(":-", serialized)
        self.assertNotIn("REMEM_API_KEY", serialized)
        self.assertNotIn("@master", serialized)
        self.assertNotIn("github.com/asimgilani/remem", serialized)

    def test_bundled_mcp_has_audited_provenance_and_exact_dependencies(self):
        bundle = _ROOT / "plugins" / "remem-memory" / "mcp"
        provenance = json.loads(
            (bundle / "PROVENANCE.json").read_text(encoding="utf-8")
        )
        project = (bundle / "pyproject.toml").read_text(encoding="utf-8")
        lock = (bundle / "uv.lock").read_text(encoding="utf-8")

        self.assertEqual(
            provenance["upstream_commit"],
            "759a57af927908315a3a4f6e4c73a935faf8d56f",
        )
        self.assertEqual(
            provenance["upstream_sha256"]["remem_mcp/server.py"],
            "f3e74617cc8ef3c11a2f9d944f99bdfb1cb245a581658023b30a9ac7244493df",
        )
        self.assertIn('"httpx==0.28.1"', project)
        self.assertIn('"mcp==1.26.0"', project)
        self.assertIn('name = "httpx"', lock)
        self.assertIn('version = "0.28.1"', lock)
        self.assertIn('name = "mcp"', lock)
        self.assertIn('version = "1.26.0"', lock)
        self.assertIn("[tool.uv]", project)
        self.assertIn("package = false", project)
        self.assertIn('source = { virtual = "." }', lock)
        self.assertNotIn("[build-system]", project)
        self.assertNotIn("[project.scripts]", project)
        self.assertNotIn("hatchling", project + lock)
        self.assertNotIn("github.com/asimgilani/remem", project + lock)

    def test_bundled_mcp_explicitly_refuses_http_redirects(self):
        server_source = (
            _ROOT
            / "plugins"
            / "remem-memory"
            / "mcp"
            / "remem_mcp"
            / "server.py"
        ).read_text(encoding="utf-8")
        self.assertIn("follow_redirects=False", server_source)
        self.assertIn("trust_env=False", server_source)
        self.assertLess(
            server_source.index("_API_KEY = _read_api_key()"),
            server_source.index("import httpx"),
        )

    def test_bundled_mcp_consumes_key_from_anonymous_descriptor_only(self):
        server_source = (
            _ROOT
            / "plugins"
            / "remem-memory"
            / "mcp"
            / "remem_mcp"
            / "server.py"
        ).read_text(encoding="utf-8")
        self.assertIn('os.environ.pop("REMEM_API_KEY_FD"', server_source)
        self.assertIn("os.close(descriptor)", server_source)
        self.assertNotIn('os.getenv("REMEM_API_KEY"', server_source)


if __name__ == "__main__":
    unittest.main()
