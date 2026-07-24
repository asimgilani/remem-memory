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
from pathlib import Path
from unittest import mock


_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN_SCRIPTS = _ROOT / "plugins" / "remem-memory" / "scripts"
sys.path.insert(0, str(_PLUGIN_SCRIPTS))

from scripts import remem_dev_sessions, remem_memory  # noqa: E402


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
        run_path = mock.Mock()
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
                "REMEM_DEFAULT_NAMESPACE": "engineering",
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

    def test_launcher_supplies_literal_safe_mcp_defaults(self):
        class ExecIntercept(Exception):
            pass

        child = {}

        def execvpe(executable, arguments, environment):
            del executable, arguments
            child.update(environment)
            raise ExecIntercept()

        with self.assertRaises(ExecIntercept):
            launcher.main(
                environment={"PATH": "/test/bin"},
                resolver=lambda **kwargs: "configured",
                which=lambda command: "/test/bin/uv",
                execvpe=execvpe,
            )

        self.assertEqual(
            child["REMEM_API_URL"],
            "https://api.remem.io",
        )
        self.assertEqual(child["REMEM_DEFAULT_NAMESPACE"], "default")

    def test_launcher_missing_key_error_is_fixed_and_non_secret(self):
        canary = "vlt_launcher-secret-canary"
        stderr = io.StringIO()

        def failing_resolver(**kwargs):
            raise RuntimeError(canary)

        with contextlib.redirect_stderr(stderr):
            result = launcher.main(
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
