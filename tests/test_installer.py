from __future__ import annotations

import contextlib
import hmac
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import install_remem_memory


_LIVE_ROOT = Path(__file__).resolve().parents[1]
_CANARY = "vlt_installer-secret-canary"


def _same_text(left: str, right: str) -> bool:
    return hmac.compare_digest(
        left.encode("utf-8"),
        right.encode("utf-8"),
    )


def _assert_secret_absent(
    test: unittest.TestCase,
    secret: str,
    *values: str,
) -> None:
    test.assertFalse(
        any(secret in value for value in values),
        "secret material was exposed",
    )


class FakeResult:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeKeychain:
    def __init__(
        self,
        value: str | None = None,
        *,
        read_after_write: str | None = None,
    ) -> None:
        self.value = value
        self.read_after_write = read_after_write
        self.calls: list[tuple[Any, ...]] = []
        self._wrote = False

    def read(self, service: str, account: str | None = None) -> str | None:
        self.calls.append(("read", service, account))
        if self._wrote and self.read_after_write is not None:
            return self.read_after_write
        return self.value

    def write(self, service: str, account: str, value: str) -> None:
        self.calls.append(("write", service, account, value))
        self.value = value
        self._wrote = True


class FakeRunner:
    """Stateful Codex/Claude/uv command harness with no real subprocesses."""

    def __init__(
        self,
        *,
        codex: bool = False,
        claude: bool = False,
        missing: set[str] | None = None,
        codex_marketplaces: list[dict[str, Any]] | None = None,
        codex_plugins: list[dict[str, Any]] | None = None,
        claude_marketplaces: list[dict[str, Any]] | None = None,
        claude_plugins: list[dict[str, Any]] | None = None,
        codex_verifies: bool = True,
        claude_verifies: bool = True,
        claude_action_enabled: bool = True,
        mcp_probe_succeeds: bool = True,
        failures: set[tuple[str, ...]] | None = None,
        events: list[tuple[Any, ...]] | None = None,
    ) -> None:
        self.codex = codex
        self.claude = claude
        self.missing = missing or set()
        self.codex_marketplaces = list(codex_marketplaces or [])
        self.codex_plugins = list(codex_plugins or [])
        self.claude_marketplaces = list(claude_marketplaces or [])
        self.claude_plugins = list(claude_plugins or [])
        self.codex_verifies = codex_verifies
        self.claude_verifies = claude_verifies
        self.claude_action_enabled = claude_action_enabled
        self.mcp_probe_succeeds = mcp_probe_succeeds
        self.failures = failures or set()
        self.commands: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.events = events if events is not None else []

    def __call__(self, args: list[str], **kwargs: Any) -> FakeResult:
        command = tuple(str(item) for item in args)
        environment = dict(kwargs["env"])
        self.commands.append(command)
        self.environments.append(environment)
        self.events.append(("command", command))

        if command[0] in self.missing:
            raise FileNotFoundError(command[0])
        if command in self.failures:
            return FakeResult(1, _CANARY, _CANARY)
        if command[-1:] == ("--probe",):
            return FakeResult(0 if self.mcp_probe_succeeds else 1)

        if command == ("uv", "--version") or command == ("uvx", "--version"):
            return FakeResult(stdout=f"{command[0]} 1.0\n")
        if command[:2] == ("uv", "venv"):
            venv = Path(command[2])
            if venv.exists() or venv.is_symlink():
                return FakeResult(
                    2,
                    stderr="A virtual environment already exists\n",
                )
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text(
                "# fake repository interpreter\n",
                encoding="utf-8",
            )
            (venv / "bin" / "python").chmod(0o755)
            (venv / "pyvenv.cfg").write_text(
                "home = /fake\n",
                encoding="utf-8",
            )
            return FakeResult()
        if command[:3] == ("uv", "pip", "install"):
            return FakeResult()

        if command == ("codex", "--version"):
            if not self.codex:
                raise FileNotFoundError("codex")
            return FakeResult(stdout="codex 1.0\n")
        if command == ("codex", "plugin", "marketplace", "list", "--json"):
            return self._json({"marketplaces": self.codex_marketplaces})
        if command[:4] == ("codex", "plugin", "marketplace", "add"):
            self.codex_marketplaces = [
                item for item in self.codex_marketplaces if item.get("name") != "remem-memory"
            ]
            self.codex_marketplaces.append(
                {
                    "name": "remem-memory",
                    "marketplaceSource": {
                        "sourceType": "local",
                        "source": command[4],
                    },
                }
            )
            return FakeResult(stdout="{}\n")
        if command == (
            "codex",
            "plugin",
            "marketplace",
            "upgrade",
            "remem-memory",
            "--json",
        ):
            return FakeResult(stdout="{}\n")
        if command == (
            "codex",
            "plugin",
            "add",
            "remem-memory@remem-memory",
            "--json",
        ):
            self.codex_plugins = [
                item for item in self.codex_plugins if item.get("name") != "remem-memory"
            ]
            self.codex_plugins.append(
                {
                    "name": "remem-memory",
                    "marketplace": "remem-memory",
                    "version": "0.3.1" if self.codex_verifies else "0.2.9",
                    "enabled": self.codex_verifies,
                }
            )
            return FakeResult(stdout="{}\n")
        if command == ("codex", "plugin", "list", "--json"):
            return self._json({"plugins": self.codex_plugins})
        if command == ("codex", "mcp", "remove", "remem"):
            config = Path(environment["CODEX_HOME"]) / "config.toml"
            if config.exists():
                lines = config.read_text(encoding="utf-8").splitlines()
                preserved: list[str] = []
                skipping = False
                for line in lines:
                    stripped = line.strip()
                    if stripped in {
                        "[mcp_servers.remem]",
                        "[mcp_servers.remem.env]",
                    }:
                        skipping = True
                        continue
                    if skipping and stripped.startswith("["):
                        skipping = False
                    if not skipping:
                        preserved.append(line)
                rendered = "\n".join(preserved).strip()
                config.write_text(
                    f"{rendered}\n" if rendered else "",
                    encoding="utf-8",
                )
            return FakeResult()

        if command == ("claude", "--version"):
            if not self.claude:
                raise FileNotFoundError("claude")
            return FakeResult(stdout="claude 1.0\n")
        if command == ("claude", "plugin", "marketplace", "list", "--json"):
            return self._json({"marketplaces": self.claude_marketplaces})
        if command[:4] == ("claude", "plugin", "marketplace", "add"):
            self.claude_marketplaces = [
                item
                for item in self.claude_marketplaces
                if item.get("name") != "remem-memory"
            ]
            self.claude_marketplaces.append(
                {
                    "name": "remem-memory",
                    "source": "directory",
                    "path": command[4],
                }
            )
            return FakeResult()
        if command == (
            "claude",
            "plugin",
            "marketplace",
            "update",
            "remem-memory",
        ):
            return FakeResult()
        if command == ("claude", "plugin", "list", "--json"):
            return self._json({"plugins": self.claude_plugins})
        if command in {
            (
                "claude",
                "plugin",
                "install",
                "remem-memory@remem-memory",
            ),
            (
                "claude",
                "plugin",
                "update",
                "remem-memory@remem-memory",
            ),
        }:
            self._set_claude_plugin(
                version="0.3.1" if self.claude_verifies else "0.2.9",
                enabled=self.claude_action_enabled and self.claude_verifies,
            )
            return FakeResult()
        if command == (
            "claude",
            "plugin",
            "enable",
            "remem-memory@remem-memory",
        ):
            self._set_claude_plugin(
                version="0.3.1" if self.claude_verifies else "0.2.9",
                enabled=self.claude_verifies,
            )
            return FakeResult()
        if command == (
            "claude",
            "plugin",
            "disable",
            "remem-dev-sessions@remem-dev-sessions",
        ):
            for plugin in self.claude_plugins:
                if plugin.get("name") == "remem-dev-sessions":
                    plugin["enabled"] = False
            return FakeResult()
        if command == (
            "claude",
            "plugin",
            "uninstall",
            "remem-dev-sessions@remem-dev-sessions",
            "--keep-data",
        ):
            self.claude_plugins = [
                item
                for item in self.claude_plugins
                if item.get("name") != "remem-dev-sessions"
            ]
            return FakeResult()
        if command == (
            "claude",
            "plugin",
            "marketplace",
            "remove",
            "remem-dev-sessions",
        ):
            self.claude_marketplaces = [
                item
                for item in self.claude_marketplaces
                if item.get("name") != "remem-dev-sessions"
            ]
            return FakeResult()

        raise AssertionError(f"unexpected command shape: {command!r}")

    @staticmethod
    def _json(value: dict[str, Any]) -> FakeResult:
        return FakeResult(stdout=json.dumps(value))

    def _set_claude_plugin(self, *, version: str, enabled: bool) -> None:
        self.claude_plugins = [
            item for item in self.claude_plugins if item.get("name") != "remem-memory"
        ]
        self.claude_plugins.append(
            {
                "name": "remem-memory",
                "marketplace": "remem-memory",
                "version": version,
                "enabled": enabled,
            }
        )


class ProductionShapeCodexRunner(FakeRunner):
    """Mirror the installed Codex CLI's top-level plugin-list schema."""

    def __call__(self, args: list[str], **kwargs: Any) -> FakeResult:
        result = super().__call__(args, **kwargs)
        command = tuple(str(item) for item in args)
        if command == ("codex", "plugin", "list", "--json"):
            return self._json({"installed": self.codex_plugins})
        return result


class ExistingHarnessRootRunner(FakeRunner):
    """Mirror CLIs that require their injected configuration root to exist."""

    def __call__(self, args: list[str], **kwargs: Any) -> FakeResult:
        command = tuple(str(item) for item in args)
        result = super().__call__(args, **kwargs)
        environment = kwargs["env"]
        if command[:2] == ("codex", "plugin"):
            if not Path(environment["CODEX_HOME"]).is_dir():
                return FakeResult(1)
        if command[:2] == ("claude", "plugin"):
            if not Path(environment["CLAUDE_CONFIG_DIR"]).is_dir():
                return FakeResult(1)
        return result


class InstallerFixture:
    def __init__(
        self,
        temporary_directory: str,
        *,
        legacy_config: str | None = None,
    ) -> None:
        base = Path(temporary_directory)
        self.repo_root = base / "checkout"
        self.home = base / "home"
        self.codex_home = base / "codex"
        self.claude_config = base / "claude"
        (self.repo_root / "scripts").mkdir(parents=True)
        for skill_name in install_remem_memory.SKILL_ALIASES:
            (self.repo_root / "codex" / "skills" / skill_name).mkdir(
                parents=True
            )
        (self.repo_root / ".agents" / "plugins").mkdir(parents=True)
        (self.repo_root / ".claude-plugin").mkdir(parents=True)
        (self.repo_root / "plugins" / "remem-memory").mkdir(parents=True)
        (self.repo_root / "scripts" / "remem_memory.py").write_text(
            "#!/usr/bin/env python3\nraise SystemExit(0)\n",
            encoding="utf-8",
        )
        for skill_name in install_remem_memory.SKILL_ALIASES:
            (
                self.repo_root
                / "codex"
                / "skills"
                / skill_name
                / "SKILL.md"
            ).write_text(
                (
                    "---\n"
                    f"name: {skill_name}\n"
                    "description: test\n"
                    "---\n"
                ),
                encoding="utf-8",
            )
        (self.repo_root / ".agents" / "plugins" / "marketplace.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        (self.repo_root / ".claude-plugin" / "marketplace.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        self.environment = {
            "HOME": str(self.home),
            "CODEX_HOME": str(self.codex_home),
            "CLAUDE_CONFIG_DIR": str(self.claude_config),
            "PATH": "/test/bin:/usr/bin:/bin",
            "REMEM_API_KEY": _CANARY,
        }
        if legacy_config is not None:
            self.codex_home.mkdir(parents=True)
            (self.codex_home / "config.toml").write_text(
                legacy_config,
                encoding="utf-8",
            )

    def install(
        self,
        *,
        runner: FakeRunner,
        keychain: FakeKeychain | None = None,
    ) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = install_remem_memory.main(
                [],
                home=self.home,
                environment=self.environment,
                runner=runner,
                keychain=keychain or FakeKeychain(),
                repo_root=self.repo_root,
            )
        return result, output.getvalue()


class LegacyCredentialParserTests(unittest.TestCase):
    def test_accepts_one_exact_basic_string_in_exact_table(self) -> None:
        text = (
            "[mcp_servers.remem]\n"
            'command = "uvx"\n\n'
            "[mcp_servers.remem.env]\n"
            'REMEM_API_URL = "https://api.remem.io"\n'
            'REMEM_API_KEY = "vlt_exact\\tvalue"\n'
        )
        self.assertEqual(
            _same_text(
                install_remem_memory.parse_legacy_api_key(text) or "",
                "vlt_exact\tvalue",
            ),
            True,
        )

    def test_absent_legacy_key_returns_none(self) -> None:
        self.assertIsNone(
            install_remem_memory.parse_legacy_api_key(
                '[mcp_servers.other.env]\nVALUE = "ok"\n'
            )
        )

    def test_ignores_key_token_inside_unrelated_assignment_value(self) -> None:
        text = (
            "[mcp_servers.remem-maya]\n"
            'args = ["--env", "REMEM_API_KEY"]\n\n'
            "[mcp_servers.remem.env]\n"
            'REMEM_API_KEY = "vlt_exact"\n'
        )

        parsed = install_remem_memory.parse_legacy_api_key(text)

        self.assertTrue(_same_text(parsed or "", "vlt_exact"))

    def test_rejects_duplicates_near_matches_and_malformed_values(self) -> None:
        invalid_cases = {
            "duplicate key": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = "one"\n'
                'REMEM_API_KEY = "two"\n'
            ),
            "duplicate table": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = "one"\n'
                "[mcp_servers.remem.env]\n"
            ),
            "literal string": (
                "[mcp_servers.remem.env]\n"
                "REMEM_API_KEY = 'one'\n"
            ),
            "multiline string": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = """one"""\n'
            ),
            "unquoted": (
                "[mcp_servers.remem.env]\n"
                "REMEM_API_KEY = one\n"
            ),
            "wrong table": (
                "[mcp_servers.remem.environment]\n"
                'REMEM_API_KEY = "one"\n'
            ),
            "near key": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEYS = "one"\n'
            ),
            "wrong key case": (
                "[mcp_servers.remem.env]\n"
                'remem_api_key = "one"\n'
            ),
            "quoted key": (
                "[mcp_servers.remem.env]\n"
                '"REMEM_API_KEY" = "one"\n'
            ),
            "malformed escape": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = "one\\q"\n'
            ),
            "empty": (
                "[mcp_servers.remem.env]\n"
                'REMEM_API_KEY = ""\n'
            ),
        }
        for label, text in invalid_cases.items():
            with self.subTest(label=label):
                with self.assertRaises(install_remem_memory.LegacyCredentialError):
                    install_remem_memory.parse_legacy_api_key(text)


class SecureInstallerTests(unittest.TestCase):
    def test_missing_uv_fails_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(
                directory,
                legacy_config=(
                    "[mcp_servers.remem.env]\n"
                    f'REMEM_API_KEY = "{_CANARY}"\n'
                ),
            )
            keychain = FakeKeychain()
            runner = FakeRunner(missing={"uv"})
            before = sorted(path.relative_to(fixture.repo_root) for path in fixture.repo_root.rglob("*"))

            result, output = fixture.install(runner=runner, keychain=keychain)

            after = sorted(path.relative_to(fixture.repo_root) for path in fixture.repo_root.rglob("*"))
            self.assertEqual(result, 1)
            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(keychain.calls, [])
            self.assertEqual(before, after)
            self.assertFalse(fixture.home.exists())
            self.assertNotIn(("uv", "venv", str(fixture.repo_root / ".venv")), runner.commands)

    def test_no_supported_client_fails_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            keychain = FakeKeychain()
            runner = FakeRunner()
            before = sorted(
                item.relative_to(fixture.repo_root)
                for item in fixture.repo_root.rglob("*")
            )

            result, output = fixture.install(runner=runner, keychain=keychain)

            after = sorted(
                item.relative_to(fixture.repo_root)
                for item in fixture.repo_root.rglob("*")
            )
            self.assertEqual(result, 1)
            self.assertIn("install Codex or Claude Code first", output)
            self.assertNotIn("installed successfully", output)
            self.assertNotIn("Finish activation", output)
            self.assertEqual(keychain.calls, [])
            self.assertEqual(before, after)
            self.assertFalse(fixture.home.exists())
            self.assertFalse(
                any(command[-1:] == ("--probe",) for command in runner.commands)
            )

    def test_success_output_matches_verified_clients(self) -> None:
        cases = (
            (True, False, ("Codex Desktop", "Codex CLI"), ("Claude Code:",)),
            (
                False,
                True,
                ("Claude Code:", "/reload-plugins"),
                ("Codex Desktop", "Codex CLI", "Codex hooks trusted"),
            ),
            (True, True, ("Codex Desktop", "Codex CLI", "Claude Code:"), ()),
        )
        for codex, claude, included, excluded in cases:
            with self.subTest(codex=codex, claude=claude), tempfile.TemporaryDirectory() as directory:
                fixture = InstallerFixture(directory)
                result, output = fixture.install(
                    runner=FakeRunner(codex=codex, claude=claude)
                )

                self.assertEqual(result, 0, output)
                self.assertIn("Remem Memory installed successfully.", output)
                self.assertIn("Finish activation:", output)
                self.assertIn(
                    "env -u REMEM_API_KEY ~/.local/bin/remem-memory status",
                    output,
                )
                self.assertIn("~/.local/bin/remem-memory auth", output)
                for phrase in included:
                    self.assertIn(phrase, output)
                for phrase in excluded:
                    self.assertNotIn(phrase, output)
                _assert_secret_absent(self, _CANARY, output)
                self.assertNotIn("dangerously-bypass-hook-trust", output)

    def test_installs_stdlib_command_aliases_and_skill_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(codex=True)

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            self.assertFalse(
                any(
                    command[:2] in {("uv", "venv"), ("uv", "pip")}
                    for command in runner.commands
                )
            )
            canonical_script = fixture.repo_root / "scripts" / "remem_memory.py"
            for alias in install_remem_memory.COMMAND_ALIASES:
                link = fixture.home / ".local" / "bin" / alias
                self.assertTrue(link.is_symlink(), alias)
                self.assertEqual(link.resolve(), canonical_script.resolve(), alias)
            for alias in install_remem_memory.SKILL_ALIASES:
                link = fixture.home / ".agents" / "skills" / alias
                source = fixture.repo_root / "codex" / "skills" / alias
                self.assertTrue(link.is_symlink(), alias)
                self.assertEqual(link.resolve(), source.resolve(), alias)
                frontmatter = (
                    (link / "SKILL.md")
                    .read_text(encoding="utf-8")
                    .splitlines()
                )
                self.assertIn(f"name: {alias}", frontmatter, alias)
            self.assertFalse(
                any(
                    command[0] in {"pip", "pip3", "python", "python3"}
                    and "install" in command
                    for command in runner.commands
                )
            )

    def test_does_not_manage_an_existing_repository_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            venv = fixture.repo_root / ".venv"
            venv.write_text("user-owned\n", encoding="utf-8")
            runner = FakeRunner(codex=True)

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            self.assertEqual(
                venv.read_text(encoding="utf-8"),
                "user-owned\n",
            )

    def test_creates_private_injected_harness_roots_before_plugin_commands(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = ExistingHarnessRootRunner(
                codex=True,
                claude=True,
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            for path in (
                fixture.codex_home,
                fixture.claude_config,
            ):
                self.assertTrue(path.is_dir())
                self.assertEqual(
                    stat.S_IMODE(path.stat().st_mode),
                    0o700,
                )

    def test_occupied_harness_root_fails_before_installation_mutation(
        self,
    ) -> None:
        cases = (
            ("codex", "codex_home"),
            ("claude", "claude_config"),
        )
        for harness, attribute in cases:
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as directory:
                fixture = InstallerFixture(directory)
                occupied = getattr(fixture, attribute)
                occupied.parent.mkdir(parents=True, exist_ok=True)
                occupied.write_text("preserve me\n", encoding="utf-8")
                runner = ExistingHarnessRootRunner(
                    codex=harness == "codex",
                    claude=harness == "claude",
                )

                result, output = fixture.install(runner=runner)

                self.assertEqual(result, 1)
                self.assertNotIn(
                    (
                        "uv",
                        "venv",
                        str(fixture.repo_root / ".venv"),
                    ),
                    runner.commands,
                )
                self.assertEqual(
                    occupied.read_text(encoding="utf-8"),
                    "preserve me\n",
                )
                self.assertFalse(fixture.home.exists())
                self.assertNotIn("preserve me", output)

    def test_every_child_environment_is_scrubbed_without_mutating_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            fixture.environment["PATH"] += (
                os.pathsep + str(fixture.home / ".local" / "bin")
            )
            fixture.environment.update(
                {
                    "PYTHONPATH": "/tmp/untrusted-python",
                    "PYTHONINSPECT": "1",
                    "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
                    "LD_PRELOAD": "/tmp/untrusted.so",
                    "NODE_OPTIONS": "--require=/tmp/untrusted.js",
                    "NODE_PATH": "/tmp/untrusted-node",
                    "BASH_ENV": "/tmp/untrusted-bash",
                    "ENV": "/tmp/untrusted-shell",
                    "ZDOTDIR": "/tmp/untrusted-zsh",
                    "PERL5OPT": "-M/tmp/untrusted-perl",
                    "RUBYOPT": "-r/tmp/untrusted-ruby",
                    "AWS_SECRET_ACCESS_KEY": "unrelated-cloud-secret",
                    "SSH_AUTH_SOCK": "/tmp/unrelated-agent",
                }
            )
            runner = FakeRunner(codex=True, claude=True)

            result, output = fixture.install(runner=runner)

            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(result, 0)
            self.assertTrue(
                _same_text(
                    fixture.environment["REMEM_API_KEY"],
                    _CANARY,
                )
            )
            self.assertTrue(runner.environments)
            for environment in runner.environments:
                self.assertNotIn("REMEM_API_KEY", environment)
                self.assertEqual(environment["HOME"], str(fixture.home))
                self.assertEqual(environment["CODEX_HOME"], str(fixture.codex_home))
                self.assertEqual(
                    environment["CLAUDE_CONFIG_DIR"],
                    str(fixture.claude_config),
                )
                self.assertEqual(
                    environment["PATH"].split(os.pathsep)[0],
                    str(fixture.home / ".local" / "bin"),
                )
                for name in (
                    "PYTHONPATH",
                    "PYTHONINSPECT",
                    "DYLD_INSERT_LIBRARIES",
                    "LD_PRELOAD",
                    "NODE_OPTIONS",
                    "NODE_PATH",
                    "BASH_ENV",
                    "ENV",
                    "ZDOTDIR",
                    "PERL5OPT",
                    "RUBYOPT",
                    "AWS_SECRET_ACCESS_KEY",
                    "SSH_AUTH_SOCK",
                ):
                    self.assertNotIn(name, environment)
            rendered_commands = "\n".join(" ".join(command) for command in runner.commands)
            _assert_secret_absent(
                self,
                _CANARY,
                rendered_commands,
                output,
            )

    def test_migrates_key_then_verifies_codex_before_removing_legacy_mcp(self) -> None:
        events: list[tuple[Any, ...]] = []
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(
                directory,
                legacy_config=(
                    "[mcp_servers.remem]\n"
                    'command = "uvx"\n\n'
                    "[mcp_servers.remem.env]\n"
                    f'REMEM_API_KEY = "{_CANARY}"\n'
                ),
            )
            runner = FakeRunner(codex=True, events=events)

            class EventKeychain(FakeKeychain):
                def read(self, service: str, account: str | None = None) -> str | None:
                    events.append(("keychain-read", service, account))
                    return super().read(service, account)

                def write(self, service: str, account: str, value: str) -> None:
                    events.append(("keychain-write", service, account))
                    super().write(service, account, value)

            keychain = EventKeychain()
            result, output = fixture.install(runner=runner, keychain=keychain)

            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(result, 0)
            writes = [
                call for call in keychain.calls if call[0] == "write"
            ]
            self.assertEqual(len(writes), 1)
            self.assertEqual(
                writes[0][:3],
                (
                    "write",
                    install_remem_memory.KEYCHAIN_SERVICE,
                    install_remem_memory.KEYCHAIN_ACCOUNT,
                ),
            )
            self.assertTrue(_same_text(str(writes[0][3]), _CANARY))
            write_index = next(
                index for index, event in enumerate(events) if event[0] == "keychain-write"
            )
            verified_read_index = max(
                index for index, event in enumerate(events) if event[0] == "keychain-read"
            )
            plugin_add_index = events.index(
                (
                    "command",
                    (
                        "codex",
                        "plugin",
                        "add",
                        "remem-memory@remem-memory",
                        "--json",
                    ),
                )
            )
            plugin_lists = [
                index
                for index, event in enumerate(events)
                if event
                == ("command", ("codex", "plugin", "list", "--json"))
            ]
            remove_index = events.index(
                ("command", ("codex", "mcp", "remove", "remem"))
            )
            probe_index = next(
                index
                for index, event in enumerate(events)
                if event[0] == "command" and event[1][-1:] == ("--probe",)
            )
            self.assertLess(write_index, verified_read_index)
            self.assertLess(verified_read_index, plugin_add_index)
            self.assertLess(probe_index, plugin_add_index)
            self.assertLess(plugin_add_index, max(plugin_lists))
            self.assertLess(probe_index, remove_index)
            _assert_secret_absent(
                self,
                _CANARY,
                (fixture.codex_home / "config.toml").read_text(
                    encoding="utf-8"
                ),
                output,
            )

    def test_failed_mcp_runtime_probe_preserves_legacy_codex_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(
                directory,
                legacy_config=(
                    "[mcp_servers.remem]\n"
                    'command = "uvx"\n\n'
                    "[mcp_servers.remem.env]\n"
                    f'REMEM_API_KEY = "{_CANARY}"\n'
                ),
            )
            runner = FakeRunner(
                codex=True,
                mcp_probe_succeeds=False,
            )

            result, output = fixture.install(
                runner=runner,
                keychain=FakeKeychain(),
            )

            self.assertEqual(result, 1)
            self.assertIn(
                "Remem MCP runtime verification failed",
                output,
            )
            self.assertNotIn(
                ("codex", "mcp", "remove", "remem"),
                runner.commands,
            )
            self.assertFalse(
                any(
                    command[:3]
                    == ("codex", "plugin", "add")
                    for command in runner.commands
                )
            )
            self.assertIn(
                "[mcp_servers.remem]",
                (fixture.codex_home / "config.toml").read_text(
                    encoding="utf-8"
                ),
            )
            _assert_secret_absent(self, _CANARY, output)

    def test_unrelated_mcp_key_token_survives_exact_legacy_migration(self) -> None:
        unrelated = (
            "[mcp_servers.remem-maya]\n"
            'command = "uvx"\n'
            'args = ["--env", "REMEM_API_KEY"]\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(
                directory,
                legacy_config=(
                    f"{unrelated}\n"
                    "[mcp_servers.remem]\n"
                    'command = "uvx"\n\n'
                    "[mcp_servers.remem.env]\n"
                    f'REMEM_API_KEY = "{_CANARY}"\n\n'
                    "[unrelated]\n"
                    'value = "preserved"\n'
                ),
            )
            runner = FakeRunner(codex=True)

            result, output = fixture.install(
                runner=runner,
                keychain=FakeKeychain(),
            )

            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(result, 0)
            rendered = (
                fixture.codex_home / "config.toml"
            ).read_text(encoding="utf-8")
            _assert_secret_absent(self, _CANARY, rendered)
            self.assertIn(unrelated.strip(), rendered)
            self.assertIn('[unrelated]\nvalue = "preserved"', rendered)

    def test_equal_existing_key_is_idempotent_but_different_key_fails_closed(self) -> None:
        config = (
            "[mcp_servers.remem]\n"
            'command = "uvx"\n\n'
            "[mcp_servers.remem.env]\n"
            f'REMEM_API_KEY = "{_CANARY}"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory, legacy_config=config)
            runner = FakeRunner(codex=True)
            keychain = FakeKeychain(_CANARY)

            result, output = fixture.install(runner=runner, keychain=keychain)

            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(result, 0)
            self.assertFalse(any(call[0] == "write" for call in keychain.calls))
            self.assertIn(("codex", "mcp", "remove", "remem"), runner.commands)

        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory, legacy_config=config)
            runner = FakeRunner(codex=True)
            keychain = FakeKeychain("vlt_different")

            result, output = fixture.install(runner=runner, keychain=keychain)

            _assert_secret_absent(self, _CANARY, output)
            self.assertEqual(result, 1)
            self.assertTrue(
                _same_text(
                    (fixture.codex_home / "config.toml").read_text(
                        encoding="utf-8"
                    ),
                    config,
                )
            )
            self.assertNotIn(("codex", "mcp", "remove", "remem"), runner.commands)
            self.assertFalse((fixture.repo_root / ".venv").exists())
            self.assertFalse(fixture.home.exists())

    def test_keychain_compare_digest_handles_valid_unicode_basic_strings(self) -> None:
        credential = "vlt_\N{SNOWMAN}"
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(
                directory,
                legacy_config=(
                    "[mcp_servers.remem.env]\n"
                    f'REMEM_API_KEY = "{credential}"\n'
                ),
            )
            runner = FakeRunner(codex=True)

            result, output = fixture.install(
                runner=runner,
                keychain=FakeKeychain(credential),
            )

            _assert_secret_absent(self, credential, output)
            self.assertEqual(result, 0)

    def test_failed_keychain_readback_or_codex_verification_preserves_mcp(self) -> None:
        config = (
            "[mcp_servers.remem]\n"
            'command = "uvx"\n\n'
            "[mcp_servers.remem.env]\n"
            f'REMEM_API_KEY = "{_CANARY}"\n'
        )
        cases = (
            (FakeKeychain(read_after_write="vlt_wrong"), FakeRunner(codex=True)),
            (FakeKeychain(), FakeRunner(codex=True, codex_verifies=False)),
        )
        for keychain, runner in cases:
            with self.subTest(codex_verifies=runner.codex_verifies):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = InstallerFixture(directory, legacy_config=config)

                    result, output = fixture.install(runner=runner, keychain=keychain)

                    _assert_secret_absent(self, _CANARY, output)
                    self.assertEqual(result, 1)
                    self.assertTrue(
                        _same_text(
                            (
                                fixture.codex_home / "config.toml"
                            ).read_text(encoding="utf-8"),
                            config,
                        )
                    )
                    self.assertNotIn(
                        ("codex", "mcp", "remove", "remem"),
                        runner.commands,
                    )

    def test_codex_uses_exact_local_add_or_git_upgrade_then_plugin_add(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            add_runner = FakeRunner(codex=True)

            result, output = fixture.install(runner=add_runner)

            self.assertEqual(result, 0, output)
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "marketplace",
                    "add",
                    str(fixture.repo_root),
                    "--json",
                ),
                add_runner.commands,
            )
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "add",
                    "remem-memory@remem-memory",
                    "--json",
                ),
                add_runner.commands,
            )
            self.assertFalse(
                any(command[:3] == ("codex", "plugin", "install") for command in add_runner.commands)
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            upgrade_runner = FakeRunner(
                codex=True,
                codex_marketplaces=[
                    {
                        "name": "remem-memory",
                        "marketplaceSource": {
                            "sourceType": "git",
                            "source": (
                                "https://github.com/asimgilani/"
                                "remem-memory.git"
                            ),
                        },
                    }
                ],
            )

            result, output = fixture.install(runner=upgrade_runner)

            self.assertEqual(result, 0, output)
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "marketplace",
                    "upgrade",
                    "remem-memory",
                    "--json",
                ),
                upgrade_runner.commands,
            )
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "add",
                    "remem-memory@remem-memory",
                    "--json",
                ),
                upgrade_runner.commands,
            )

    def test_codex_accepts_live_installed_schema_and_nested_git_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = ProductionShapeCodexRunner(
                codex=True,
                codex_marketplaces=[
                    {
                        "name": "remem-memory",
                        "marketplaceSource": {
                            "sourceType": "git",
                            "source": (
                                "https://github.com/asimgilani/"
                                "remem-memory.git"
                            ),
                        },
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "marketplace",
                    "upgrade",
                    "remem-memory",
                    "--json",
                ),
                runner.commands,
            )
            self.assertIn(
                (
                    "codex",
                    "plugin",
                    "add",
                    "remem-memory@remem-memory",
                    "--json",
                ),
                runner.commands,
            )

    def test_claude_verifies_new_plugin_before_old_cleanup_with_exact_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(
                claude=True,
                claude_marketplaces=[{"name": "remem-dev-sessions"}],
                claude_plugins=[
                    {
                        "name": "remem-dev-sessions",
                        "marketplace": "remem-dev-sessions",
                        "version": "0.1.2",
                        "enabled": True,
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            add = (
                "claude",
                "plugin",
                "marketplace",
                "add",
                str(fixture.repo_root),
            )
            install = (
                "claude",
                "plugin",
                "install",
                "remem-memory@remem-memory",
            )
            verify = ("claude", "plugin", "list", "--json")
            disable = (
                "claude",
                "plugin",
                "disable",
                "remem-dev-sessions@remem-dev-sessions",
            )
            uninstall = (
                "claude",
                "plugin",
                "uninstall",
                "remem-dev-sessions@remem-dev-sessions",
                "--keep-data",
            )
            remove_marketplace = (
                "claude",
                "plugin",
                "marketplace",
                "remove",
                "remem-dev-sessions",
            )
            self.assertIn(add, runner.commands)
            self.assertIn(install, runner.commands)
            self.assertGreater(
                max(index for index, command in enumerate(runner.commands) if command == verify),
                runner.commands.index(install),
            )
            self.assertLess(
                max(index for index, command in enumerate(runner.commands) if command == verify),
                runner.commands.index(disable),
            )
            self.assertLess(runner.commands.index(disable), runner.commands.index(uninstall))
            self.assertLess(
                runner.commands.index(uninstall),
                runner.commands.index(remove_marketplace),
            )
            for command in runner.commands:
                if command[:2] == ("claude", "plugin") and "--json" in command:
                    self.assertIn("list", command)

    def test_claude_existing_marketplace_updates_and_plugin_updates_or_enables(self) -> None:
        cases = (
            (
                {
                    "name": "remem-memory",
                    "marketplace": "remem-memory",
                    "version": "0.2.9",
                    "enabled": True,
                },
                (
                    "claude",
                    "plugin",
                    "update",
                    "remem-memory@remem-memory",
                ),
            ),
            (
                {
                    "name": "remem-memory",
                    "marketplace": "remem-memory",
                    "version": "0.3.1",
                    "enabled": False,
                },
                (
                    "claude",
                    "plugin",
                    "enable",
                    "remem-memory@remem-memory",
                ),
            ),
        )
        for plugin, expected_action in cases:
            with self.subTest(action=expected_action), tempfile.TemporaryDirectory() as directory:
                fixture = InstallerFixture(directory)
                runner = FakeRunner(
                    claude=True,
                    claude_marketplaces=[
                        {
                            "name": "remem-memory",
                            "source": "github",
                            "repo": "asimgilani/remem-memory",
                        }
                    ],
                    claude_plugins=[plugin],
                )

                result, output = fixture.install(runner=runner)

                self.assertEqual(result, 0, output)
                self.assertIn(
                    (
                        "claude",
                        "plugin",
                        "marketplace",
                        "update",
                        "remem-memory",
                    ),
                    runner.commands,
                )
                self.assertIn(expected_action, runner.commands)

    def test_codex_rejects_same_named_marketplace_from_another_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(
                codex=True,
                codex_marketplaces=[
                    {
                        "name": "remem-memory",
                        "marketplaceSource": {
                            "sourceType": "git",
                            "source": "https://example.invalid/remem.git",
                        },
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 1)
            self.assertIn("marketplace source", output.lower())
            self.assertFalse(
                any(
                    command[:3] == ("codex", "plugin", "add")
                    or command[:4]
                    == ("codex", "plugin", "marketplace", "upgrade")
                    for command in runner.commands
                )
            )

    def test_claude_rejects_same_named_marketplace_from_another_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(
                claude=True,
                claude_marketplaces=[
                    {
                        "name": "remem-memory",
                        "source": "github",
                        "repo": "someone-else/remem-memory",
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 1)
            self.assertIn("marketplace source", output.lower())
            self.assertFalse(
                any(
                    command[:3]
                    in {
                        ("claude", "plugin", "install"),
                        ("claude", "plugin", "update"),
                        ("claude", "plugin", "enable"),
                    }
                    or command[:4]
                    == ("claude", "plugin", "marketplace", "update")
                    for command in runner.commands
                )
            )

    def test_claude_failed_verification_never_cleans_up_old_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(
                claude=True,
                claude_verifies=False,
                claude_marketplaces=[{"name": "remem-dev-sessions"}],
                claude_plugins=[
                    {
                        "name": "remem-dev-sessions",
                        "marketplace": "remem-dev-sessions",
                        "version": "0.1.2",
                        "enabled": True,
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 1)
            _assert_secret_absent(self, _CANARY, output)
            self.assertFalse(
                any(
                    command[:3]
                    in {
                        ("claude", "plugin", "disable"),
                        ("claude", "plugin", "uninstall"),
                    }
                    for command in runner.commands
                )
            )
            self.assertNotIn(
                (
                    "claude",
                    "plugin",
                    "marketplace",
                    "remove",
                    "remem-dev-sessions",
                ),
                runner.commands,
            )

    def test_failed_mcp_probe_preserves_legacy_claude_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(
                claude=True,
                mcp_probe_succeeds=False,
                claude_marketplaces=[{"name": "remem-dev-sessions"}],
                claude_plugins=[
                    {
                        "name": "remem-dev-sessions",
                        "marketplace": "remem-dev-sessions",
                        "version": "0.1.2",
                        "enabled": True,
                    }
                ],
            )

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 1)
            self.assertIn(
                "Remem MCP runtime verification failed",
                output,
            )
            self.assertFalse(
                any(
                    command[:3]
                    in {
                        ("claude", "plugin", "disable"),
                        ("claude", "plugin", "uninstall"),
                    }
                    for command in runner.commands
                )
            )
            self.assertFalse(
                any(
                    command[:3]
                    in {
                        ("claude", "plugin", "install"),
                        ("claude", "plugin", "update"),
                    }
                    for command in runner.commands
                )
            )
            self.assertNotIn(
                (
                    "claude",
                    "plugin",
                    "marketplace",
                    "remove",
                    "remem-dev-sessions",
                ),
                runner.commands,
            )

    def test_rerun_is_idempotent_and_all_paths_remain_inside_injected_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            runner = FakeRunner(codex=True, claude=True)
            keychain = FakeKeychain()

            first_result, first_output = fixture.install(
                runner=runner,
                keychain=keychain,
            )
            second_result, second_output = fixture.install(
                runner=runner,
                keychain=keychain,
            )

            self.assertEqual(first_result, 0, first_output)
            self.assertEqual(second_result, 0, second_output)
            self.assertFalse(
                any(
                    command[:2] in {("uv", "venv"), ("uv", "pip")}
                    for command in runner.commands
                )
            )
            self.assertEqual(
                runner.commands.count(
                    (
                        "codex",
                        "plugin",
                        "add",
                        "remem-memory@remem-memory",
                        "--json",
                    )
                ),
                1,
            )
            self.assertEqual(
                runner.commands.count(
                    (
                        "claude",
                        "plugin",
                        "install",
                        "remem-memory@remem-memory",
                    )
                ),
                1,
            )
            for alias in install_remem_memory.COMMAND_ALIASES:
                link = fixture.home / ".local" / "bin" / alias
                self.assertEqual(
                    link.resolve(),
                    (fixture.repo_root / "scripts" / "remem_memory.py").resolve(),
                )

    def test_never_writes_plaintext_to_shell_or_metadata_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = InstallerFixture(directory)
            fixture.home.mkdir(parents=True)
            zshrc = fixture.home / ".zshrc"
            zshrc.write_text("# untouched\n", encoding="utf-8")
            config = fixture.codex_home / "config.toml"
            fixture.codex_home.mkdir(parents=True, exist_ok=True)
            config.write_text("# untouched\n", encoding="utf-8")
            runner = FakeRunner(codex=True, claude=True)

            result, output = fixture.install(runner=runner)

            self.assertEqual(result, 0, output)
            self.assertEqual(zshrc.read_text(encoding="utf-8"), "# untouched\n")
            for path in (
                zshrc,
                config,
                fixture.repo_root / ".agents" / "plugins" / "marketplace.json",
                fixture.repo_root
                / "plugins"
                / "remem-memory"
                / ".codex-plugin"
                / "plugin.json",
            ):
                if path.exists():
                    _assert_secret_absent(
                        self,
                        _CANARY,
                        path.read_text(encoding="utf-8"),
                    )


class CompatibilityEntrypointTests(unittest.TestCase):
    def test_legacy_python_module_import_delegates_to_secure_main(self) -> None:
        from scripts import install_codex_mcp

        with mock.patch.object(
            install_codex_mcp,
            "_secure_installer_main",
            return_value=17,
        ) as secure:
            self.assertEqual(install_codex_mcp.main([]), 17)
        secure.assert_called_once_with([])

    def test_legacy_python_entrypoint_rejects_plaintext_flags_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / "codex" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("# untouched\n", encoding="utf-8")
            environment = {
                "HOME": str(base / "home"),
                "CODEX_HOME": str(config.parent),
                "CLAUDE_CONFIG_DIR": str(base / "claude"),
                "PATH": os.environ.get("PATH", ""),
            }

            result = subprocess.run(
                [
                    sys.executable,
                    str(_LIVE_ROOT / "scripts" / "install_codex_mcp.py"),
                    "--api-key",
                    _CANARY,
                ],
                cwd=_LIVE_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            _assert_secret_absent(
                self,
                _CANARY,
                result.stdout,
                result.stderr,
            )
            self.assertEqual(config.read_text(encoding="utf-8"), "# untouched\n")

    def test_shell_entrypoint_only_delegates_to_secure_installer(self) -> None:
        shell = (_LIVE_ROOT / "install-codex-skill.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/install_remem_memory.py", shell)
        self.assertRegex(shell, r'exec python3 -I ')
        self.assertNotIn("install_codex_mcp.py", shell)
        self.assertNotIn("REMEM_API_KEY", shell)
        self.assertNotIn("config.toml", shell)

    def test_installer_remains_python_310_compatible_without_tomllib(self) -> None:
        source = (
            _LIVE_ROOT / "scripts" / "install_remem_memory.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("tomllib", source)
        spec = importlib.util.spec_from_file_location(
            "installer_compile_check",
            _LIVE_ROOT / "scripts" / "install_remem_memory.py",
        )
        self.assertIsNotNone(spec)

    def test_repository_helpers_have_no_third_party_dependency_manifest(
        self,
    ) -> None:
        self.assertFalse((_LIVE_ROOT / "requirements.txt").exists())
        for name in (
            "remem_checkpoint.py",
            "remem_recall.py",
            "remem_rollup.py",
        ):
            source = (
                _LIVE_ROOT / "scripts" / name
            ).read_text(encoding="utf-8")
            self.assertNotIn("import httpx", source)


if __name__ == "__main__":
    unittest.main()
