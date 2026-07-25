import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_VERSION = "0.4.0"


def load_json(relative_path: str):
    return json.loads((_ROOT / relative_path).read_text(encoding="utf-8"))


def iter_hook_commands(hooks):
    for event, configurations in hooks.items():
        for configuration_index, configuration in enumerate(configurations):
            for hook_index, hook in enumerate(configuration["hooks"]):
                yield event, configuration_index, hook_index, hook["command"]


class PluginContractTests(unittest.TestCase):
    def test_marketplaces_and_manifests_share_one_identity(self):
        claude_market = load_json(".claude-plugin/marketplace.json")
        codex_market = load_json(".agents/plugins/marketplace.json")
        claude_plugin = load_json(
            "plugins/remem-memory/.claude-plugin/plugin.json"
        )
        codex_plugin = load_json(
            "plugins/remem-memory/.codex-plugin/plugin.json"
        )
        self.assertEqual(claude_market["name"], "remem-memory")
        self.assertEqual(codex_market["name"], "remem-memory")
        self.assertEqual(claude_market["plugins"][0]["name"], "remem-memory")
        self.assertEqual(codex_market["plugins"][0]["name"], "remem-memory")
        self.assertEqual(
            claude_market["plugins"][0]["version"],
            _RELEASE_VERSION,
        )
        self.assertEqual(claude_plugin["name"], "remem-memory")
        self.assertEqual(codex_plugin["name"], "remem-memory")
        self.assertEqual(claude_plugin["version"], _RELEASE_VERSION)
        self.assertEqual(codex_plugin["version"], _RELEASE_VERSION)

    def test_codex_manifest_uses_default_hook_discovery(self):
        manifest = load_json(
            "plugins/remem-memory/.codex-plugin/plugin.json"
        )
        self.assertEqual(manifest["skills"], "./skills/")
        self.assertEqual(manifest["mcpServers"], "./.mcp.json")
        self.assertNotIn("hooks", manifest)
        self.assertTrue(
            (_ROOT / "plugins/remem-memory/hooks/hooks.json").is_file()
        )

    def test_shared_hooks_cover_recall_memory_and_sessions(self):
        hooks = load_json("plugins/remem-memory/hooks/hooks.json")["hooks"]
        expected_modes = {
            "UserPromptSubmit": "user_prompt_submit",
            "PostToolUse": "post_tool_use",
            "Stop": "stop",
            "PreCompact": "pre_compact",
            "SessionEnd": "session_end",
        }

        self.assertEqual(set(hooks), set(expected_modes))
        self.assertEqual(
            hooks["PostToolUse"][0]["matcher"],
            "Write|Edit|MultiEdit|Bash|apply_patch",
        )
        for event, mode in expected_modes.items():
            with self.subTest(event=event):
                configured = hooks[event][0]["hooks"]
                self.assertEqual(len(configured), 1)
                command = configured[0]["command"]
                self.assertIn("remem_memory_hook.py", command)
                self.assertIn("${CLAUDE_PLUGIN_ROOT}", command)
                self.assertIn(f"--mode {mode}", command)
                self.assertIn("--harness", command)

        serialized = json.dumps(hooks)
        self.assertNotIn('"async"', serialized)
        self.assertLessEqual(
            hooks["SessionEnd"][0]["hooks"][0]["timeout"],
            3,
        )
        self.assertNotIn('"TaskCompleted"', serialized)

    def test_every_hook_command_uses_an_isolated_local_import_bootstrap(self):
        hooks = load_json("plugins/remem-memory/hooks/hooks.json")["hooks"]

        for event, configuration_index, hook_index, command in iter_hook_commands(
            hooks
        ):
            with self.subTest(
                event=event,
                configuration=configuration_index,
                hook=hook_index,
            ):
                arguments = shlex.split(command)

                self.assertEqual(arguments[0:3], ["python3", "-I", "-c"])
                self.assertIn("sys.path.insert(0,scripts)", arguments[3])
                self.assertIn("runpy.run_path(entry,run_name=", arguments[3])
                self.assertEqual(arguments[4], "${CLAUDE_PLUGIN_ROOT}")

    def test_every_hook_command_ignores_python_environment_and_loads_its_plugin(
        self,
    ):
        hooks = load_json("plugins/remem-memory/hooks/hooks.json")["hooks"]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_root = root / "trusted plugin"
            scripts = plugin_root / "scripts"
            scripts.mkdir(parents=True)
            poisoned = root / "poisoned"
            poisoned.mkdir()
            (poisoned / "hook_probe.py").write_text(
                "ORIGIN = 'poisoned'\n",
                encoding="utf-8",
            )
            (scripts / "hook_probe.py").write_text(
                "ORIGIN = 'plugin'\n",
                encoding="utf-8",
            )
            (scripts / "remem_memory_hook.py").write_text(
                (
                    "import json, sys\n"
                    "from hook_probe import ORIGIN\n"
                    "print(json.dumps({'origin': ORIGIN, 'argv': sys.argv[1:]}))\n"
                ),
                encoding="utf-8",
            )

            for event, configuration_index, hook_index, command in (
                iter_hook_commands(hooks)
            ):
                for harness in ("claude", "codex"):
                    with self.subTest(
                        event=event,
                        configuration=configuration_index,
                        hook=hook_index,
                        harness=harness,
                    ):
                        environment = os.environ.copy()
                        environment["PYTHONPATH"] = str(poisoned)
                        environment["PYTHONHOME"] = str(poisoned)
                        if harness == "claude":
                            environment["CLAUDE_PLUGIN_ROOT"] = str(plugin_root)
                            environment.pop("PLUGIN_ROOT", None)
                        else:
                            environment["CLAUDE_PLUGIN_ROOT"] = (
                                "${CLAUDE_PLUGIN_ROOT}"
                            )
                            environment["PLUGIN_ROOT"] = str(plugin_root)

                        completed = subprocess.run(
                            command,
                            cwd=plugin_root,
                            env=environment,
                            shell=True,
                            executable="/bin/sh",
                            check=False,
                            capture_output=True,
                            text=True,
                        )

                        self.assertEqual(
                            completed.returncode,
                            0,
                            completed.stderr,
                        )
                        observed = json.loads(completed.stdout)
                        self.assertEqual(observed["origin"], "plugin")
                        self.assertEqual(observed["argv"][0], "--mode")
                        self.assertEqual(observed["argv"][-2:], [
                            "--harness",
                            harness,
                        ])

    def test_valid_unresolved_root_tokens_select_codex_before_fallback(self):
        hooks = load_json("plugins/remem-memory/hooks/hooks.json")["hooks"]
        command = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]
        base_arguments = shlex.split(command)

        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory) / "plugin"
            scripts = plugin_root / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "remem_memory_hook.py").write_text(
                (
                    "import json,sys\n"
                    "print(json.dumps({'argv': sys.argv[1:]}))\n"
                ),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.pop("CLAUDE_PLUGIN_ROOT", None)
            environment["PLUGIN_ROOT"] = str(plugin_root)

            for token in ("${CLAUDE_PLUGIN_ROOT}", "$UNRESOLVED_ROOT"):
                with self.subTest(token=token):
                    arguments = list(base_arguments)
                    arguments[4] = token
                    completed = subprocess.run(
                        arguments,
                        cwd=plugin_root,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(
                        completed.returncode,
                        0,
                        completed.stderr,
                    )
                    observed = json.loads(completed.stdout)
                    self.assertEqual(
                        observed["argv"][-2:],
                        ["--harness", "codex"],
                    )

    def test_hook_bootstrap_rejects_empty_relative_and_malformed_roots(self):
        hooks = load_json("plugins/remem-memory/hooks/hooks.json")["hooks"]
        command = hooks["UserPromptSubmit"][0]["hooks"][0]["command"]
        base_arguments = shlex.split(command)

        for token in (
            "",
            ".",
            "relative/root",
            "$",
            "$9BROKEN",
            "${BROKEN",
            "prefix$BROKEN",
        ):
            with self.subTest(token=token):
                arguments = list(base_arguments)
                arguments[4] = token
                environment = os.environ.copy()
                environment["PLUGIN_ROOT"] = (
                    "/tmp/vlt_secret-plugin-root-canary"
                )

                completed = subprocess.run(
                    arguments,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(
                    completed.stderr.strip(),
                    "invalid plugin root",
                )
                self.assertNotIn("secret", completed.stderr)

    def test_mcp_bootstrap_uses_original_root_token_for_client_identity(self):
        server = load_json(
            "plugins/remem-memory/.mcp.json"
        )["mcpServers"]["remem"]
        bootstrap = server["args"][2]
        with tempfile.TemporaryDirectory() as directory:
            plugin_root = Path(directory) / "plugin"
            scripts = plugin_root / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "remem_mcp_launcher.py").write_text(
                (
                    "import json,sys\n"
                    "print(json.dumps({'argv': sys.argv[1:]}))\n"
                ),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PLUGIN_ROOT"] = str(plugin_root)
            cases = (
                (str(plugin_root), "claude"),
                ("${CLAUDE_PLUGIN_ROOT}", "codex"),
                ("$UNRESOLVED_ROOT", "codex"),
            )
            for token, expected in cases:
                with self.subTest(token=token):
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            bootstrap,
                            token,
                        ],
                        cwd=plugin_root,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(
                        json.loads(completed.stdout)["argv"],
                        ["--client", expected],
                    )

            malformed = subprocess.run(
                [sys.executable, "-I", "-c", bootstrap, "$"],
                cwd=plugin_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertEqual(malformed.stderr.strip(), "invalid plugin root")
            missing = subprocess.run(
                [sys.executable, "-I", "-c", bootstrap],
                cwd=plugin_root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(missing.stderr.strip(), "invalid plugin root")


if __name__ == "__main__":
    unittest.main()
