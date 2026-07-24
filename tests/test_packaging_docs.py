from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXACT_RAW_INSTALL_URL = (
    "https://raw.githubusercontent.com/asimgilani/remem-memory/"
    "refs/heads/master/.codex/INSTALL.md"
)
UPSTREAM_PROVENANCE_COMMIT = (
    "759a57af927908315a3a4f6e4c73a935faf8d56f"
)
PUBLIC_DOC_PATHS = (
    "README.md",
    ".codex/INSTALL.md",
    "docs/README.codex.md",
    "docs/SECURITY.md",
)
CANONICAL_SKILL_PATHS = (
    "plugins/remem-memory/skills/remem-memory/SKILL.md",
    "codex/skills/remem-memory/SKILL.md",
)
LEGACY_SKILL_PATHS = (
    "plugins/remem-memory/skills/session-memory/SKILL.md",
    "codex/skills/remem-dev-sessions/SKILL.md",
    "codex/skills/remem-session-memory/SKILL.md",
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def read_public_docs() -> str:
    return "\n".join(read(path) for path in PUBLIC_DOC_PATHS)


def parse_frontmatter(path: str) -> dict[str, str]:
    content = read(path)
    match = re.match(r"\A---\n(.*?)\n---\n", content, flags=re.DOTALL)
    if match is None:
        raise AssertionError(f"{path} has no YAML frontmatter")
    parsed: dict[str, str] = {}
    for line in match.group(1).splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            raise AssertionError(f"{path} has malformed frontmatter")
        parsed[key.strip()] = value.strip().strip("\"'")
    return parsed


class PackagingDocsTests(unittest.TestCase):
    def test_readme_puts_complete_activation_path_after_quick_install(
        self,
    ) -> None:
        readme = read("README.md")
        quick = readme.index("## Quick install")
        activation = readme.index("## Finish activation")
        requirements = readme.index("## Requirements")

        self.assertLess(quick, activation)
        self.assertLess(activation, requirements)
        self.assertIn("Codex or Claude Code", readme[quick:activation])
        self.assertIn("https://app.remem.io", readme[activation:requirements])
        self.assertIn(
            "env -u REMEM_API_KEY ~/.local/bin/remem-memory status",
            readme[activation:requirements],
        )
        self.assertIn(
            "~/.local/bin/remem-memory auth",
            readme[activation:requirements],
        )

    def test_activation_docs_distinguish_codex_and_claude_surfaces(
        self,
    ) -> None:
        readme = read("README.md")
        install = read(".codex/INSTALL.md")
        codex = read("docs/README.codex.md")

        for document_name, document in (
            ("README.md", readme),
            (".codex/INSTALL.md", install),
        ):
            self.assertIn("Codex Desktop", document, document_name)
            self.assertIn("Plugins", document, document_name)
            self.assertIn("Remem Memory", document, document_name)
            self.assertIn("Review", document, document_name)
            self.assertIn("five hooks", document, document_name)
            self.assertIn("Codex CLI", document, document_name)
            self.assertIn("/hooks", document, document_name)
            self.assertIn("Claude Code", document, document_name)
            self.assertIn("/reload-plugins", document, document_name)
            self.assertIn("read-only", document.lower(), document_name)

        for label in ("Codex Desktop", "Codex CLI"):
            self.assertIn(label, codex)
        self.assertIn("/hooks", codex)
        self.assertIn("exact hook hash", codex.lower())
        self.assertIn("local", codex.lower())

        readme_desktop = readme.split("| Codex Desktop |", 1)[1].split(
            "\n",
            1,
        )[0]
        codex_desktop = codex.split("- **Codex Desktop:**", 1)[1].split(
            "- **Codex CLI:**",
            1,
        )[0]
        for document_name, desktop_route in (
            ("README.md", readme_desktop),
            ("docs/README.codex.md", codex_desktop),
        ):
            normalized_route = " ".join(desktop_route.lower().split())
            self.assertIn("restart codex desktop", normalized_route, document_name)
            self.assertLess(
                normalized_route.index("restart codex desktop"),
                normalized_route.index("plugins"),
                document_name,
            )

    def test_activation_docs_define_expected_state_and_common_recovery(
        self,
    ) -> None:
        readme = read("README.md")
        activation = readme.split("## Finish activation", 1)[1].split(
            "## Requirements",
            1,
        )[0]
        normalized = " ".join(activation.lower().split())

        self.assertIn(
            (
                "canonical status command above reports the intended mode "
                "and sensitivity plus `credential: configured`"
            ),
            normalized,
        )
        self.assertIn("enabled at version `0.3.2`", normalized)
        self.assertIn("if codex is installed", normalized)
        self.assertIn("all five remem memory hooks trusted", normalized)
        self.assertIn(
            "fresh supported-client session can use automatic memory",
            normalized,
        )
        self.assertIn("keychain", normalized)
        self.assertIn("rerun the installer", normalized)
        self.assertIn("reload-plugins", normalized)

    def test_docs_use_one_product_name_and_keep_install_url(self) -> None:
        readme = read("README.md")
        install = read(".codex/INSTALL.md")

        self.assertTrue(readme.startswith("# Remem Memory\n"))
        self.assertIn(
            "Automatic personal and engineering memory for Claude Code and Codex.",
            readme,
        )
        self.assertIn(EXACT_RAW_INSTALL_URL, readme)
        self.assertIn("remem-memory", install)
        self.assertNotIn("vlt_your_key_here", install)

    def test_legacy_names_only_appear_in_transition_or_alias_sections(
        self,
    ) -> None:
        readme = read("README.md")
        before_transition, transition = readme.split(
            "## Updating from remem-dev-sessions",
            maxsplit=1,
        )

        self.assertNotIn("remem-dev-sessions", before_transition)
        self.assertIn("remem-dev-sessions", transition)

    def test_docs_state_supported_surfaces_without_overclaiming(self) -> None:
        docs = read_public_docs()
        lowered = docs.lower()

        self.assertIn("Codex Remote", docs)
        self.assertIn("Mac host", docs)
        self.assertIn("ordinary ChatGPT mobile", docs)
        self.assertIn("Codex Cloud", docs)
        self.assertIn("IDE extension", docs)
        self.assertIn("different SSH", docs)
        self.assertNotIn(
            "ordinary ChatGPT mobile chats automatically",
            docs,
        )
        self.assertNotIn("modify the Remem portal", docs)
        self.assertIn("no local web server", lowered)
        self.assertIn("no setup wizard", lowered)
        self.assertIn("no daemon", lowered)
        self.assertIn("stdio", lowered)

    def test_codex_docs_require_exact_hook_review_and_re_review(self) -> None:
        for path in ("README.md", ".codex/INSTALL.md"):
            docs = read(path)
            lowered = docs.lower()
            normalized = " ".join(lowered.split())

            self.assertIn("/hooks", docs, path)
            self.assertIn("exact hook hash", lowered, path)
            self.assertIn(
                "codex skips those hooks until they are trusted",
                normalized,
                path,
            )
            self.assertIn(
                "automatic recall, durable capture",
                normalized,
                path,
            )
            self.assertIn(
                (
                    "mcp tools, skills, and manual cli commands can still "
                    "work before hook trust"
                ),
                normalized,
                path,
            )
            self.assertRegex(
                normalized,
                r"(new|changed).{0,80}hook.{0,80}re-review",
                path,
            )

    def test_docs_define_secure_cli_install_and_update_contract(self) -> None:
        docs = read_public_docs()
        lowered = docs.lower()

        for phrase in (
            "macos keychain",
            "io.remem.memory",
            "remem-memory auth",
            "remem-memory status",
            "remem-memory mode",
            "remem-memory sensitivity",
            "uv",
            "standard library",
            "git pull --ff-only",
            "clean checkout",
            "remem_default_namespace",
            "remem_memory_personal_namespace",
            "remem_memory_engineering_namespace",
            "remem_memory_project",
            "remem_memory_interval_seconds",
            "remem_memory_min_events",
            "remem_memory_rollup_on_session_end",
            "remem_memory_summary_enabled",
        ):
            self.assertIn(phrase, lowered)
        self.assertIn("REMEM_API_KEY", docs)
        self.assertIn("override", lowered)
        self.assertIn("unset", lowered)
        self.assertIn("rollback", lowered)

    def test_behavior_docs_classify_all_mcp_reads_and_writes(self) -> None:
        for path in (
            "README.md",
            "docs/README.codex.md",
            "docs/SECURITY.md",
        ):
            normalized = " ".join(read(path).lower().split())

            self.assertIn("read-only mcp tools", normalized, path)
            self.assertIn("write mcp tools", normalized, path)
            self.assertIn("remem_extract_facts", normalized, path)
            self.assertNotRegex(
                normalized,
                r"recall-only.{0,100}only `remem_query`",
                path,
            )

    def test_docs_distinguish_wrapper_controls_from_explicit_helpers(
        self,
    ) -> None:
        readme = " ".join(read("README.md").lower().split())
        codex_docs = " ".join(
            read("docs/README.codex.md").lower().split()
        )

        for docs in (readme, codex_docs):
            self.assertIn(
                "mechanically rechecks the persisted mode before every "
                "checkpoint and final rollup",
                docs,
            )
            self.assertIn("off-record marker", docs)
            self.assertIn("deterministic checkpoints can resume", docs)

        helper_section = readme.split(
            "the optional `remem-memory codex` launcher",
            maxsplit=1,
        )[0]
        self.assertIn("checkpoint, rollup, and recall helpers", helper_section)
        self.assertNotIn("remem-memory codex --help", helper_section)

    def test_docs_describe_the_bundled_locked_mcp_boundary(self) -> None:
        docs = read_public_docs()
        lowered = docs.lower()
        normalized = " ".join(docs.split())

        for phrase in (
            "plugins/remem-memory/mcp",
            "audited",
            "bundled",
            "uv.lock",
            "httpx==0.28.1",
            "mcp==1.26.0",
            "locked pypi artifacts",
            "dummy credential",
            "anonymous file descriptor",
            "direct cached python",
            "--no-editable",
            "--no-install-project",
            "redirects",
            "proxies",
        ):
            self.assertIn(phrase, lowered)
        self.assertIn(UPSTREAM_PROVENANCE_COMMIT, docs)
        self.assertIn(
            "real api key reaches only the direct cached python",
            normalized.lower(),
        )
        self.assertNotIn("uvx", lowered)
        self.assertNotIn(
            "git+https://github.com/asimgilani/remem.git",
            lowered,
        )

    def test_command_path_fallback_does_not_mutate_shell_startup(
        self,
    ) -> None:
        docs = read_public_docs()
        install = read(".codex/INSTALL.md")
        lowered = docs.lower()

        self.assertIn("command -v remem-memory", docs)
        self.assertIn("~/.local/bin/remem-memory", docs)
        self.assertIn("Change into the selected checkout", install)
        self.assertIn(
            "env -u REMEM_API_KEY ~/.local/bin/remem-memory status",
            install,
        )
        self.assertNotIn("export path=", lowered)

    def test_docs_remove_insecure_or_obsolete_setup_paths(self) -> None:
        docs = read_public_docs()
        lowered = docs.lower()

        for obsolete in (
            "vlt_your_key_here",
            "pip install",
            "@master#subdirectory=packages/remem-mcp",
            "git+https://github.com/asimgilani/remem.git",
            "echo 'export remem_api_key",
            ">> ~/.zshrc",
            'command = "uvx"',
            "uvx",
        ):
            self.assertNotIn(obsolete, lowered)
        self.assertNotIn("rm -rf", lowered)
        self.assertNotIn("git reset --hard", lowered)

    def test_docs_define_transition_without_data_or_service_migration(
        self,
    ) -> None:
        docs = read_public_docs()
        lowered = docs.lower()

        self.assertIn("no remem data", lowered)
        self.assertIn("no remem api", lowered)
        self.assertIn("no remem portal", lowered)
        self.assertIn("legacy codex", lowered)
        self.assertIn("verified", lowered)
        self.assertIn("after", lowered)

    def test_rollback_is_a_safe_pause_without_false_downgrade_claims(self) -> None:
        docs = read_public_docs()
        lowered = " ".join(docs.lower().split())

        self.assertIn("verified rollback boundary", lowered)
        self.assertIn("version downgrade is intentionally not automated", lowered)
        self.assertIn("canonical git marketplace", lowered)
        self.assertIn("tested exact-source procedure", lowered)
        self.assertIn("remem_memory_auto_enabled=0", lowered)
        self.assertIn("old codex mcp", lowered)
        self.assertIn("aliases", lowered)
        self.assertNotIn(
            "run that checkout's installer",
            lowered,
        )
        self.assertNotIn(
            "claude plugin install remem-dev-sessions@remem-dev-sessions",
            lowered,
        )

    def test_canonical_skill_covers_memory_and_engineering_contract(
        self,
    ) -> None:
        for path in CANONICAL_SKILL_PATHS:
            skill = read(path).lower()
            normalized_skill = " ".join(skill.split())
            for phrase in (
                "automatic recall",
                "durable capture",
                "off the record",
                "engineering checkpoint",
                "untrusted",
                "recall-only",
                "remem_query",
                "remem_ingest",
                "remem_extract_facts",
                "read-only mcp tools",
                "write mcp tools",
            ):
                self.assertIn(phrase, skill, path)
            self.assertRegex(
                skill,
                r"(do not|don't|never).{0,120}duplicat",
                path,
            )
            self.assertIn("command -v remem-memory", skill, path)
            self.assertIn("~/.local/bin/remem-memory", skill, path)
            self.assertIn("before any explicit mcp call", skill, path)
            self.assertIn("run `remem-memory status`", skill, path)
            self.assertIn(
                "before running any `remem-memory` command",
                normalized_skill,
                path,
            )
            self.assertNotIn(
                "permit only `remem_query`",
                normalized_skill,
                path,
            )
            self.assertRegex(
                normalized_skill,
                (
                    r"write mcp tools.{0,160}"
                    r"(explicitly requests|explicit user)"
                ),
                path,
            )

    def test_skill_identity_and_legacy_alias_contracts(self) -> None:
        for path in CANONICAL_SKILL_PATHS:
            parsed = parse_frontmatter(path)
            self.assertEqual(Path(path).parent.name, "remem-memory")
            self.assertEqual(parsed["name"], "remem-memory")
            self.assertTrue(parsed["description"].startswith("Use when"))
        for path in LEGACY_SKILL_PATHS:
            content = read(path)
            parsed = parse_frontmatter(path)
            self.assertTrue(parsed["description"].startswith("Use when"))
            self.assertIn("canonical", content.lower())
            self.assertIn("remem-memory", content)
            self.assertLessEqual(len(content.splitlines()), 24, path)

    def test_plugin_descriptions_cover_personal_and_engineering_memory(
        self,
    ) -> None:
        for path in (
            "plugins/remem-memory/.codex-plugin/plugin.json",
            "plugins/remem-memory/.claude-plugin/plugin.json",
        ):
            manifest = json.loads(read(path))
            description = manifest["description"].lower()
            self.assertIn("personal", description, path)
            self.assertIn("engineering", description, path)
            self.assertEqual(manifest["name"], "remem-memory")
            self.assertEqual(manifest["version"], "0.3.2")

    def test_security_doc_covers_full_boundary(self) -> None:
        security = read("docs/SECURITY.md").lower()
        normalized = " ".join(security.split())
        for phrase in (
            "data sent to remem",
            "bounded",
            "untrusted",
            "secret filtering",
            "local state",
            ".remem",
            "summary provider",
            "keychain",
            "environment variable",
            "at-rest configuration",
            "fully compromised same-user host",
            "user-authorized process",
            "cannot promise secrecy against arbitrary local code",
            "credential-bearing http proxy and ca boundary",
            "https_proxy",
            "ssl_cert_file",
            "outside the remem transport trust boundary",
            "bundled mcp execution",
            "anonymous file descriptor",
            "dummy credential",
            "direct cached python",
            "trust_env=false",
            "fail open",
            "rollback",
            "no remem data",
            "no remem portal",
            "no remem api",
        ):
            self.assertIn(phrase, normalized)

    def test_mcp_runtime_has_no_plugin_default_namespace_override(self) -> None:
        for path in (
            "plugins/remem-memory/.mcp.json",
            "plugins/remem-memory/scripts/remem_mcp_launcher.py",
            "plugins/remem-memory/mcp/remem_mcp/server.py",
        ):
            self.assertNotIn("REMEM_DEFAULT_NAMESPACE", read(path), path)


if __name__ == "__main__":
    unittest.main()
