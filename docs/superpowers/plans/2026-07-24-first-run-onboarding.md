# Remem Memory First-Run Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release Remem Memory 0.3.2 with a novice-safe install and activation path for Codex Desktop, Codex CLI, and Claude Code.

**Architecture:** Keep the existing single plugin and secure installer. Add per-client installation results to the installer so its successful output can show only relevant activation guidance, reject a host with no supported client before mutation, and make the three public onboarding documents agree. Preserve Keychain, explicit Codex hook trust, Claude's normal plugin loading, and every existing memory behavior.

**Tech Stack:** Python 3.10+ standard library, `unittest`, Markdown, JSON plugin manifests, Codex and Claude Code plugin CLIs.

## Global Constraints

- Target release version is `0.3.2`.
- No Remem API, portal, data, account, namespace, memory-policy, wizard, server, daemon, profile, persona, or Maya-specific change.
- Never accept, print, persist, or transport an API key through chat, command arguments, plugin manifests, or shell startup files.
- Canonical credential verification is `env -u REMEM_API_KEY ~/.local/bin/remem-memory status`.
- Codex hook trust remains local, explicit, and hash-bound; the installer may not approve or bypass it.
- Claude Code may reload with `/reload-plugins` or a restarted session and has no Codex-style hook approval gate.
- Existing compatibility aliases and Claude engineering-memory behavior remain unchanged.
- Use test-driven development: add each failing regression test, observe the expected failure, then write the minimum production change.

---

### Task 1: Public first-run documentation

**Files:**
- Modify: `tests/test_packaging_docs.py`
- Modify: `README.md`
- Modify: `.codex/INSTALL.md`
- Modify: `docs/README.codex.md`

**Interfaces:**
- Consumes: Existing raw agent-install URL and current hook-security wording.
- Produces: A `## Finish activation` README section, explicit per-surface activation copy, and matching agent/Codex guides.

- [ ] **Step 1: Add failing per-document onboarding tests**

Add these methods to `PackagingDocsTests`:

```python
def test_readme_puts_complete_activation_path_after_quick_install(self) -> None:
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

def test_activation_docs_distinguish_codex_and_claude_surfaces(self) -> None:
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

def test_activation_docs_define_expected_state_and_common_recovery(self) -> None:
    readme = read("README.md")
    activation = readme.split("## Finish activation", 1)[1].split(
        "## Requirements",
        1,
    )[0]
    normalized = " ".join(activation.lower().split())

    self.assertIn("credential: configured", normalized)
    self.assertIn("enabled at version", normalized)
    self.assertIn("all five", normalized)
    self.assertIn("keychain", normalized)
    self.assertIn("rerun the installer", normalized)
    self.assertIn("reload-plugins", normalized)
```

- [ ] **Step 2: Run the new documentation tests and verify RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_packaging_docs.PackagingDocsTests.test_readme_puts_complete_activation_path_after_quick_install \
  tests.test_packaging_docs.PackagingDocsTests.test_activation_docs_distinguish_codex_and_claude_surfaces \
  tests.test_packaging_docs.PackagingDocsTests.test_activation_docs_define_expected_state_and_common_recovery \
  -v
```

Expected: all three tests fail because `## Finish activation`, the explicit Desktop/CLI routes, and the recovery checklist do not exist.

- [ ] **Step 3: Implement the README first-run flow**

Change the Quick install introduction to:

```markdown
Ask Codex or Claude Code on the target Mac:
```

Immediately after the agent-install prompt, add:

```markdown
## Finish activation

The installer safely installs and verifies the plugin. Complete these local
activation steps:

1. Check the canonical Keychain credential:

   ```bash
   env -u REMEM_API_KEY ~/.local/bin/remem-memory status
   ```

   If it reports `credential: missing`, get a least-privilege API key from your
   [Remem account](https://app.remem.io), then enter it only in the hidden
   prompt:

   ```bash
   ~/.local/bin/remem-memory auth
   ```

   Never paste the key into chat, a command argument, or a configuration file.
2. Finish activation for each installed client:

| Surface | What to do |
| --- | --- |
| Codex Desktop | Open **Plugins → Remem Memory → Hooks**, choose **Review**, inspect the five hooks, then trust them. |
| Codex CLI | Start interactive Codex, enter `/hooks`, select **Remem Memory**, inspect the five hooks, then approve them. |
| Claude Code | Run `/reload-plugins`, or restart Claude Code and begin a new session. Claude has no separate Codex-style hook approval; its `/hooks` view is read-only and can verify that the plugin hooks loaded. |

Codex approval is local to that installation/configuration and bound to the
exact hook hash. Review again on a new Mac/configuration or after hook content
changes.

Setup is active when Keychain status says `credential: configured`, every
installed client reports Remem Memory enabled at version `0.3.2`, and Codex
shows all five Remem Memory hooks trusted.

If activation does not work:

- Missing credential: run the hidden `auth` prompt above.
- Plugin not listed: update a clean checkout and rerun the installer.
- Codex automation absent: review its local hook trust.
- Claude still shows old plugin state: run `/reload-plugins` or restart it.
```

Remove the later duplicate generic hook paragraph from Manual setup and replace
it with one sentence pointing back to `Finish activation`. Keep the existing
detailed Keychain, MCP, and hook-security explanations.

- [ ] **Step 4: Implement matching agent and Codex guide instructions**

In `.codex/INSTALL.md`, keep the existing verification commands, then replace
the generic Codex paragraph with labeled `Codex Desktop`, `Codex CLI`, and
`Claude Code` activation bullets using the same actions as the README. State
that the agent may verify plugin state but may not approve Codex hooks for the
user. State that Claude's `/hooks` view is read-only.

In `docs/README.codex.md`, replace the generic `/hooks` paragraph with two
labeled routes:

```markdown
- **Codex Desktop:** open **Plugins → Remem Memory → Hooks**, choose
  **Review**, inspect the five hooks, and trust them.
- **Codex CLI:** start interactive Codex, enter `/hooks`, select
  **Remem Memory**, inspect the five hooks, and approve them.
```

Follow with the existing skipped-until-trusted behavior and state that approval
is local and bound to the exact hook hash.

- [ ] **Step 5: Run documentation tests and verify GREEN**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_packaging_docs -v
```

Expected: every packaging documentation test passes.

- [ ] **Step 6: Commit the documentation slice**

```bash
git add README.md .codex/INSTALL.md docs/README.codex.md tests/test_packaging_docs.py
git commit -m "docs: make first-run activation explicit"
```

---

### Task 2: Safe installer completion and client preflight

**Files:**
- Modify: `tests/test_installer.py`
- Modify: `scripts/install_remem_memory.py`

**Interfaces:**
- Consumes: `Installer._tool_available(command: str) -> bool`.
- Produces: `_InstalledClients(codex: bool, claude: bool)`,
  `Installer.run() -> _InstalledClients`, and client-specific success output.

- [ ] **Step 1: Add failing tests for a host with no supported client**

Add:

```python
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
```

Change the three existing successful `FakeRunner()` fixtures at the alias,
existing-environment, and Unicode-Keychain tests to `FakeRunner(codex=True)`.

- [ ] **Step 2: Run the no-client test and verify RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_installer.SecureInstallerTests.test_no_supported_client_fails_before_any_mutation \
  -v
```

Expected: FAIL because the current installer returns success and creates
aliases with no supported client.

- [ ] **Step 3: Add failing client-specific completion-output tests**

Add:

```python
def test_success_output_matches_verified_clients(self) -> None:
    cases = (
        (True, False, ("Codex Desktop", "Codex CLI"), ("Claude Code:",)),
        (False, True, ("Claude Code:", "/reload-plugins"), ("Codex Desktop", "Codex CLI")),
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
```

- [ ] **Step 4: Run the output test and verify RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_installer.SecureInstallerTests.test_success_output_matches_verified_clients \
  -v
```

Expected: FAIL because the current output is only
`Remem Memory setup complete.`.

- [ ] **Step 5: Implement detected-client return state and preflight**

Add beside `_LegacyConfig`:

```python
@dataclass(frozen=True)
class _InstalledClients:
    codex: bool
    claude: bool
```

Change `Installer.run` to return `_InstalledClients`. After repository
validation and client detection, before any legacy credential bridge or
filesystem mutation, add:

```python
if not codex_available and not claude_available:
    raise InstallerError(
        "install Codex or Claude Code first"
    )
```

After verified cleanup, return:

```python
return _InstalledClients(
    codex=codex_ready,
    claude=claude_available,
)
```

- [ ] **Step 6: Implement secure client-specific completion output**

Add a pure renderer:

```python
def _activation_guidance(installed: _InstalledClients) -> str:
    lines = [
        "Remem Memory installed successfully.",
        "",
        "Finish activation:",
        (
            "1. Verify Keychain: env -u REMEM_API_KEY "
            "~/.local/bin/remem-memory status"
        ),
        (
            "   If credential is missing: "
            "~/.local/bin/remem-memory auth"
        ),
        "2. Reload or restart each installed client:",
    ]
    if installed.codex:
        lines.extend(
            (
                (
                    "   Codex Desktop: Plugins -> Remem Memory -> Hooks -> "
                    "Review; inspect and trust all five hooks."
                ),
                (
                    "   Codex CLI: start interactive Codex, enter /hooks, "
                    "select Remem Memory, inspect and approve all five hooks."
                ),
            )
        )
    if installed.claude:
        lines.extend(
            (
                (
                    "   Claude Code: run /reload-plugins, or restart and "
                    "start a new session."
                ),
                (
                    "   Claude Code has no separate Codex hook approval; "
                    "its /hooks view is read-only."
                ),
            )
        )
    lines.append(
        "3. Confirm credential: configured, plugin enabled, and Codex hooks trusted."
    )
    return "\n".join(lines)
```

In `main`, retain the `Installer` instance, capture `installed = installer.run()`,
and print `_activation_guidance(installed)`. Error branches must return before
the renderer is called.

- [ ] **Step 7: Run installer tests and verify GREEN**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_installer -v
```

Expected: every installer test passes with no credential material in output.

- [ ] **Step 8: Commit the installer slice**

```bash
git add scripts/install_remem_memory.py tests/test_installer.py
git commit -m "feat: finish activation after secure install"
```

---

### Task 3: Version 0.3.2 release identity

**Files:**
- Modify: `tests/test_packaging_docs.py`
- Modify: `tests/test_plugin_contract.py`
- Modify: `tests/test_installer.py`
- Modify: `scripts/install_remem_memory.py`
- Modify: `.claude-plugin/marketplace.json`
- Modify: `plugins/remem-memory/.codex-plugin/plugin.json`
- Modify: `plugins/remem-memory/.claude-plugin/plugin.json`
- Modify: `README.md`
- Modify: `.codex/INSTALL.md`
- Modify: `docs/README.codex.md`
- Modify: `docs/SECURITY.md`

**Interfaces:**
- Consumes: Existing semantic-version fields and installer verification.
- Produces: One exact release identity, `0.3.2`, in all manifests, tests, and public release-boundary copy.

- [ ] **Step 1: Change exact-version tests to 0.3.2**

Replace exact `0.3.1` expectations with `0.3.2` in
`tests/test_packaging_docs.py` and `tests/test_plugin_contract.py`. In
`tests/test_installer.py`, make successful fake plugin records use
`install_remem_memory.PLUGIN_VERSION`, and update the existing disabled-current
plugin fixture to `"version": "0.3.2"`.

- [ ] **Step 2: Run exact-version tests and verify RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_plugin_contract.PluginContractTests.test_marketplaces_and_manifests_share_one_identity \
  tests.test_packaging_docs.PackagingDocsTests.test_plugin_descriptions_cover_personal_and_engineering_memory \
  -v
```

Expected: both tests fail because manifests still report `0.3.1`.

- [ ] **Step 3: Bump every release surface to 0.3.2**

Set `PLUGIN_VERSION = "0.3.2"` and update:

- `.claude-plugin/marketplace.json`
- `plugins/remem-memory/.codex-plugin/plugin.json`
- `plugins/remem-memory/.claude-plugin/plugin.json`
- all public current-release and rollback-boundary references found by
  `rg -n '0\.3\.1' README.md .codex docs scripts tests plugins`

Do not change bundled MCP dependency versions or its upstream provenance.

- [ ] **Step 4: Validate JSON and verify exact-version tests GREEN**

Run:

```bash
python3 -m json.tool .claude-plugin/marketplace.json
python3 -m json.tool plugins/remem-memory/.codex-plugin/plugin.json
python3 -m json.tool plugins/remem-memory/.claude-plugin/plugin.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_plugin_contract.PluginContractTests.test_marketplaces_and_manifests_share_one_identity \
  tests.test_packaging_docs.PackagingDocsTests.test_plugin_descriptions_cover_personal_and_engineering_memory \
  -v
```

Expected: JSON validation and both tests pass.

- [ ] **Step 5: Commit the release identity**

```bash
git add .claude-plugin/marketplace.json plugins/remem-memory/.codex-plugin/plugin.json plugins/remem-memory/.claude-plugin/plugin.json scripts/install_remem_memory.py README.md .codex/INSTALL.md docs/README.codex.md docs/SECURITY.md tests/test_installer.py tests/test_packaging_docs.py tests/test_plugin_contract.py
git commit -m "chore: release Remem Memory 0.3.2"
```

---

### Task 4: Full QA, review, publish, and local transition

**Files:**
- Verify only: all tracked repository files
- External verified state: installed Codex/Claude plugins and exact legacy MCP registrations

**Interfaces:**
- Consumes: Release commit with version `0.3.2`.
- Produces: Pushed `master`, verified local installs, one active Remem Memory MCP path per client, and no legacy duplicate registrations.

- [ ] **Step 1: Run both full Python suites**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s tests -v
```

Expected: the baseline 264 tests plus all new tests pass under Python 3.14.3
and the compatibility smoke passes under macOS Python 3.9.6.

- [ ] **Step 2: Run repository and plugin validation**

Run:

```bash
/Users/asimg/.local/bin/claude plugin validate plugins/remem-memory
python3 -m json.tool .agents/plugins/marketplace.json
python3 -m json.tool .claude-plugin/marketplace.json
python3 -m json.tool plugins/remem-memory/.codex-plugin/plugin.json
python3 -m json.tool plugins/remem-memory/.claude-plugin/plugin.json
git diff --check
```

Expected: Claude's native validator, every JSON parser, and the whitespace
check pass.

Create one isolated QA home and run the real installer twice:

```bash
qa_root="$(mktemp -d /private/tmp/remem-memory-qa.XXXXXX)"
qa_home="${qa_root}/home"
qa_codex="${qa_root}/codex"
qa_claude="${qa_root}/claude"
qa_path="/Users/asimg/.local/bin:/opt/homebrew/bin:/usr/bin:/bin"

env HOME="${qa_home}" CODEX_HOME="${qa_codex}" \
  CLAUDE_CONFIG_DIR="${qa_claude}" PATH="${qa_path}" \
  ./install-codex-skill.sh
env HOME="${qa_home}" CODEX_HOME="${qa_codex}" \
  CLAUDE_CONFIG_DIR="${qa_claude}" PATH="${qa_path}" \
  ./install-codex-skill.sh
env HOME="${qa_home}" CODEX_HOME="${qa_codex}" \
  CLAUDE_CONFIG_DIR="${qa_claude}" PATH="${qa_path}" \
  codex plugin list --json
env HOME="${qa_home}" CODEX_HOME="${qa_codex}" \
  CLAUDE_CONFIG_DIR="${qa_claude}" PATH="${qa_path}" \
  claude plugin list --json
env HOME="${qa_home}" PATH="${qa_path}" \
  python3 -I plugins/remem-memory/scripts/remem_mcp_launcher.py --probe
```

Expected: both installs succeed, the second is idempotent, both client lists
show Remem Memory `0.3.2` enabled, and the direct MCP probe exits zero. Inspect
only `${qa_codex}/config.toml` and `${qa_claude}/settings.json` for unexpected
credential values; plugin source caches legitimately contain the fixed probe
canary as source code and are not credential persistence.

- [ ] **Step 3: Request independent code and security review**

Have a fresh reviewer compare the implementation against
`docs/superpowers/specs/2026-07-24-first-run-onboarding-design.md`, inspect all
changed code and tests, and report only actionable findings. Resolve every
finding with a failing regression test first.

- [ ] **Step 4: Merge the reviewed branch to master and push**

Fast-forward the clean stable checkout from `master` to the reviewed release
branch, then push `master` to `origin`. Verify local and remote commit IDs are
identical.

- [ ] **Step 5: Update the current Mac in place**

From the stable clean checkout, rerun:

```bash
./install-codex-skill.sh
env -u REMEM_API_KEY ~/.local/bin/remem-memory status
codex plugin list --json
claude plugin list --json
```

Expected: credential configured outside the restricted test sandbox and
Remem Memory `0.3.2` enabled in both clients. No uninstall is needed.

- [ ] **Step 6: Reload clients and remove exact legacy duplicates**

After the replacement is verified, reload/restart Codex and Claude Code. Remove
only the previously identified global `remem-maya` Codex MCP and user-scope
`remem` Claude MCP registrations. Re-read both configurations and plugin lists
to confirm the canonical plugin is the only active Remem Memory MCP path.

- [ ] **Step 7: Verify live recall and durable capture**

In a fresh supported-client session, verify the canonical MCP can perform an
authenticated read and that trusted hooks produce one bounded automatic
milestone/capture without exposing recalled private content or duplicating a
write.

- [ ] **Step 8: Final repository proof**

Run:

```bash
git status --short
git rev-parse HEAD
git rev-parse origin/master
```

Expected: clean status and identical local/remote release commits.
