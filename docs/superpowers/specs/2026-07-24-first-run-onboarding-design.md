# Remem Memory First-Run Onboarding Design

Date: 2026-07-24  
Status: Proposed for implementation

## Problem

Remem Memory installs and verifies the plugin correctly, but a first-time user
can still miss the final activation steps. The current documentation mentions
Codex hook trust after a long manual-setup section, does not distinguish Codex
Desktop from Codex CLI, and only implies what Claude Code needs. The installer
ends with `Remem Memory setup complete.` even when a reload or hook approval is
still required.

This creates a misleading state: MCP tools, skills, and manual commands may
work, while automatic recall, durable conversational capture, and engineering
continuity remain inactive because Codex hooks have not been trusted.

## Audience

- A person arriving organically at the GitHub repository.
- A person telling an AI coding agent to follow `.codex/INSTALL.md`.
- A Codex Desktop user who prefers visible controls.
- A Codex CLI user working entirely in a terminal.
- A Claude Code user, or a user installing into both supported clients.
- A returning user updating the plugin on an existing or replacement Mac.

## Goals

1. Make the shortest safe path from repository arrival to working automatic
   memory obvious.
2. Explain exactly where Codex Desktop and Codex CLI users approve hooks.
3. Explain that Claude Code must reload active plugins or start a restarted
   session, but does not use Codex's separate `/hooks` approval.
4. State the expected end state in language a non-expert can verify.
5. Print the relevant activation steps when installation completes.
6. Preserve manual, hash-bound hook trust and secure Keychain entry.
7. Keep agent-driven installation as the primary quick-install path.
8. Add regression tests so these instructions cannot silently disappear.
9. Fail safely when neither supported client is installed instead of reporting
   a successful plugin installation.

## Non-goals

- No Remem API, portal, data, account, or namespace changes.
- No migration wizard, browser setup panel, local server, or daemon.
- No new plugin, profile system, persona, or Maya-specific behavior.
- No change to recall, capture, checkpoint, rollup, or sensitivity policy.
- No automatic hook trust and no hook-trust bypass.
- No promise that ordinary ChatGPT mobile conversations load a Mac-local
  plugin.

## Documentation structure

### Repository README

Keep the existing one-plugin explanation. Change the agent-install prompt to
address either Codex or Claude Code on the target Mac, while retaining the same
reviewable `.codex/INSTALL.md` URL. Give manual setup as the fallback for a
person who is not already inside a supported coding agent.

The Requirements section must link to the Remem account at
`https://app.remem.io` as the place to obtain an API key, without changing or
embedding the customer portal. It must recommend a least-privilege key whose
workspace/namespace access matches what the user wants this Mac to remember.

Immediately after Quick install, add a prominent **Finish activation** section
with this order:

1. Run
   `env -u REMEM_API_KEY ~/.local/bin/remem-memory status` to check the
   canonical Keychain source. Run `~/.local/bin/remem-memory auth` only if it
   reports `credential: missing`. Explain that the prompt is hidden and the API
   key must never be pasted into chat, a command argument, or a config file,
   and link to `https://app.remem.io` if the user still needs a key.
2. Reload or restart each installed client as described for its surface.
3. Follow the surface-specific activation table:

| Surface | Required action |
| --- | --- |
| Codex Desktop | Open **Plugins → Remem Memory → Hooks**, choose **Review**, inspect the five hooks, and trust them. |
| Codex CLI | Start interactive Codex, enter `/hooks`, select **Remem Memory**, inspect the five hooks, and approve them. |
| Claude Code | Run `/reload-plugins`, or restart Claude Code and start a new session. There is no separate Codex-style `/hooks` approval. Claude's `/hooks` view is read-only and can verify that plugin hooks loaded. |

The section must say that Codex trust is local to that Codex installation or
configuration and bound to the reviewed hook hash. A new Mac/configuration or a
release that changes hook content requires review again.

The README must also give a concise expected end state:

- `env -u REMEM_API_KEY ~/.local/bin/remem-memory status` reports the intended
  mode/sensitivity and `credential: configured`;
- every installed client reports Remem Memory enabled at the release version;
- Codex shows all five Remem Memory hooks trusted; and
- a fresh supported-client session can use automatic memory.

All commands needed before the README explains `PATH` behavior must use the
installed absolute command path, so a user whose shell does not include
`~/.local/bin` cannot dead-end.

Keep the detailed security and runtime explanation later in the README so the
first-run path stays short.

### Agent install guide

Retain the current safety rules, clean-checkout behavior, hidden credential
entry, verification commands, and no-portal/no-API boundary. Replace the
generic restart paragraph with explicit Codex Desktop, Codex CLI, and Claude
Code reload/restart steps. An installing agent must:

- stop before asking for or handling an API key in chat;
- let the user enter the key into the hidden terminal prompt;
- tell the user which UI or CLI approval remains;
- verify plugin state without pretending it can approve hooks for the user;
- explain that automatic Codex behavior is unavailable until trust is granted;
  and
- stop with a clear prerequisite error when neither Codex nor Claude Code is
  installed.

### Codex-specific guide

Mirror the two Codex approval routes in `docs/README.codex.md`, including local
and hash-bound trust. This prevents the secondary guide from drifting back to
an ambiguous `/hooks` instruction.

### Bounded troubleshooting

Keep troubleshooting adjacent to activation and limited to the common
first-run dead ends:

- Keychain status is missing: run the hidden `auth` prompt.
- A client does not list the plugin: rerun the installer from a clean,
  up-to-date checkout and read its fixed error.
- Codex automatic behavior is absent: review the local hook trust state.
- Claude Code still shows the old plugin state: run `/reload-plugins` or
  restart it.
- Neither supported client is installed: install Codex or Claude Code before
  rerunning setup.

Do not add a wizard, background health service, or broad operational manual to
solve these documentation cases.

## Installer completion contract

The secure installer will retain its existing preflight, installation,
verification, and rollback behavior, except that preflight will now reject a
host with neither supported client before installation mutation. Its successful
return value will identify which supported clients were detected and verified.
The command-line entry point will then print:

1. `Remem Memory installed successfully.`
2. `Finish activation:` so remaining user work cannot be mistaken for a fully
   active setup.
3. A canonical-Keychain reminder using
   `env -u REMEM_API_KEY ~/.local/bin/remem-memory status` and, only if needed,
   `~/.local/bin/remem-memory auth`.
4. A reload/restart instruction.
5. Only the client instructions relevant to the detected clients:
   - When Codex was installed, print two clearly labeled alternative routes:
     Codex Desktop and Codex CLI. The installer does not attempt to infer which
     Codex surface the user prefers.
   - Claude Code `/reload-plugins` or restart guidance and the explicit absence
     of a Codex `/hooks` approval gate when Claude Code was installed.
6. A short verification checklist.

The output must never include a credential, suggest pasting one into chat, edit
shell startup files, approve hooks, or invoke a dangerous trust bypass. Failure
paths must continue to print no success or activation message.

If neither supported client is present, setup must fail before installing
aliases, preparing the MCP cache, writing credentials, or changing client
configuration. Its fixed error must tell the user to install Codex or Claude
Code first. This change does not broaden platform support.

## Security and trust model

- Codex hook approval remains a user decision.
- Approval is local and hash-bound; changed hooks must be re-reviewed.
- The installer may detect and verify client state but may not mutate hook
  trust.
- The API key remains in the macOS Keychain item
  `io.remem.memory` / `default`.
- Documentation never asks a user or agent to expose the key in chat, command
  history, process arguments, plugin manifests, or configuration files.
- MCP, skills, and manual commands may work before Codex hook trust, but the
  docs must not describe the installation as fully activated until automatic
  hooks are trusted.

## Test strategy

Use test-driven changes.

1. Extend packaging-documentation tests to require:
   - the **Finish activation** section near Quick install;
   - distinct `Codex Desktop`, `Codex CLI`, and `Claude Code` guidance;
   - the Desktop navigation route and CLI `/hooks` route;
   - five-hook review;
   - local/hash-bound approval and re-review;
   - Claude's reload/restart behavior, read-only hook inspection, and lack of a
     Codex `/hooks` approval gate;
   - the expected end-state checklist; and
   - the secure hidden-credential warning.
   Assertions must be made against the specific document that owns each
   requirement. Heading-order assertions must protect the README's short
   first-run path instead of merely searching an aggregate documentation blob.
2. Add installer-output tests for Codex only, Claude Code only, and both
   clients. Codex cases must contain both labeled Desktop and CLI alternatives;
   Claude-only output must not contain Codex trust instructions.
3. Add a no-client test that proves preflight fails before filesystem,
   Keychain, cache, or client mutation.
4. Assert that every installer failure omits success and activation guidance.
5. Assert that output contains no test credential or insecure bypass language.
6. Run the full Python suite under a supported Python 3.10+ interpreter. On the
   current Mac, also run the suite under `/usr/bin/python3` 3.9.6 as an
   additional backward-compatibility smoke test; this does not lower the
   documented Python 3.10+ minimum.
7. Re-run native Codex and Claude plugin validation, clean-install QA,
   idempotent-update QA, and the bundled MCP probe before release.
8. Manually read the rendered first-run flow once as a novice usability check;
   subjective clarity is a review gate, not something token-presence tests can
   prove.

## Release and transition

Ship this as version `0.3.2`, a patch release, because public onboarding and
installer behavior change without altering the memory protocol or stored data.
Existing users rerun the same installer. No Remem data migration is performed.
Existing Claude Code engineering-memory behavior and compatibility aliases
remain unchanged.

After release, install the patch on the current Mac, reload or restart each
client, approve any changed Codex hook hash, verify exactly one active Remem
Memory plugin/MCP path per client, and remove only the already-identified
legacy global MCP registrations after the replacement is proven.

## Acceptance criteria

- A new user can complete installation from the README without knowing what a
  hook, MCP server, or harness is beforehand.
- Codex-only and Claude-only visitors both have a complete entry path, including
  where to obtain a Remem API key.
- Desktop, CLI, and Claude Code users each see one unambiguous activation path.
- A host with neither supported client fails before mutation.
- The installer distinguishes successful installation from the remaining
  activation actions.
- The security model is preserved: hidden Keychain entry and explicit
  hash-bound Codex trust.
- All documentation and installer-output regression tests pass.
- The unchanged baseline commit passes all 264 tests, and the final branch
  passes that full suite plus the new onboarding tests.
- Codex and Claude Code retain one shared Remem Memory product identity and
  all existing automatic personal and engineering memory behavior.
