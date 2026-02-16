# Installing Remem Dev Sessions for Codex

Enable automatic Remem checkpoints in Codex using the `remem-codex` wrapper, with MCP configured automatically.

## Prerequisites

- OpenAI Codex CLI installed
- Git
- Python 3.10+

## Installation (macOS/Linux)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/asimgilani/remem-memory.git ~/.codex/remem-dev-sessions
   ```

2. **Install dependencies:**
   ```bash
   cd ~/.codex/remem-dev-sessions
   python3 -m pip install -r requirements.txt
   ```

3. **Ensure command PATH includes `~/.local/bin`:**
   ```bash
   if ! echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
     echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
     export PATH="$HOME/.local/bin:$PATH"
   fi
   ```

4. **Set Remem API environment variables:**
   ```bash
   echo 'export REMEM_API_URL="https://api.remem.io"' >> ~/.zshrc
   echo 'export REMEM_API_KEY="vlt_your_key_here"' >> ~/.zshrc
   source ~/.zshrc
   ```

5. **Install skills/commands and MCP config:**
   ```bash
   cd ~/.codex/remem-dev-sessions
   ./install-codex-skill.sh
   ```

6. **Restart Codex.**

## Verify

```bash
which remem-codex
rg -n "mcp_servers.remem" ~/.codex/config.toml
remem-dev-sessions checkpoint --project smoke --session-id test --summary "ok" --dry-run --no-log
```

## Daily Usage

In your project directory, launch Codex via wrapper:

```bash
remem-codex
```

This automatically:

- Creates periodic interval checkpoints (default 20 min)
- Writes milestone checkpoint on Codex exit when changes exist
- Writes final rollup on exit
- Generates structured checkpoint/rollup summaries from Codex session transcript using Codex CLI

MCP (`remem_query`) is configured during install and available after restart.

Optional summary tuning:

```bash
export REMEM_MEMORY_SUMMARY_ENABLED="1"
export REMEM_MEMORY_SUMMARY_PROVIDER="codex_cli"
export REMEM_MEMORY_SUMMARY_MODEL="gpt-5.3-codex-spark"
```

## Update

```bash
cd ~/.codex/remem-dev-sessions
git pull
python3 -m pip install -r requirements.txt
./install-codex-skill.sh
```

## Uninstall

```bash
rm -f ~/.local/bin/remem-codex \
      ~/.local/bin/remem-dev-sessions \
      ~/.local/bin/remem-dev-sessions-codex \
      ~/.local/bin/remem-dev-sessions-checkpoint \
      ~/.local/bin/remem-dev-sessions-rollup \
      ~/.local/bin/remem-dev-sessions-recall \
      ~/.local/bin/remem-memory-codex \
      ~/.local/bin/remem-memory-checkpoint \
      ~/.local/bin/remem-memory-rollup \
      ~/.local/bin/remem-memory-recall
rm -f ~/.agents/skills/remem-dev-sessions ~/.agents/skills/remem-session-memory
```

Optionally remove the clone:

```bash
rm -rf ~/.codex/remem-dev-sessions
```
