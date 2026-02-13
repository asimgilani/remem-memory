#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${HOME}/.agents/skills"
SKILL_SRC="${ROOT_DIR}/codex/skills/remem-session-memory"
SKILL_DST="${TARGET_DIR}/remem-session-memory"

mkdir -p "${TARGET_DIR}"
ln -sfn "${SKILL_SRC}" "${SKILL_DST}"

echo "Installed Codex skill: ${SKILL_DST} -> ${SKILL_SRC}"
echo "Restart Codex to reload skills."
