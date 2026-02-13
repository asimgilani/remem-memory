#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${HOME}/.agents/skills"
SKILL_SRC="${ROOT_DIR}/codex/skills/remem-session-memory"
SKILL_DST="${TARGET_DIR}/remem-session-memory"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "${TARGET_DIR}" "${BIN_DIR}"
ln -sfn "${SKILL_SRC}" "${SKILL_DST}"
ln -sfn "${ROOT_DIR}/scripts/remem_checkpoint.py" "${BIN_DIR}/remem-memory-checkpoint"
ln -sfn "${ROOT_DIR}/scripts/remem_rollup.py" "${BIN_DIR}/remem-memory-rollup"

chmod +x "${ROOT_DIR}/scripts/remem_checkpoint.py" "${ROOT_DIR}/scripts/remem_rollup.py"

echo "Installed Codex skill: ${SKILL_DST} -> ${SKILL_SRC}"
echo "Installed helpers: ${BIN_DIR}/remem-memory-checkpoint and ${BIN_DIR}/remem-memory-rollup"
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "Add ${BIN_DIR} to your PATH to call helpers directly."
fi
echo "Restart Codex to reload skills."
