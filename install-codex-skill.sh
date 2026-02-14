#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${HOME}/.agents/skills"
SKILL_SRC="${ROOT_DIR}/codex/skills/remem-dev-sessions"
SKILL_DST="${TARGET_DIR}/remem-dev-sessions"
LEGACY_SKILL_SRC="${ROOT_DIR}/codex/skills/remem-session-memory"
LEGACY_SKILL_DST="${TARGET_DIR}/remem-session-memory"
BIN_DIR="${HOME}/.local/bin"

mkdir -p "${TARGET_DIR}" "${BIN_DIR}"
ln -sfn "${SKILL_SRC}" "${SKILL_DST}"
if [[ -d "${LEGACY_SKILL_SRC}" ]]; then
  ln -sfn "${LEGACY_SKILL_SRC}" "${LEGACY_SKILL_DST}"
fi

ln -sfn "${ROOT_DIR}/scripts/remem_dev_sessions.py" "${BIN_DIR}/remem-dev-sessions"
ln -sfn "${ROOT_DIR}/scripts/remem_codex_wrapper.py" "${BIN_DIR}/remem-dev-sessions-codex"
ln -sfn "${ROOT_DIR}/scripts/remem_checkpoint.py" "${BIN_DIR}/remem-dev-sessions-checkpoint"
ln -sfn "${ROOT_DIR}/scripts/remem_rollup.py" "${BIN_DIR}/remem-dev-sessions-rollup"
ln -sfn "${ROOT_DIR}/scripts/remem_recall.py" "${BIN_DIR}/remem-dev-sessions-recall"

# Legacy command aliases for backwards compatibility.
ln -sfn "${ROOT_DIR}/scripts/remem_codex_wrapper.py" "${BIN_DIR}/remem-memory-codex"
ln -sfn "${ROOT_DIR}/scripts/remem_checkpoint.py" "${BIN_DIR}/remem-memory-checkpoint"
ln -sfn "${ROOT_DIR}/scripts/remem_rollup.py" "${BIN_DIR}/remem-memory-rollup"
ln -sfn "${ROOT_DIR}/scripts/remem_recall.py" "${BIN_DIR}/remem-memory-recall"

chmod +x \
  "${ROOT_DIR}/scripts/remem_dev_sessions.py" \
  "${ROOT_DIR}/scripts/remem_codex_wrapper.py" \
  "${ROOT_DIR}/scripts/remem_checkpoint.py" \
  "${ROOT_DIR}/scripts/remem_rollup.py" \
  "${ROOT_DIR}/scripts/remem_recall.py"

echo "Installed Codex skill: ${SKILL_DST} -> ${SKILL_SRC}"
if [[ -d "${LEGACY_SKILL_SRC}" ]]; then
  echo "Installed legacy skill alias: ${LEGACY_SKILL_DST} -> ${LEGACY_SKILL_SRC}"
fi
echo "Installed helpers:"
echo "  ${BIN_DIR}/remem-dev-sessions"
echo "  ${BIN_DIR}/remem-dev-sessions-codex"
echo "  ${BIN_DIR}/remem-dev-sessions-checkpoint"
echo "  ${BIN_DIR}/remem-dev-sessions-rollup"
echo "  ${BIN_DIR}/remem-dev-sessions-recall"
echo "Legacy aliases kept:"
echo "  ${BIN_DIR}/remem-memory-codex"
echo "  ${BIN_DIR}/remem-memory-checkpoint"
echo "  ${BIN_DIR}/remem-memory-rollup"
echo "  ${BIN_DIR}/remem-memory-recall"
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "Add ${BIN_DIR} to your PATH to call helpers directly."
fi
echo "Restart Codex to reload skills."
