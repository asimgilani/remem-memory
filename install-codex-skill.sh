#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 -I "${ROOT_DIR}/scripts/install_remem_memory.py" "$@"
