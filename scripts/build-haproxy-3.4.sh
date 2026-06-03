#!/usr/bin/env bash
# Build HAProxy 3.4 with OpenSSL for schema tooling (dkall + integration tests).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MONOREPO_ROOT="$(cd "${TOOLS_ROOT}/.." && pwd)"
SRC="${MONOREPO_ROOT}/haproxy_git/haproxy-3.4"
BIN="${TOOLS_ROOT}/haproxy_schema/bin/haproxy-3.4"

if [[ ! -f "${SRC}/Makefile" ]]; then
  echo "error: ${SRC}/Makefile not found" >&2
  exit 1
fi

cd "${SRC}"
make clean 2>/dev/null || true
make -j"$(nproc)" TARGET=linux-glibc USE_OPENSSL=1

mkdir -p "$(dirname "${BIN}")"
install -m 0755 haproxy "${BIN}"

echo "Installed ${BIN}"
"${BIN}" -v 2>&1 | head -n 1
"${BIN}" -vv 2>&1 | grep Feature
