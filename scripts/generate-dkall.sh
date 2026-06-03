#!/usr/bin/env bash
# Dump HAProxy registered keywords via -dKall for schema generation.
# Usage: generate-dkall.sh [version] [output-path]
#   version defaults to 3.2 (used in output filename only unless HAPROXY is set).
#
# Requires a HAProxy binary built with DEBUG (Debian/Ubuntu packages usually work).
# Per HAProxy docs, a silent check on any config is enough:
#   haproxy -dKall -q -c -f foo.cfg
# With no config, -f /dev/null dumps all default keywords (exit status may be non-zero).

set -euo pipefail

VERSION="${1:-3.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MONOREPO_ROOT="$(cd "${TOOLS_ROOT}/.." && pwd)"
OUT="${2:-${TOOLS_ROOT}/haproxy_schema/dkall-${VERSION}.txt}"
BIN_CANDIDATE="${TOOLS_ROOT}/haproxy_schema/bin/haproxy-${VERSION}"
if [[ -z "${HAPROXY:-}" ]]; then
  if [[ -x "${BIN_CANDIDATE}" ]] || [[ -f "${BIN_CANDIDATE}" ]]; then
    HAPROXY="${BIN_CANDIDATE}"
  else
    HAPROXY="haproxy"
  fi
fi

CFG="/dev/null"
if [[ -d "${MONOREPO_ROOT}/haproxy_git" ]]; then
  REPO_CFG="${MONOREPO_ROOT}/haproxy_git/haproxy-${VERSION}/tests/conf/basic-check.cfg"
  if [[ -f "${REPO_CFG}" ]]; then
    CFG="${REPO_CFG}"
  fi
fi

if [[ "${HAPROXY}" == */* ]]; then
  if [[ ! -x "${HAPROXY}" ]]; then
    echo "error: ${HAPROXY} is not executable" >&2
    exit 1
  fi
elif ! command -v "${HAPROXY}" >/dev/null 2>&1; then
  echo "error: ${HAPROXY} not found in PATH" >&2
  exit 1
fi

VER_LINE="$("${HAPROXY}" -v 2>&1 | head -n 1 || true)"
if [[ "${VER_LINE}" == *"version is"* ]]; then
  INSTALLED="${VER_LINE#*version is }"
  INSTALLED="${INSTALLED%% *}"
elif [[ "${VER_LINE}" == *"HAProxy version"* ]]; then
  INSTALLED="${VER_LINE#*HAProxy version }"
  INSTALLED="${INSTALLED%% *}"
else
  INSTALLED="unknown"
fi

if [[ "${INSTALLED}" != "${VERSION}"* && "${INSTALLED}" != unknown ]]; then
  echo "warning: requested dkall-${VERSION}.txt but '${HAPROXY}' reports ${INSTALLED}" >&2
fi

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

dump_keywords() {
  local cfg="$1"
  : >"${TMP}"
  if ! "${HAPROXY}" -dKall -q -c -f "${cfg}" >"${TMP}" 2>/dev/null; then
    "${HAPROXY}" -dKall -q -c -f "${cfg}" >"${TMP}" 2>/dev/null || true
  fi
}

dump_keywords "${CFG}"
if [[ ! -s "${TMP}" ]] || head -n 1 "${TMP}" | grep -qE '^HAProxy version|Usage :'; then
  if [[ "${CFG}" != "/dev/null" ]]; then
    echo "warning: -dKall with ${CFG} produced no dump; retrying with /dev/null" >&2
    CFG="/dev/null"
    dump_keywords "${CFG}"
  fi
fi

if [[ ! -s "${TMP}" ]] || head -n 1 "${TMP}" | grep -qE '^HAProxy version|Usage :'; then
  echo "error: -dKall produced no keyword dump (binary may lack DEBUG). First lines:" >&2
  head -n 5 "${TMP}" >&2 || true
  exit 1
fi

mkdir -p "$(dirname "${OUT}")"
{
  echo "# HAProxy keyword dump for schema tooling (dkall)"
  echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Binary: ${VER_LINE}"
  echo "# Command: ${HAPROXY} -dKall -q -c -f ${CFG}"
  echo "# Target schema version label: ${VERSION}"
  cat "${TMP}"
} >"${OUT}"

LINES="$(wc -l <"${OUT}" | tr -d ' ')"
echo "Wrote ${OUT} (${LINES} lines, cfg=${CFG})"
