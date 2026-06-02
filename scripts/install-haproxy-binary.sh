#!/usr/bin/env bash
# Download and extract a versioned haproxy binary from haproxy.debian.net (no apt swap).
# Usage: install-haproxy-binary.sh 3.0|3.2 [install-dir]
set -euo pipefail

VERSION="${1:?version required (e.g. 3.0 or 3.2)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="${2:-${TOOLS_ROOT}/haproxy_schema/bin}"
MAJOR="${VERSION%%.*}.${VERSION#*.}"
DIST="bookworm-backports-${MAJOR}"
PKG_URL="https://haproxy.debian.net/dists/${DIST}/main/binary-amd64/Packages"
TARGET="${INSTALL_DIR}/haproxy-${VERSION}"

mkdir -p "${INSTALL_DIR}"
TMP="$(mktemp -d -p /tmp 2>/dev/null || mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

FILENAME="$(curl -fsSL "${PKG_URL}" | awk -v ver="${VERSION}" '
  /^Package: haproxy$/ { pkg=1; next }
  pkg && /^Version:/ { v=$2; sub(/~.*/, "", v); if (index(v, ver ".") == 1) ver_match=1; else ver_match=0 }
  pkg && ver_match && /^Filename:/ { print $2; exit }
')"
if [[ -z "${FILENAME}" ]]; then
  echo "error: could not find haproxy package for version ${VERSION} in ${DIST}" >&2
  exit 1
fi

DEB_URL="https://haproxy.debian.net/${FILENAME}"
echo "Downloading ${DEB_URL}"
curl -fsSL "${DEB_URL}" -o "${TMP}/haproxy.deb"
dpkg-deb -x "${TMP}/haproxy.deb" "${TMP}/root"
install -m 0755 "${TMP}/root/usr/sbin/haproxy" "${TARGET}"
echo "Installed ${TARGET}"
"${TARGET}" -v 2>&1 | head -n 1
