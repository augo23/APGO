#!/usr/bin/env bash
# Cross-compile the APGO overlay client for pfSense (FreeBSD).
# Run from anywhere with Go >= 1.23 installed; no FreeBSD machine needed.
#
#   bash pfsense/build-freebsd.sh          # amd64 (pfSense on x86 hardware)
#   ARCH=arm64 bash pfsense/build-freebsd.sh   # arm64 (e.g. Netgate 2100/3100)
set -euo pipefail
cd "$(dirname "$0")/../client"

ARCH="${ARCH:-amd64}"
OUT="../pfsense/overlay-client-freebsd-${ARCH}"

echo "==> Resolving dependencies"
go mod tidy

echo "==> Building overlay-client for freebsd/${ARCH}"
CGO_ENABLED=0 GOOS=freebsd GOARCH="${ARCH}" \
  go build -trimpath -ldflags="-s -w" -o "${OUT}" .

echo "Built ${OUT}"
echo "Next: bash pfsense/install-pfsense.sh <router-address>  (or follow pfsense/README.md)"
