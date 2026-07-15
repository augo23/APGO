#!/usr/bin/env bash
#
# easy-deploy.sh — the simplest way to run APGO on a single Linux host. It builds
# the two images locally with podman (or docker) from the root Containerfiles,
# then brings the stack up with easy-compose.yml. No registry, no Kubernetes.
#
#   ./easy-deploy.sh            build images + start
#   ./easy-deploy.sh --down     stop and remove the stack
#   ./easy-deploy.sh --rebuild  force a fresh (no-cache) image build, then start
#
# On first run it generates a .env with a fresh PSK and a random dashboard
# password; edit .env to set your own NETWORK_NAME if you like.
set -euo pipefail
cd "$(dirname "$0")"

# --- pick a container engine + compose ---
if command -v podman >/dev/null 2>&1; then
  ENGINE=podman
  if command -v podman-compose >/dev/null 2>&1; then COMPOSE="podman-compose"
  else COMPOSE="podman compose"; fi
elif command -v docker >/dev/null 2>&1; then
  ENGINE=docker
  COMPOSE="docker compose"
else
  echo "Need podman or docker installed." >&2
  exit 1
fi

# --- generate .env on first run ---
if [ ! -f .env ]; then
  echo "==> Creating .env (edit it to change the network name)…"
  rand() { openssl rand -base64 "$1" 2>/dev/null | tr -d '\n'; }
  cat > .env <<EOF
# APGO easy-deploy configuration. Use the SAME NETWORK_NAME and PSK on every
# node/device that should join this network.
NETWORK_NAME=apgo-$(rand 6 | tr -dc 'a-z0-9' | cut -c1-8)
PSK=base64:$(rand 32)
OVERLAY_CIDR=10.28.55.0/24
FRIENDLY_NAME=$(hostname)
# Set EXIT_NODE=1 to make this host an internet exit / outproxy.
EXIT_NODE=
# Optional HTTPS discovery servers for BitTorrent-blocked networks (comma list).
RENDEZVOUS_SERVERS=
# Admin dashboard login (blank = create one on first visit).
ADMIN_USER=admin
ADMIN_PASSWORD=$(rand 12 | tr -dc 'A-Za-z0-9' | cut -c1-16)
EOF
  echo "    Wrote .env — network name + credentials:"
  grep -E 'NETWORK_NAME|ADMIN_USER|ADMIN_PASSWORD' .env | sed 's/^/      /'
fi

if [ "${1:-}" = "--down" ]; then
  echo "==> Stopping stack…"
  $COMPOSE -f easy-compose.yml down
  exit 0
fi

BUILD_ARGS=""
[ "${1:-}" = "--rebuild" ] && BUILD_ARGS="--no-cache"

echo "==> Building images with $ENGINE…"
$ENGINE build $BUILD_ARGS -f apgoclient.containerfile -t apgoclient:latest .
$ENGINE build $BUILD_ARGS -f apgoadmin.containerfile  -t apgoadmin:latest  .

echo "==> Starting stack…"
$COMPOSE -f easy-compose.yml up -d

echo
echo "==> Up. Dashboard: http://127.0.0.1:8788   (put a reverse proxy in front to expose it)"
echo "    Logs: $ENGINE logs -f overlay-client"
