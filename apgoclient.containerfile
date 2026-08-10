# APGO overlay client image. Build from the REPO ROOT as the context:
#   podman build -f apgoclient.containerfile -t apgoclient:latest .
# Go 1.24: the Windows Wintun dep (golang.zx2c4.com/wireguard/tun, resolved by
# `go mod tidy` across all platforms) requires >= 1.23.1. It is only COMPILED on
# Windows; on this Linux build it is resolved then excluded by build tags.
FROM golang:1.24-alpine AS build
RUN apk add --no-cache git gcc musl-dev
WORKDIR /src
COPY client/ ./
# Resolve deps (incl. the optional post-quantum circl library) and write go.sum.
RUN go mod tidy
RUN CGO_ENABLED=1 go build -o /out/overlay-client ./

FROM alpine:3.21
# iptables is needed for EXIT_NODE (internet outproxy) NAT.
RUN apk add --no-cache ca-certificates iputils iproute2 iptables tini
COPY --from=build /out/overlay-client /usr/local/bin/overlay-client

# Bake the network config INTO the image as a read-only seed. At runtime the
# entrypoint copies it into the /config volume on first start (see below), so
# the container never depends on a host bind mount — which is what broke reboot
# recovery when config was mounted from ephemeral /dev/shm deploy scratch.
# NOTE: only the NETWORK-WIDE settings (network_name, psk, overlay_cidr, …) are
# baked; the per-node identity (node.key) is generated at runtime into the
# volume and is never part of the image. The psk lives in this layer, so keep
# the image in a private registry (as this project already assumes).
COPY config/client.yaml config/trackers.txt /seed/

# First-run seeder: populate the persistent /config volume from /seed without
# ever clobbering node.key (this node's identity) or later admin edits. Set
# FORCE_CONFIG_RESEED=1 to push a rebuilt image's client.yaml/trackers over the
# volume copy on next start.
#
# /config is NOT always writable. Under Kubernetes it is a ConfigMap volume,
# which is mounted read-only — the client.yaml there is already authoritative,
# so there is nothing to seed. Seeding must therefore never be fatal: a failed
# copy is logged and skipped, and trackers.txt falls back to the writable state
# dir (/state, or $TRACKERS_FILE) which is where the client looks by default and
# where the admin panel's tracker editor needs to be able to write anyway.
RUN cat > /usr/local/bin/apgo-entrypoint <<'EOF'
#!/bin/sh
set -e
SEED=/seed
CFG=/config

# Where a seeded copy can actually land. Prefer /config; fall back to the state
# dir when /config is read-only (Kubernetes ConfigMap mount).
TRACKER_DEST_DIR="$(dirname "${TRACKERS_FILE:-/state/trackers.txt}")"
mkdir -p "$CFG" 2>/dev/null || true
if [ -w "$CFG" ]; then
  cfg_writable=1
else
  cfg_writable=0
  echo "[entrypoint] /config is read-only — treating it as authoritative (no seeding)"
fi

seed_file() {
  src="$1"; dst="$2"
  if cp "$src" "$dst" 2>/dev/null; then
    echo "[entrypoint] seeded $(basename "$src") into $(dirname "$dst")"
  else
    echo "[entrypoint] WARNING: could not write $dst — continuing without seeding it"
  fi
}

for f in client.yaml trackers.txt; do
  [ -f "$SEED/$f" ] || continue

  # Pick a destination: /config when writable, else the state dir for
  # trackers.txt (client.yaml comes from the read-only mount itself).
  dst="$CFG/$f"
  if [ "$cfg_writable" = "0" ]; then
    if [ "$f" = "trackers.txt" ] && mkdir -p "$TRACKER_DEST_DIR" 2>/dev/null && [ -w "$TRACKER_DEST_DIR" ]; then
      dst="$TRACKER_DEST_DIR/$f"
    else
      continue
    fi
  fi

  if [ ! -f "$dst" ]; then
    seed_file "$SEED/$f" "$dst"
  elif [ "${FORCE_CONFIG_RESEED:-0}" = "1" ]; then
    echo "[entrypoint] FORCE_CONFIG_RESEED=1 — overwriting $dst from image"
    seed_file "$SEED/$f" "$dst"
  fi
done

# Resolve THIS NODE's public address, dynamically.
#
# Why this is needed: STUN tells the client where its packets appear to come
# from, which in a Kubernetes cluster is the EGRESS node — not necessarily the
# node this pod runs on, and it is the node this pod runs on that holds the
# hostPort DNAT. Announcing the egress address sends every peer to a machine
# with no route to this pod, and they all silently fall back to relay.
#
# NODE_PUBLIC_IPS is a "nodeName=ip,nodeName=ip" map (from the ConfigMap) and
# NODE_NAME comes from the downward API, so the pod looks up whichever node it
# actually landed on. Nothing is pinned: reschedule the pod and it resolves the
# new node's address by itself. Unset/unmatched simply falls through to the
# existing behaviour.
if [ -n "${NODE_PUBLIC_IPS:-}" ] && [ -n "${NODE_NAME:-}" ]; then
  _ip="$(printf '%s' "$NODE_PUBLIC_IPS" | tr ',' '\n' | while IFS='=' read -r n v; do
      [ "$(printf '%s' "$n" | tr -d ' ')" = "$NODE_NAME" ] && printf '%s' "$(printf '%s' "$v" | tr -d ' ')" && break
    done)"
  if [ -n "$_ip" ]; then
    _port="${ADVERTISE_PORT:-6970}"
    # Keep any operator-set candidates and put ours first.
    if [ -n "${EXTRA_CANDIDATES:-}" ]; then
      EXTRA_CANDIDATES="${_ip}:${_port},${EXTRA_CANDIDATES}"
    else
      EXTRA_CANDIDATES="${_ip}:${_port}"
    fi
    export EXTRA_CANDIDATES
    echo "[entrypoint] node $NODE_NAME -> public ${_ip}:${_port} (EXTRA_CANDIDATES=$EXTRA_CANDIDATES)"
  else
    echo "[entrypoint] WARNING: NODE_PUBLIC_IPS has no entry for node '$NODE_NAME' —" \
         "peers will use the STUN-observed address, which in this cluster may be the" \
         "egress node rather than this one. Add '$NODE_NAME=<public-ip>' to NODE_PUBLIC_IPS."
  fi
fi

exec /usr/local/bin/overlay-client "$@"
EOF
RUN chmod +x /usr/local/bin/apgo-entrypoint

ENTRYPOINT ["tini", "--", "/usr/local/bin/apgo-entrypoint"]
