# APGO overlay client image. Build from the REPO ROOT as the context:
#   podman build -f apgo-client.containerfile -t apgo-client:latest .
# Go 1.26: golang.org/x/crypto v0.52 needs >= 1.25. The Windows Wintun dep (golang.zx2c4.com/wireguard/tun, resolved by
# `go mod tidy` across all platforms) requires >= 1.23.1. It is only COMPILED on
# Windows; on this Linux build it is resolved then excluded by build tags.
FROM golang:1.26-alpine AS build
RUN apk add --no-cache git gcc musl-dev
WORKDIR /src
COPY client/ ./
# Resolve deps (incl. the optional post-quantum circl library) and write go.sum.
RUN go mod tidy
RUN CGO_ENABLED=1 go build -o /out/overlay-client ./

FROM alpine:3.21
# iptables is needed for EXIT_NODE (internet outproxy) NAT.
RUN apk add --no-cache ca-certificates iputils iproute2 iptables tini curl jq util-linux-misc
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
  _ip="$(printf '%s\n' "$NODE_PUBLIC_IPS" | tr ',' '\n' | while IFS='=' read -r n v; do
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

# LAN CANDIDATES, AUTO-DETECTED (2026-10-19). Nothing is configured per node.
# A pod on a node that shares a public IP with the peers trying to reach it
# (any node at a site where the devices also live) only advertises
# <public ip>:6970. Those peers can only reach that through NAT loopback, which
# most home routers do not do, and the pod's LAN-discovery beacon never leaves
# the pod network - so laptops/phones on the same LAN ended up relayed or with
# no path at all. Fix: advertise every private IPv4 address the NODE itself
# has, paired with the hostPort. The hostPort DNAT answers on every node
# address, so whichever LAN a peer shares with the node, it gets a direct path.
# Remote peers cannot reach a private address and move on to the public one.
#
# How: the container is privileged and /proc of the HOST is mounted at
# /host/proc (apgo.yaml), so nsenter can read the host's interfaces. Skipped:
# loopback, CNI/pod/tunnel/overlay interfaces and non-private addresses.
# LAN_CANDIDATES=off disables it; anything else (default "auto") enables it.
if [ "${LAN_CANDIDATES:-auto}" != off ] && [ -e /host/proc/1/ns/net ] && command -v nsenter >/dev/null 2>&1; then
  _lans="$(nsenter --net=/host/proc/1/ns/net ip -4 -o addr show scope global 2>/dev/null \
    | awk '{ i=$2; sub(/@.*/,"",i); if (i !~ /^(lo|cni|flannel|cali|vxlan|tunl|veth|ovl|zt|docker|podman|br-|kube|nodelocaldns|wg|tailscale|cilium)/) { split($4,a,"/"); print a[1] } }' \
    | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u)"
  _added=""
  for _ip in $_lans; do
    _c="${_ip}:${ADVERTISE_PORT:-6970}"
    case ",${EXTRA_CANDIDATES:-}," in *",${_c},"*) continue ;; esac
    EXTRA_CANDIDATES="${EXTRA_CANDIDATES:+${EXTRA_CANDIDATES},}${_c}"
    _added="${_added:+${_added} }${_c}"
  done
  export EXTRA_CANDIDATES
  if [ -n "$_added" ]; then
    echo "[entrypoint] node ${NODE_NAME:-?}: LAN candidates ${_added} (EXTRA_CANDIDATES=$EXTRA_CANDIDATES)"
  else
    echo "[entrypoint] node ${NODE_NAME:-?}: no private LAN address found on the host - none advertised"
  fi
elif [ "${LAN_CANDIDATES:-auto}" != off ]; then
  echo "[entrypoint] LAN candidates: host /proc not mounted at /host/proc or nsenter missing - skipped"
fi

exec /usr/local/bin/overlay-client "$@"
EOF
RUN chmod +x /usr/local/bin/apgo-entrypoint

# `apgo` — operator CLI inside the container. It is a thin client for the same
# local control socket the admin dashboard uses (control.go); nothing new is
# exposed. Usage: apgo help
RUN cat > /usr/local/bin/apgo <<'EOF'
#!/bin/sh
SOCK="${CONTROL_SOCKET:-/shared/control.sock}"
api() {
  [ -S "$SOCK" ] || { echo "apgo: control socket $SOCK not found (is overlay-client running? set CONTROL_SOCKET)" >&2; exit 1; }
  curl -fsS --unix-socket "$SOCK" "http://apgo$1"
}
case "${1:-help}" in
  peers|sessions)
    api /api/sessions | jq -r '
      (["NAME","OVERLAY_IP","PATH","VIA","REMOTE","EST","APPROVED","LAST_SEEN_S"] | @tsv),
      (sort_by(.overlay_ip)[] | [
        (.name // "-" | if .=="" then "-" else . end), .overlay_ip,
        (.path // (if .relayed then "relay" else "?" end)),
        (if (.via // "") == "" then "-" else .via end),
        .remote, .established, .approved,
        (if .last_seen_unix then (now - .last_seen_unix | floor) else "-" end)
      ] | @tsv)' | column -t -s "$(printf '\t')" ;;
  relayed)
    api /api/sessions | jq -r '.[] | select(.relayed or .path=="relay") | "\(.name // "") \(.overlay_ip) via \(.via)"' ;;
  status|info)  api /api/info | jq . ;;
  exits)        api /api/exits | jq . ;;
  discovery)    api /api/discovery | jq . ;;
  trackers)     api /api/trackers | jq . ;;
  revocations)  api /api/revocations | jq . ;;
  networks)     api /api/networks | jq . ;;
  services|replicas)
    # Service copies (client/replicas.go): the copies THIS node publishes for
    # its own address (with health), then every service with copies this node
    # knows. "*" marks where NEW connections go.
    _j="$(api /api/services)"
    printf '%s' "$_j" | jq -r 'if .publishing then
        "publishing copies of \(.publishing.address) (\(.publishing.ports)): " +
        (.publishing.nodes | map("\(.address) \(if .healthy then "ok" else "DOWN" end)") | join(", ")), ""
      else empty end'
    printf '%s' "$_j" | jq -r '(["SERVICE","CANDIDATE","NAME","RTT_MS","USABLE"] | @tsv),
      ((.services // [])[] | .address as $a | .candidates[] |
        [$a, ((if .preferred then "*" else "" end) + .address + (if .owner then " (owner)" else "" end)),
         (if (.name // "") == "" then "-" else .name end), (.rtt_ms // "?"), .usable] | @tsv)' | column -t -s "$(printf '\t')"
    printf '%s' "$_j" | jq -r '"", "redirected connections: \(.flows)  packets rewritten out/in: \(.tx_rewritten)/\(.rx_rewritten)"'
    ;;
  get)          api "$2" | jq . ;;
  log|logs)     exec tail -n "${2:-100}" -F "${LOG_FILE:-/shared/overlay-client.log}" ;;
  help|-h|--help)
    cat <<H
apgo — APGO overlay node CLI (talks to $SOCK)
  apgo peers         peers with path (lan/direct/wan/relay) and relay node (VIA)
  apgo relayed       only peers reached through a relay
  apgo status        this node: key, overlay IP, uptime, config
  apgo services      service copies: what this node publishes, which copy each service uses, RTTs
  apgo exits | discovery | trackers | revocations | networks
  apgo get /api/...  raw GET of any control endpoint
  apgo log [N]       follow the client log
H
    ;;
  *) echo "apgo: unknown command '$1' (try: apgo help)" >&2; exit 2 ;;
esac
EOF
RUN chmod +x /usr/local/bin/apgo && ln -s apgo /usr/local/bin/apgoverlay

ENTRYPOINT ["tini", "--", "/usr/local/bin/apgo-entrypoint"]
