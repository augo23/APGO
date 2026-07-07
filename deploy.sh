#!/usr/bin/env bash
# deploy.sh — Run this ON the target server. Brings up the overlay stack
# for whichever role this box plays (server 1 or server 2). With --test,
# verifies the overlay can reach the other side.
#
# Place this at the PROJECT ROOT. The Forgejo workflow ships the repo to
# the server and runs `./deploy.sh` from there.
#
# Role detection (in priority order):
#   1. $SERVER_NUM = 1 or 2          (set by CI matrix)
#   2. hostname pattern              (site-specific; see detect_role below)
#
# Modes:
#   ./deploy.sh                  full cleanup + bring the stack up (default)
#   ./deploy.sh --test           ping the other server's TUN IP from local client
#   ./deploy.sh --deploy-test    do both in one shot
#   ./deploy.sh --down           full cleanup, leave stack down
#
# Every `deploy` starts from a clean slate:
#   - existing compose stack brought down (with volumes + orphans)
#   - any leftover overlay-* containers force-removed
#   - overlay-net network dropped
#   - legacy bare-metal overlay binaries (/tmp/overlay-*) killed
#   - stale screen sessions named overlay-* quit
#   - active-config/ wiped (so node.key is regenerated fresh)
#
# Env knobs:
#   SERVER_NUM=1|2               override role detection
#   SKIP_BUILD=1                 docker compose up -d (no rebuild)
#   FRESH_BUILD=1                also remove overlay-* images + build --no-cache --pull
#   TEST_MAX_WAIT=360            seconds to wait for overlay before failing

set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# --- Node identity -----------------------------------------------------------
#
# Every node now runs the IDENTICAL compose template and config; there are
# no per-server files anymore. SERVER_NUM (still passed by the CI matrix)
# is informational only.

NUM="${SERVER_NUM:-?}"

COMPOSE_TEMPLATE="docker-compose.template.yml"
ACTIVE_DIR="$PWD/active-config"
LOCAL_CLIENT="overlay-client"

# Machine-local overrides live OUTSIDE the repo so they survive redeploys
# and can differ per node. To pin this node's static overlay IP:
#   echo "OVERLAY_ADDRESS=10.28.55.2" | sudo tee /etc/overlay-node.env
if [[ -f /etc/overlay-node.env ]]; then
    set -a
    # shellcheck disable=SC1091
    . /etc/overlay-node.env
    set +a
fi

# Overlay nodes derive their own IPs inside OVERLAY_CIDR from their node
# keys (unless pinned via OVERLAY_ADDRESS), so the peer's exact address is
# not known in advance. The test discovers our own IP from the client logs
# and ping-sweeps the subnet.
OVERLAY_CIDR="${OVERLAY_CIDR:-10.28.55.0/24}"
OVERLAY_ADDRESS="${OVERLAY_ADDRESS:-}"
export OVERLAY_CIDR OVERLAY_ADDRESS

TEST_MAX_WAIT="${TEST_MAX_WAIT:-360}"

# --- Helpers ----------------------------------------------------------------

info() { printf "[+] %s\n" "$*"; }
warn() { printf "[!] %s\n" "$*"; }
err()  { printf "[ERR] %s\n" "$*" >&2; }

# Podman fallback: if docker is absent but podman exists, shim it. Both the
# CLI and compose invocations go through these helpers.
if ! command -v docker >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
    docker() { podman "$@"; }
fi

dc() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    elif command -v podman-compose >/dev/null 2>&1; then
        podman-compose "$@"
    else
        err "no compose implementation found (docker compose / docker-compose / podman-compose)"
        exit 1
    fi
}

# --- Modes ------------------------------------------------------------------

cleanup_old() {
    info "Cleaning up old deployments..."

    # 1. Bring the current compose stack down with zero grace period so
    #    restart-looping containers do not delay teardown.
    if [[ -f docker-compose.yml ]]; then
        info "  - docker compose down (timeout=0, --volumes, --remove-orphans)"
        dc down --timeout 0 --volumes --remove-orphans 2>/dev/null || true
    fi

    # 2. Hard-kill then remove every overlay-* container, running or not.
    #    We kill first because "docker rm -f" on a restarting container can
    #    race with the daemon and silently leave it behind.
    local stale
    stale="$(docker ps -aq --filter 'name=^overlay-' 2>/dev/null || true)"
    if [[ -n "$stale" ]]; then
        info "  - killing stale overlay-* containers (SIGKILL)"
        # shellcheck disable=SC2086
        docker kill $stale 2>/dev/null || true
        info "  - removing stale overlay-* containers"
        # shellcheck disable=SC2086
        docker rm -f $stale 2>/dev/null || true
    fi

    # 3. Verify containers are gone; if anything survived, try once more.
    local remaining
    remaining="$(docker ps -aq --filter 'name=^overlay-' 2>/dev/null || true)"
    if [[ -n "$remaining" ]]; then
        warn "  - containers still present after first pass; retrying..."
        # shellcheck disable=SC2086
        docker kill $remaining 2>/dev/null || true
        sleep 2
        # shellcheck disable=SC2086
        docker rm -f $remaining 2>/dev/null || true
        remaining="$(docker ps -aq --filter 'name=^overlay-' 2>/dev/null || true)"
        if [[ -n "$remaining" ]]; then
            warn "  - WARNING: could not remove: $remaining"
        fi
    fi

    # 4. Forcefully disconnect all endpoints from every overlay network before
    #    removing it — "docker network rm" fails if anything is still attached.
    #    Compose names the network <project>_overlay-net; handle both forms.
    local net
    for net in overlay-net overlay-deploy_overlay-net; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            info "  - disconnecting all containers from network: $net"
            docker network inspect "$net" \
                --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null \
                | tr ' ' '\n' \
                | grep -v '^$' \
                | xargs -r -I{} docker network disconnect -f "$net" {} 2>/dev/null || true
            info "  - removing network: $net"
            docker network rm "$net" 2>/dev/null || true
        fi
    done

    # 5. Kill bare-metal binaries from the legacy /tmp/overlay-* deploy flow
    for pattern in '/tmp/overlay-tracker' '/tmp/overlay-client' '/tmp/overlay/bin/'; do
        pkill -f "$pattern" 2>/dev/null || true
    done

    # 6. Quit stale screen sessions named overlay-*
    if command -v screen >/dev/null 2>&1; then
        screen -ls 2>/dev/null | awk '/overlay-/ {print $1}' | while read -r s; do
            screen -S "$s" -X quit 2>/dev/null || true
        done
    fi

    # 7. Wipe generated state so the next deploy regenerates from scratch.
    #    chmod first so root-owned files inside active-config/ are always
    #    removable even when this step runs without sudo (e.g. future CI changes).
    chmod -R u+w "$ACTIVE_DIR" 2>/dev/null || true
    rm -rf "$ACTIVE_DIR" docker-compose.yml

    # 8. Optionally nuke images for a true from-scratch rebuild
    if [[ "${FRESH_BUILD:-0}" == "1" ]]; then
        info "  - removing overlay-* images (FRESH_BUILD=1)"
        docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
            | grep -E '^overlay-' \
            | xargs -r docker rmi -f >/dev/null 2>&1 || true
    fi

    info "Cleanup complete."
}

do_deploy() {
    info "Deploying (server${NUM}) from $PWD"
    [[ -f "$COMPOSE_TEMPLATE" ]] || { err "$COMPOSE_TEMPLATE not found"; exit 1; }

    cleanup_old

    info "Generating fresh active-config/"
    mkdir -p "$ACTIVE_DIR"
    cp config/client.yaml "$ACTIVE_DIR/client.yaml"
    cp config/trackers.txt "$ACTIVE_DIR/trackers.txt"

    # The node key persists in /etc/overlay/ across redeploys: the node's
    # identity AND its auto-derived overlay IP are computed from this key,
    # so regenerating it every deploy would give the machine a new IP each
    # time. Generated once per machine, then reused.
    if [[ ! -f /etc/overlay/node.key ]]; then
        info "  - generating persistent node key at /etc/overlay/node.key"
        mkdir -p /etc/overlay
        openssl rand -hex 32 > /etc/overlay/node.key
        chmod 600 /etc/overlay/node.key
    fi
    cp /etc/overlay/node.key "$ACTIVE_DIR/node.key"
    chmod 600 "$ACTIVE_DIR/node.key"

    # Hand ownership of active-config/ back to the invoking user so that the
    # next CI run can `rm -rf` the project folder without sudo.  When this
    # script is called via `sudo`, $SUDO_USER is the original (non-root) user.
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown -R "${SUDO_USER}:" "$ACTIVE_DIR"
    fi

    # Materialize docker-compose.yml from the shared template, pointing the
    # config mount at our generated active-config dir.
    info "Rendering $COMPOSE_TEMPLATE -> docker-compose.yml (config: $ACTIVE_DIR)"
    sed -e "s|__CONFIG_DIR__|${ACTIVE_DIR}|g" \
        "$COMPOSE_TEMPLATE" > docker-compose.yml

    if [[ ! -c /dev/net/tun ]]; then
        info "Creating /dev/net/tun"
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 2>/dev/null || true
        chmod 666 /dev/net/tun 2>/dev/null || true
    fi

    if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
        info "docker compose up -d (no rebuild)"
        dc up -d
    elif [[ "${FRESH_BUILD:-0}" == "1" ]]; then
        info "docker compose build --no-cache --pull, then up -d"
        dc build --no-cache --pull
        dc up -d
    else
        info "docker compose up -d --build"
        dc up -d --build
    fi
    dc ps
    info "Server${NUM} deployment complete."
}

do_test() {
    local sep="------------------------------------------------------------"

    info "========================================================"
    info "  Overlay test: server${NUM}  (${LOCAL_CLIENT} -> peers in ${OVERLAY_CIDR})"
    info "========================================================"
    echo

    # --- 1. Container status -------------------------------------------
    info "[ 1/4 ] Container status"
    info "$sep"
    docker ps \
        --filter "name=overlay-" \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" \
        2>/dev/null || true
    echo

    if ! docker ps --format '{{.Names}}' | grep -qx "$LOCAL_CLIENT"; then
        err "Container $LOCAL_CLIENT is not running. Deploy first."
        exit 1
    fi

    # Wait for the container to be stably running.
    # A crash-looping container briefly flickers through 'running' on each
    # restart, so we require it to hold 'running' for 3 consecutive checks
    # (spaced 2s apart) before we trust it enough to exec into it.
    info "Waiting for $LOCAL_CLIENT to be stable..."
    local wait_start wait_elapsed container_status consecutive=0
    wait_start=$(date +%s)
    while true; do
        container_status=$(docker inspect --format '{{.State.Status}}' "$LOCAL_CLIENT" 2>/dev/null || echo "missing")
        wait_elapsed=$(( $(date +%s) - wait_start ))

        if [[ "$container_status" == "running" ]]; then
            consecutive=$(( consecutive + 1 ))
            printf '  [%ds] running (%d/3 stable checks)\n' "$wait_elapsed" "$consecutive"
            if (( consecutive >= 3 )); then
                info "  Container is stable."
                break
            fi
            sleep 2
        else
            consecutive=0
            if (( wait_elapsed >= 90 )); then
                err "$LOCAL_CLIENT did not stabilise after 90s (last status: $container_status)"
                warn "Container logs:"
                docker logs --tail 40 "$LOCAL_CLIENT" 2>&1 | sed 's/^/    /'
                exit 1
            fi
            printf '  [%ds] status: %s — waiting...\n' "$wait_elapsed" "$container_status"
            sleep 3
        fi
    done
    echo

    # Install test tools inside the container so nothing runs on the host.
    # bind-tools  -> nslookup + drill for DNS lookups
    # netcat-openbsd -> nc -zu for UDP probing
    info "Installing test tools inside $LOCAL_CLIENT..."
    docker exec "$LOCAL_CLIENT" \
        apk add --no-cache bind-tools netcat-openbsd 2>&1 \
        | grep -E '(Installing|OK|ERROR)' || true
    echo

    # --- 2. Tracker reachability (runs entirely inside the container) ---
    info "[ 2/4 ] Tracker reachability  (inside $LOCAL_CLIENT -> trackers.txt)"
    info "$sep"
    docker exec "$LOCAL_CLIENT" sh << 'INNER'
trackers="/config/trackers.txt"
if [ ! -f "$trackers" ]; then
    echo "  [WARN] $trackers not found inside container — skipping"
    exit 0
fi

total=0; ok=0; dns_fail=0; udp_fail=0

while IFS= read -r line || [ -n "$line" ]; do
    # skip blank lines
    case "$line" in
        "") continue ;;
    esac

    # only handle udp:// URLs
    case "$line" in
        udp://*) ;;
        *) continue ;;
    esac

    if [ "$total" -ge 10 ]; then
        remaining=$(grep -c '^udp://' "$trackers" 2>/dev/null || echo "?")
        echo "  ... (showing first 10 of ${remaining} total)"
        break
    fi

    host=$(echo "$line" | sed 's|udp://\([^/:]*\).*|\1|')
    port=$(echo "$line" | sed 's|udp://[^:]*:\([0-9]*\).*|\1|')

    # DNS check via nslookup (from bind-tools)
    ip=$(nslookup "$host" 2>/dev/null \
        | awk '/^Address [0-9]/{ip=$3} END{print ip}')

    if [ -z "$ip" ]; then
        printf "  [DNS FAIL ] %s:%s\n" "$host" "$port"
        dns_fail=$((dns_fail + 1))
        total=$((total + 1))
        continue
    fi

    # UDP probe: nc -zu sends a UDP datagram and returns non-zero if it
    # receives an ICMP port-unreachable back. No response = OK (expected
    # for real trackers that only respond to valid announce packets).
    if nc -zu -w3 "$host" "$port" >/dev/null 2>&1; then
        printf "  [OK       ] %-40s  resolved: %s\n" "$host:$port" "$ip"
        ok=$((ok + 1))
    else
        printf "  [UDP FAIL ] %-40s  resolved: %s\n" "$host:$port" "$ip"
        udp_fail=$((udp_fail + 1))
    fi
    total=$((total + 1))
done < "$trackers"

echo ""
printf "  Result: %d OK  |  %d DNS fail  |  %d UDP fail  (of %d checked)\n" \
    "$ok" "$dns_fail" "$udp_fail" "$total"
INNER
    echo

    # --- 3. Peer / session discovery from container logs ---------------
    info "[ 3/4 ] Peer discovery — $LOCAL_CLIENT logs"
    info "$sep"

    info "  Recent logs (last 40 lines):"
    docker logs --tail 40 "$LOCAL_CLIENT" 2>&1 | sed 's/^/    /'
    echo

    info "  Peer & tracker activity lines (filtered):"
    local activity
    activity=$(docker logs "$LOCAL_CLIENT" 2>&1 \
        | grep -iE \
            'peer|session|establish|discover|announce|connect|handshake|tunnel|tracker|found|join|hello' \
        | tail -30)
    if [[ -n "$activity" ]]; then
        echo "$activity" | sed 's/^/    /'
    else
        warn "  (no peer/tracker activity lines found in logs yet)"
    fi
    echo

    # --- 4. Overlay ping test (runs inside the container) --------------
    # Nodes self-assign IPs inside OVERLAY_CIDR, so we don't know the
    # peer's address in advance. Discover our own overlay IP from the
    # client logs, then ping-sweep the /24 in parallel until any other
    # host answers.
    info "[ 4/4 ] Overlay ping sweep: ${LOCAL_CLIENT} -> ${OVERLAY_CIDR}"
    info "$sep"

    local my_ip prefix
    my_ip=$(docker logs "$LOCAL_CLIENT" 2>&1 \
        | sed -n 's/.*\[overlay\] TUN address \([0-9.]*\)\/.*/\1/p' | tail -1)
    if [[ -z "$my_ip" ]]; then
        err "could not determine local overlay IP from container logs"
        docker logs --tail 40 "$LOCAL_CLIENT" 2>&1 | sed 's/^/    /'
        return 1
    fi
    prefix="${my_ip%.*}"
    info "  Local overlay IP: ${my_ip}  (sweeping ${prefix}.1-254)"

    local start elapsed reached
    start=$(date +%s)
    while true; do
        reached=$(docker exec "$LOCAL_CLIENT" sh -c '
            prefix="'"$prefix"'"; me="'"$my_ip"'"
            for i in $(seq 1 254); do
                ip="$prefix.$i"
                [ "$ip" = "$me" ] && continue
                ( ping -c 1 -W 1 "$ip" >/dev/null 2>&1 && echo "$ip" ) &
            done
            wait' 2>/dev/null | head -5)
        if [[ -n "$reached" ]]; then
            elapsed=$(( $(date +%s) - start ))
            info "PASS — overlay is up after ${elapsed}s; reachable peer(s):"
            echo "$reached" | sed 's/^/    /'
            echo
            info "  Ping details (3 packets to first peer):"
            docker exec "$LOCAL_CLIENT" ping -c 3 -W 3 "$(echo "$reached" | head -1)" 2>&1 | sed 's/^/    /'
            return 0
        fi
        elapsed=$(( $(date +%s) - start ))
        if (( elapsed >= TEST_MAX_WAIT )); then
            err "FAIL — ${LOCAL_CLIENT} found no reachable overlay peers after ${elapsed}s"
            echo
            warn "  Full logs (last 60 lines):"
            docker logs --tail 60 "$LOCAL_CLIENT" 2>&1 | sed 's/^/    /'
            return 1
        fi
        printf '.'
        sleep 5
    done
}

do_down() {
    info "Tearing down server${NUM}"
    cleanup_old
}

# --- Dispatch ---------------------------------------------------------------

MODE="${1:-deploy}"
case "$MODE" in
    ""|deploy)         do_deploy ;;
    --test|test)       do_test ;;
    --deploy-test)     do_deploy; do_test ;;
    --down|down)       do_down ;;
    -h|--help)
        sed -n '2,/^set -euo/p' "$0" | sed -n 's/^# \{0,1\}//p'
        ;;
    *)
        err "unknown mode: $MODE"
        exit 2
        ;;
esac