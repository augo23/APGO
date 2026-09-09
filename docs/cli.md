# APGO command-line reference

Every command in the repository, what it does, and every flag and environment
variable it reads.

**The first thing to know:** the APGO binaries take almost no flags. The client
has none at all — it is configured entirely by a YAML file and environment
variables, because it is built to run identically from a container, a systemd
unit, an OpenWrt init script and a desktop app. The `--flags` in this document
belong to the *build and install scripts*, not to the daemons.

| You want to… | Command |
|---|---|
| Run a node on Linux | `./easy-deploy.sh` |
| Run a node on macOS / Windows | `bash macos/install-macos.sh` / `windows\install.cmd` |
| Create the network admin key | `overlay-admin genkey` |
| Ask a running node anything | `curl --unix-socket <control.sock> http://x/api/info` |
| Build every installer and publish | `./build-release.sh` |

---

## 1. `overlay-client` — the node daemon

The overlay engine: TUN device, tracker/DHT discovery, STUN, hole punching,
Noise sessions, relaying, exits.

```bash
overlay-client            # no arguments, no flags
```

It reads `$CLIENT_CONFIG` (default `/config/client.yaml`), then lets environment
variables override anything the file set. **A missing config file is not an
error** — a node can be configured entirely from the environment, which is how
the container and Kubernetes deployments work. Two nodes are on the same network
if and only if they agree on `NETWORK_NAME` and `PSK`.

Started with no network name and no PSK, the client runs a one-shot **setup
server** on its control socket instead of joining anything: it waits for a
desktop app or dashboard to post a configuration, persists it, and exits so the
supervisor restarts it configured.

Requires `/dev/net/tun` (Linux), and root or `CAP_NET_ADMIN` to create the
interface and routes.

### Network identity — must match on every node

| Variable | Default | Meaning |
|---|---|---|
| `NETWORK_NAME` | — | The network. Hashed to the tracker info-hash (`SHA1(network_name)`). |
| `PSK` | — | Pre-shared key, `base64:…`. Mixed into the Noise prologue: without it a handshake cannot complete even for a peer that finds you. |
| `OVERLAY_CIDR` | `10.22.55.0/24` | The overlay subnet every node addresses inside. |
| `CLIENT_CONFIG` | `/config/client.yaml` | Path to the YAML config. |

### Identity and address of this node

| Variable | Default | Meaning |
|---|---|---|
| `NODE_KEY_FILE` | `/state/node.key` | This node's X25519 private key. **Its overlay identity.** Lose it and the node rejoins as a stranger — a new fingerprint, and on a network with admission control it lands back in "pending". Back this file up. |
| `OVERLAY_ADDRESS` | derived | Pin this node's overlay IP (`10.22.55.5/24`). Blank derives it from the node key. A pinned address is never moved automatically. |
| `FRIENDLY_NAME` | hostname | The name shown next to this node in dashboards. |
| `ADVERTISE_PORT` | — | The port to publish to peers when it differs from the local listen port (Kubernetes `hostPort`, manual port-forward). |
| `KEEPALIVE_SECONDS` | `10` | Keepalive interval; clamped to 5–120. |

### Discovery

| Variable | Default | Meaning |
|---|---|---|
| `TRACKERS_FILE` | `/state/trackers.txt` | Tracker list. |
| `DHT` | on | BitTorrent DHT discovery (`1`/`0`). |
| `DHT_PUBLIC_KEY` | off | Publish under a public-key topic rather than the plain info-hash. |
| `DHT_STATE_FILE` | beside the node state | Persisted DHT routing table. Derived from `NODE_SETTINGS_FILE` when unset. |
| `RENDEZVOUS_SERVERS` | — | Space-separated HTTPS discovery URLs, for networks that block BitTorrent. |
| `RENDEZVOUS_USER` / `RENDEZVOUS_PASSWORD` | — | Basic-auth credentials for those servers. |
| `RENDEZVOUS_TOKEN` / `RENDEZVOUS_AUTH` | — | Bearer token form of the same. |
| `EXTRA_CANDIDATES` | — | Extra `ip:port` candidates to advertise (a known public address). |
| `SELF_ENDPOINTS_FILE` | beside the node state | Remembered own endpoints, for faster reconnect. |
| `CONTROLLER_BASE_URL` | — | Optional external controller to fetch bootstrap data from. |

### Transport and crypto

| Variable | Default | Meaning |
|---|---|---|
| `POST_QUANTUM` | `1` | ML-KEM layer over the Noise session. |
| `PQ_AUTH` | `1` | Quantum-resistant handshake authentication. **Changes the wire format — keep the fleet consistent.** |
| `IPV6` | `1` | Dual-stack transport; direct IPv6 where both ends have it. |
| `PORT_PREDICTION` | `1` | Symmetric-NAT/CGNAT port prediction. Only used behind a symmetric NAT. |

Cipher (`chacha` default, or `aesgcm`), MTU, compression and the UDP listen port
(`6969`) are YAML-only keys: `cipher`, `mtu`, `compression`, `udp_listen_port`.
`cipher` must be identical network-wide or handshakes fail.

### Relaying and exits

| Variable | Default | Meaning |
|---|---|---|
| `USE_PUBLIC_RELAYS` | on | Use volunteer public relays when a direct path fails. |
| `PUBLIC_RELAY` | off | Offer THIS node as a public relay. |
| `STATIC_RELAYS` | — | Explicit relay endpoints. |
| `RELAY_UP_LIMIT` / `RELAY_DOWN_LIMIT` | — | Bandwidth caps for relayed traffic. |
| `RELAY_QUOTA` / `RELAY_QUOTA_DAYS` | — | Volume cap over a rolling window. |
| `RELAY_MAX_CIRCUITS` / `RELAY_MAX_PER_IP` / `RELAY_PER_CIRCUIT_LIMIT` | — | Relay fairness limits. |
| `RELAY_STATE_FILE` | beside the node state | Relay accounting. Derived from `NODE_SETTINGS_FILE` when unset. |
| `EXIT_NODE` | off | Make this node an internet exit (needs NAT/firewall setup — see the README). |
| `USE_EXIT` | off | Send *this* node's internet traffic out through a mesh exit. |
| `EXIT_PEER` | — | Pin a specific exit instead of the fastest. |
| `EXIT_STATE_FILE` | beside the relay state | Exit bandwidth accounting. |
| `SOCKS5_LISTEN` | — | Serve a SOCKS5 proxy on this address. |
| `SOCKS5_USER` / `SOCKS5_PASS` | — | Credentials for it. |
| `SOCKS5_OVERLAY_ONLY` | — | Restrict the proxy to overlay destinations. |

### Admission control, admin key, state

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_PUBLIC_KEY` | — | Pin the network admin public key instead of learning it on first use. |
| `ADMIN_PUBKEY_FILE` | `/state/admin-pubkey` | Where the learned/pinned key is stored. |
| `SEALED_ADMIN_KEY_FILE` | `/state/admin-key-sealed.json` | The password-encrypted admin key, gossiped so any node's panel can sign given the password. |
| `APGO_RESET_ADMIN` | — | One boot with this set wipes the admin key on this node. Reset every node together, or a peer re-seeds the old key. |
| `ADMISSION_ENFORCE` | auto | Force blocking of unapproved peers on or off. Unset, enforcement turns on once this node holds its first approval record. |
| `APPROVALS_FILE` | `/state/approvals.json` | Signed admission records. |
| `REVOCATIONS_FILE` | `/state/revocations.json` | Signed revocations. |
| `REVOCATION_TTL_SECONDS` | — | How long a revocation is re-gossiped. |
| `PROVISIONS_FILE` | `/state/provisions.json` | Admin address/name assignments. |
| `POLICY_FILE` | `/state/policy.json` | Signed network policy. |
| `NETCONFIG_FILE` | `/state/netconfig.json` | Admin-pushed network config. |
| `NETSHARES_FILE` | `/state/netshares.json` | Shared-subnet records. |
| `NODE_CONFIG_FILE` / `NODE_SETTINGS_FILE` | `/state/…` | Per-node settings set from a dashboard. |
| `SETUP_FILE` | `/state/setup.json` | Config captured by the first-run setup server. |

### Plumbing

| Variable | Default | Meaning |
|---|---|---|
| `CONTROL_SOCKET` | — | Unix socket for the local control API (below). Also how the client detects a second copy of itself. |
| `LOG_FILE` | stderr | Log destination. |
| `APGO_NETWORKS_DIR` | — | Root for secondary-network profiles. |
| `APGO_NET_CHILD` | — | Set by the parent when it spawns a per-network child. Not for hand use. |

### The control API

Every dashboard action is an HTTP call on the control socket, so anything the UI
can do is scriptable:

```bash
SOCK=/shared/control.sock                  # containers
SOCK=~/.apgo/control.sock                  # macOS / Windows desktop

curl --unix-socket $SOCK http://x/api/info      | jq   # this node: IP, key, NAT, PQ, conflicts
curl --unix-socket $SOCK http://x/api/sessions  | jq   # peers, paths, traffic
curl --unix-socket $SOCK http://x/api/exits     | jq   # known exit nodes + RTT
curl --unix-socket $SOCK http://x/api/revocations | jq
```

Read endpoints: `/api/info`, `/api/sessions`, `/api/exits`, `/api/discovery`,
`/api/trackers`, `/api/revocations`, `/api/netshares`, `/api/node-config`,
`/api/rendezvous-config`, `/api/join-info`, `/api/net-epoch`, `/api/gen-psk`.

Write endpoints take JSON POSTs and, where they change network-wide state,
require an admin signature: `/api/revoke`, `/api/revoke-signed`,
`/api/approve-signed`, `/api/provision-signed`, `/api/policy-signed`,
`/api/network-config-signed`, `/api/netshare-signed`, `/api/exit-pin`,
`/api/set-ipv6`, `/api/set-admin-pubkey`, `/api/admin-key-sealed`,
`/api/local-restore`.

---

## 2. `overlay-admin` — the dashboard

```bash
overlay-admin              # serve the dashboard
overlay-admin genkey       # create the network admin key; password on stdin
```

`genkey` is the one real subcommand in the project. It reads the password from
stdin, writes the password-encrypted signing key, and prints the public key:

```bash
printf 'my-admin-password' | overlay-admin genkey
```

The password cannot be recovered, and every revoke, approve and address
assignment needs it.

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_LISTEN` | `:8088` | Listen address. Normally pinned to the node's overlay IP so the panel exists only on the overlay. |
| `ADMIN_USER` | `admin` | Dashboard username. |
| `ADMIN_PASSWORD` | — | Dashboard password. Blank means the first visitor creates the login. |
| `ADMIN_CREDS_FILE` | `/adminkey/credentials.json` | Stored dashboard login. |
| `ADMIN_KEY_FILE` | `/adminkey/admin.key` | The encrypted network admin signing key. |
| `ADMIN_THROTTLE_FILE` | `/adminkey/login-throttle.json` | Brute-force backoff state, kept across restarts. |
| `ADMIN_TLS_CERT` / `ADMIN_TLS_KEY` | — | Serve HTTPS instead of HTTP. |
| `CONTROL_SOCKET` | `/shared/control.sock` | The client to drive. |
| `LOG_FILE` | `/shared/overlay-client.log` | The client log to display. |

---

## 3. `rendezvous` — HTTPS discovery server

An alternative to public trackers for networks that block BitTorrent. One tiny
binary, no database.

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Listen address. |
| `PEER_TTL_SECONDS` | `300` | How long an announced peer stays listed. |
| `AUTH_USERS` | — | `user:password` pairs for basic auth. |
| `AUTH_TOKENS` | — | Accepted bearer tokens. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | Serve HTTPS directly instead of behind a proxy. |

Endpoints: `/api/rendezvous` (announce + fetch), `/api/auth-check`, `/healthz`.

---

## 4. Desktop app (macOS / Windows)

The tray/menu-bar app supervises a bundled `overlay-client` and serves the same
dashboard locally. It has no command-line interface; it reads one variable:

| Variable | Meaning |
|---|---|
| `OVERLAY_CLIENT_BIN` | Path to the client binary to supervise, instead of the bundled one. |

Everything lives in `~/.apgo` (`%USERPROFILE%\.apgo` on Windows): `node.key`,
`client.yaml`, `control.sock`, `provisions.json`, `revocations.json`,
`approvals.json`, `admin-key-sealed.json`, `overlay-client.log`.

**`node.key` is the machine's identity on the overlay.** Copy it before wiping a
machine; without it, a reinstall rejoins as a new device.

---

## 5. Running a node with containers

```bash
./easy-deploy.sh              # build both images, start the stack
./easy-deploy.sh --rebuild    # force a no-cache rebuild, then start
./easy-deploy.sh --down       # stop and remove the stack
```

Auto-detects podman or docker. The first run writes `.env` with a fresh `PSK`
and a random dashboard password and prints them; **copy `NETWORK_NAME` and `PSK`
to every other node.** Everything in `.env` is passed through to the containers,
so any client variable from §1 can be set there.

```bash
podman compose -f easy-compose.yml logs -f client   # follow the node log
podman compose -f easy-compose.yml restart client
podman exec overlay-client sh -c 'ip addr show ovl0'
```

The dashboard is published on `127.0.0.1:8788` — put a reverse proxy in front to
expose it. `apgo.yaml` / `compose.yml` are the fuller multi-service variants.

---

## 6. Platform installers

### macOS

```bash
bash macos/install-macos.sh          # build + install /Applications/APGO.app
bash macos/install-macos.sh --fresh  # ALSO delete ~/.apgo (new node identity)
bash macos/build.sh                  # just build the .app, no install
bash mac-ios-easy.sh                 # iOS xcframework + project, then install the Mac app
```

`--fresh` is not the default on purpose: it discards `node.key`, so the Mac
rejoins as an unknown device and, with admission control on, waits in "pending"
until an admin re-approves it.

### Windows

```bat
windows\install.cmd
```

```powershell
powershell -File windows\install.ps1 -Fresh    # also wipe ~\.apgo (new identity)
powershell -File windows\install.ps1 -SkipGo   # fail rather than download Go
```

Installs to `%LOCALAPPDATA%\APGO` with a startup shortcut. No admin rights to
install; the client elevates via UAC when you press Connect.

### pfSense / OPNsense (FreeBSD)

```bash
bash pfsense/build-freebsd.sh                              # amd64
ARCH=arm64 bash pfsense/build-freebsd.sh                   # Netgate 2100/3100
bash pfsense/install-pfsense.sh admin@192.168.1.1 [amd64|arm64]
```

Cross-compiles from any machine with Go — no FreeBSD host needed. The installer
copies the binary, `client.yaml` and `pfsense/apgo.rc` over SSH (enable SSH under
System → Advanced → Secure Shell first). One FreeBSD build serves both pfSense
and OPNsense.

### OpenWrt

Built as a normal OpenWrt package from `openwrt/apgo` (`GO_PKG` points at
`client/`), configured through UCI rather than environment variables:

```sh
uci set apgo.main.enabled='1'
uci set apgo.main.network_name='my-net'
uci set apgo.main.psk='base64:…'
uci commit apgo && /etc/init.d/apgo restart
```

UCI options mirror §1: `friendly_name`, `overlay_cidr`, `overlay_address`,
`udp_listen_port`, `mtu`, `post_quantum`, `pq_auth`, `ipv6`, `cipher`,
`use_exit`, `exit_peer`, `exit_node`, `rendezvous_servers`.

### Android

```bash
bash android/build-apk.sh    # installs every prerequisite, then builds a debug APK
bash android/build-aar.sh    # just the Go core → app/libs/overlaymobile.aar
```

Output: `android/app/build/outputs/apk/debug/app-debug.apk`. `APGO_VERSION=`
names the build (`build-release.sh` sets it from the newest git tag).

### iOS

```bash
bash ios/build-xcframework.sh   # installs prerequisites, builds Overlaymobile.xcframework
bash ios/bump-build.sh          # bump version + build number
cd ios && xcodegen generate && open APGO.xcodeproj
```

Needs a Mac with the full Xcode app. Both mobile apps bind the **same** Go core
in `ios/core` — a vendored copy of `client/`, so a core fix has to be mirrored
into it.

---

## 7. Release tooling

```bash
./build-release.sh                    # build every installer, publish, cut the next patch version
./build-release.sh --no-bump          # rebuild the current version
./build-release.sh --no-push          # build only; inspect release/ first (never bumps)
./build-release.sh --push-only        # push the staged release/ without rebuilding
./build-release.sh --torrent-only     # regenerate torrents/magnets/manifest from the existing payload
./build-release.sh --restore-payload  # re-download the published payload into release/APGO/
./build-release.sh --publish          # legacy: upload straight to the release API (needs FORGEJO_TOKEN)
./build-release.sh --publish-only     # publish what is already staged
./build-release.sh --bump patch|minor|major|X.Y.Z   # cut a tag and stop
```

| Variable | Meaning |
|---|---|
| `APGO_BUMP` | Bump level for a normal build: `patch` (default), `minor`, `major`, or `X.Y.Z`. |
| `APGO_VERSION` | Name this build explicitly; suppresses the bump. |
| `FORGEJO_TOKEN` | Only needed for the direct `--publish` paths. |

`--torrent-only` exists because the info-hash is computed over the payload, not
the announce URLs: regenerating from an unchanged payload keeps the same
info-hash, so published magnets and tracker registrations stay valid. Do not run
this script with sudo.

```bash
./push-github.sh [url]    # publish a filtered snapshot to GitHub
```

Pushes a single squashed snapshot commit with private paths (the ones holding
the PSK) removed — `git push` would publish them in history.

---

## 8. Diagnostics

```bash
curl --unix-socket $SOCK http://x/api/info | jq '{overlay_ip, key_fp, nat_type, self_approved, ip_conflict}'
```

| Symptom | What to look at |
|---|---|
| Peers listed, nothing reachable | `self_approved` in `/api/info` — an unapproved node's data is dropped while its control traffic flows, so it looks connected. |
| Overlay IP is not the one you set | `ip_conflict` in `/api/info` — an address another node held is vacated automatically and the banner says where it went. |
| "Already in use" after a reinstall | `ip_conflict.stale` — a leftover claim from the old node key. Re-provision the address onto `ip_conflict.self_fp`. |
| Everything relayed | `nat_type` — two symmetric NATs cannot punch; traffic still flows, with one extra hop. |
| Nothing found on the same Wi-Fi | `lan_targets` / `lan_peer` — zero targets means no local addresses; targets with no peer usually means AP/client isolation. |
