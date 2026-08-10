# Guest Networks (secondary networks)

Status: **implemented** for the Go client (Linux/containers), the admin web
dashboard, and the desktop (macOS/Windows) app. iOS/Android are planned — the
share-record machinery is mobile-ready (records ride the main mesh), but the
mobile clients don't yet run secondary network instances.

## What it gives you

A node can belong to several overlay networks at once. A "guest network" is
simply a second network with its own `network_name`, its own **separate PSK**,
and its own `overlay_cidr` (its own virtual subnet):

- **Not every device is exposed.** A device is reachable by guests only if it
  runs the guest network's profile. Isolation is cryptographic, not
  firewall-based: the PSK is bound into every Noise handshake (prologue +
  XXpsk0), so a guest cannot even complete a handshake with an unshared
  device — and tracker discovery is per-network (`SHA1(network_name)`), so it
  can't find one either.
- **Per-device sharing from any admin panel.** Editing a node offers a
  checkbox per secondary network: share / unshare that one device.
- **Revocable.** Kick one guest with the existing signed revocation; revoke
  the whole guest PSK by removing the network (or rotating name + PSK
  together, which also changes the tracker infohash).
- **Guest exits.** A guest-network device can serve as a VPN exit node
  ("exit" checkbox when sharing), and any device can route its internet
  traffic through an exit on a guest network ("Use as VPN exit" on the
  network). That's the untrusted-datacenter-VPS pattern: the VPS joins ONLY
  the guest network, sees ONLY the devices you shared, yet can still carry
  your full-tunnel VPN traffic. It never holds your main network's PSK.

## Architecture: instance-per-network under one supervisor

Each ADDITIONAL network runs as a supervised **child process** of the client
(same binary, re-exec'd) with its own generated config, TUN interface, UDP
port, control socket, and state directory (`client/multinet.go`). This is the
two-clients-on-one-host pattern ([two-nodes-same-host.md](two-nodes-same-host.md))
made automatic, and it keeps every single-network invariant intact: no state
is shared between networks, and a crash in one cannot take down another.

- The node **key is shared** (one stable device identity); the overlay IP
  still differs per network because each network derives it inside its own
  CIDR (`deriveOverlayIP`).
- Children scrub/override env (`CLIENT_CONFIG`, `CONTROL_SOCKET`,
  per-network `*_FILE` paths) and tag log lines `[net:<id>]`. The child's
  control socket is `<main socket>.<id>`, so panels can reach every network.
- A network's id is the first 8 hex chars of `SHA-256(network_name)`; its
  default UDP port is derived from the name (stable NAT mappings), and its
  default TUN name is `apg<id[:4]>`.
- **Exactly one network** (main or secondary) may set `use_exit` — the
  full-VPN default route can only point one way. The supervisor enforces it.
- The parent seeds each child's admin trust (`admin.pub` + sealed admin key)
  so the SAME admin key governs guest networks: admission control,
  revocation, and provisioning all work per-network from the same dashboard.

Secondary networks come from three sources, merged at reconcile (first
definition of a name wins): the config file's `networks:` list, networks
added at runtime via the panel (persisted under `<state>/networks/<id>/`),
and networks this device was **shared into** by a signed record.

### Config file form

```yaml
# main network stays top-level — fully backward compatible
network_name: "home-lab"
psk: "base64:…A…"
overlay_cidr: "10.22.55.0/24"

networks:
  - network_name: "home-lab.guest-8f2k1c9d"
    psk: "base64:…B…"
    overlay_cidr: "10.22.56.0/24"
    # optional: tun_name, mtu, udp_listen_port, cipher, post_quantum, pq_auth,
    # static_peers, rendezvous_servers, trackers, enabled,
    # exit_node (BE an exit there), use_exit + exit_peer (route MY internet
    # through that network's exit)
```

A config without `networks:` behaves exactly as before.

## Share / unshare records (`client/netshare.go`)

"Share device X into network Y" is an admin-signed record flooded across the
MAIN network like revocations:

	OVLYCTL1 S <json>    — SignedNetShare gossip

- Signed by the network admin key (ML-DSA, same trust root as revocations);
  canonical bytes `OVLYNETSHARE1|action|pubkey|network|cidr|port|exit|digest|seq|ts`.
- The guest PSK never travels readable, even inside the encrypted tunnel: it
  is **sealed to the target's X25519 static key** (ephemeral-static ECDH +
  AES-256-GCM, key = SHA-256("APGO-NETSHARE-SEAL-1|" ‖ shared ‖ ephPub ‖
  targetPub); blob = ephPub ‖ nonce ‖ ct). Relaying nodes carry ciphertext
  they cannot open. The construction is stdlib-only and duplicated
  byte-for-byte in `admin/networks.go` and `desktop/multinet.go`.
- Records persist (`NETSHARES_FILE`) and re-flood on the heavy gossip tick,
  so a target that was offline picks the share up later from any node.
- The target's main instance applies it: persists the profile
  (origin: "shared"), starts/stops the child. `unshare` removes it.
  Replay-guarded per target+network by `Seq`; only main instances process
  the frame.

## Control API (client, local socket)

`/api/networks` (list incl. run state), `/api/network-add` (mode `join` |
`create` — create generates name + PSK via the existing generator and returns
them for the invite), `/api/network-remove`, `/api/network-set`
(enable/disable, `use_exit`, `exit_peer`, `exit_node`), `/api/network-profile`
(full profile incl. PSK — same exposure class as `/api/join-info`),
`/api/netshare-signed` (verify + store + flood + apply), `/api/netshares`.
Per-network data goes through the child's own socket (sessions, approvals,
revocations, exits — the panels pass `?net=<id>` / `"net"` in the body).

## Panel UX (admin dashboard + desktop app)

- **Connected nodes** is a collapsible section (with a live count).
- Beneath it: one collapsible section per secondary network (name, CIDR,
  running/disabled, exit badges, its own session table with per-network
  Approve/Revoke), then an **“+ Add Network”** button.
- Add Network asks to **Join existing** (name + PSK) or **Create — be the
  initiator** (name/PSK generated; invite details shown for QR/copy). Subnet
  defaults to the next free `10.22.x.0/24`.
- **Editing a node** (when secondary networks exist) shows a checkbox per
  network — share/unshare that device — plus a per-network **“exit”**
  checkbox to offer the device as a VPN exit there. Changes are signed with
  the admin password and gossiped; the target applies them itself.
- Each network row has **“Use as VPN exit”** to route this device's internet
  traffic through that network's exit (full VPN), enforced one-network-only.

## Security notes

- A guest PSK is a shared secret: assume it spreads beyond the invitees.
  Admission control (same admin key, per network) is the per-identity
  backstop; removing/rotating the network is the reset lever. Rotation must
  change name + PSK together, or ex-guests can still enumerate endpoints via
  the unchanged tracker infohash.
- Guests see and reach each other (they are one mesh) and the shared
  devices — nothing else. Guest-to-guest isolation would be a per-network
  policy flag (future work).
- No forwarding is ever enabled between overlay TUNs; a guest packet
  terminates at the shared device.
- Guest networks inherit the main network's cipher/PQ posture by default.
- The main network's PSK, member roster, and admin private key never appear
  in any guest-side artifact.

## Platform notes

- **Containers/Linux**: works with the stock compose stack; per-network state
  lives under `/state/networks/`. No compose changes required.
- **Desktop**: the client is launched with `APGO_NETWORKS_DIR` and
  `NETSHARES_FILE` under `~/.apgo/`; the tray's existing network *profiles*
  (switch the MAIN network) are unchanged and coexist with concurrent
  secondary networks.
- **iOS/Android**: pending. NetworkExtension/VpnService allow only one TUN
  per app, so mobile needs a multiplexed-TUN variant of the supervisor
  rather than child processes.
