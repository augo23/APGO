# Running APGO natively on macOS (experimental)

The same Go client now builds and runs on macOS as a first-class overlay node —
the Mac gets its own overlay IP on a `utun` interface, just like a Linux node.
This is **Stage 1** (the data plane). A menu-bar app to drive it is Stage 2.

> Status: this path can't be built/tested in CI here — it needs a Mac. Treat it
> as experimental and expect to iterate. If a tunnel comes up but no traffic
> flows, the first thing to check is the utun 4-byte address-family header
> handling in `client/tun_darwin.go`.

## Build

On the Mac (Go 1.22+; no cgo required):

```bash
cd client
go build -o overlay-client .
```

Build tags select the platform automatically: `tun_darwin.go` (utun +
ifconfig/route) is used on macOS, `tun_linux.go` (TUN + netlink) on Linux.

## Configure

Create a `client.yaml` somewhere writable, e.g. `~/.apgo/client.yaml`:

```yaml
network_name: "my-overlay-CHANGE-ME"     # same on every node
psk: "base64:<the network PSK>"          # same on every node
overlay_cidr: "10.28.55.0/24"            # same on every node
node_private_key: "/Users/you/.apgo/node.key"   # created on first run
udp_listen_port: 6969
cipher: "aesgcm"
tun:
  mtu: 1280

# Optional: pin this node's overlay IP instead of deriving it from the key
# tun:
#   address_cidr: "10.28.55.9/24"
```

To join an existing network, use the **same** `network_name`, `psk`,
`overlay_cidr`, and `cipher` as your other nodes. To let this Mac be
managed by the admin dashboard's network revocations, also set
`ADMIN_PUBLIC_KEY` (below) to the same value as the rest of the fleet.

## Run

Creating a `utun` device, assigning an address, and adding a route all require
root, so run with `sudo`:

```bash
sudo CLIENT_CONFIG=~/.apgo/client.yaml \
     ADMIN_PUBLIC_KEY=<optional, from `overlay-admin genkey`> \
     ./overlay-client
```

You should see `TUN utunN created (macOS utun)`, then an overlay IP assignment
and the usual tracker/STUN/handshake logs. Verify with:

```bash
ifconfig utun<N>            # shows your overlay IP
ping 10.28.55.X            # another node's overlay IP
```

To stop: Ctrl-C (the route and interface are torn down by the kernel when the
process exits).

## Notes & limitations

- **Root required.** The menu-bar app (Stage 2) will run the data plane through
  a small privileged helper so you don't invoke `sudo` by hand.
- **No Docker.** This runs the client directly on the Mac; there's no container.
- **Firewalling.** macOS has no `ovl0`-style default filtering — anyone on the
  overlay can reach open ports on your Mac. Use the macOS firewall / `pf` if
  that matters, the same way the Linux guide suggests `iptables` on `ovl0`.
- **IPv6** overlay addresses are not supported; the overlay is IPv4.
