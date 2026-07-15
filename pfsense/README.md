# APGO for pfSense

Runs the same headless overlay client as the Docker container, natively on
pfSense (FreeBSD) — the router becomes a node on your mesh, so every device
on the mesh can reach it (and, with a couple of GUI rules, the LAN behind it).

The FreeBSD data plane lives in `client/tun_freebsd.go` (wireguard-go's tun
device + ifconfig/route), added alongside the Linux/macOS/Windows ones.

## Install

1. **Build** (any machine with Go ≥ 1.23; cross-compiles, no FreeBSD needed):

   ```
   bash pfsense/build-freebsd.sh              # amd64
   ARCH=arm64 bash pfsense/build-freebsd.sh   # Netgate ARM appliances
   ```

2. **Enable SSH** on pfSense (System → Advanced → Secure Shell), then:

   ```
   bash pfsense/install-pfsense.sh admin@<router-ip> [amd64|arm64]
   ```

   This installs `/usr/local/bin/overlay-client`, the boot service
   `/usr/local/etc/rc.d/apgo.sh`, and a sample config.

3. **Configure**: edit `/usr/local/etc/apgo/client.yaml` — set `network_name`
   and `psk` to the same values as your other devices (Diagnostics → Command
   Prompt → Edit File works too). Then:

   ```
   service apgo.sh start
   ```

   Log: `/var/log/apgo.log`. The router appears in every admin panel like any
   other node, with a stable overlay IP on `ovl0`.

## Firewall (pfSense GUI)

- **Allow the transport in**: Firewall → Rules → WAN — pass UDP to
  `udp_listen_port` (default 6969). Optional but makes this router directly
  reachable (it can then act as the well-connected node that relays for
  phones behind hard NATs). Without it, outbound hole-punching still works.
- **Allow overlay traffic**: Interfaces → Assignments — assign `ovl0` as an
  optional interface (e.g. `APGO`), enable it (no address — the client
  manages that), then Firewall → Rules → APGO — pass what you want overlay
  peers to reach (the router itself, or hosts on LAN).
- **Reach the LAN behind the router** (advanced): overlay peers reach the
  router itself out of the box. To reach devices behind it, add on the peer a
  static route for the router's LAN subnet via the router's overlay IP
  (e.g. `route add -net 192.168.1.0/24 10.28.55.1`), pass that traffic in the
  APGO interface rules, and add an Outbound NAT rule on LAN for the overlay
  subnet so replies return (or add a matching static route on LAN hosts).

## Exit node (full-VPN outproxy)

`exit_node: true` works, but unlike Linux the NAT isn't set up automatically
(that path uses iptables). Add it in the GUI once: Firewall → NAT → Outbound
→ switch to Hybrid mode, and add a rule translating source =
your `overlay_cidr` (e.g. `10.28.55.0/24`) → WAN address. Devices that enable
"Route all traffic via an exit node" will then egress through your pfSense
WAN.

## Updates & pfSense upgrades

pfSense OS upgrades can remove custom files under `/usr/local`. Keep the
built binary around and re-run `install-pfsense.sh` after an upgrade (your
`client.yaml` and node key in `/usr/local/etc/apgo/` are preserved unless the
upgrade wipes `/usr/local/etc` — take a backup of that folder to be safe).
