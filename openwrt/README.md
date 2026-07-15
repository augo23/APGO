# APGO for OpenWrt

Runs the same headless overlay client as the Docker container, natively on
OpenWrt — the router becomes a node on your mesh. Configured through UCI
(`/etc/config/apgo`), supervised by procd, same YAML core underneath.

## Build the .ipk

Use the OpenWrt SDK matching your router's release + target (download from
https://downloads.openwrt.org, e.g. `openwrt-sdk-23.05.*`):

```
cp -r openwrt/apgo <sdk>/package/apgo
cd <sdk>
./scripts/feeds update -a
./scripts/feeds install -a          # pulls the golang build support
make defconfig
make package/apgo/compile V=s
```

The package lands in `bin/packages/<arch>/base/apgo_*.ipk`. Notes:

- The Makefile fetches a tagged GitHub release. First build: it will print
  the tarball hash — paste it into `PKG_HASH`. For local hacking, set
  `USE_SOURCE_DIR` to your checkout instead.
- Go binaries are ~10 MB even stripped — fine for most routers with 16 MB+
  flash or an external overlay; too big for 8 MB devices.

## Install & configure

```
scp bin/packages/<arch>/base/apgo_*.ipk root@router:/tmp/
ssh root@router opkg install /tmp/apgo_*.ipk

ssh root@router
uci set apgo.main.enabled='1'
uci set apgo.main.network_name='your-network-name'
uci set apgo.main.psk='base64:...'
uci commit apgo
/etc/init.d/apgo enable
/etc/init.d/apgo start
logread -e apgo -f          # watch it join
```

The router appears in every admin panel like any other node, with a stable
overlay IP on `ovl0`. The node key and managed state live in `/etc/apgo/`
(preserved across reboots and sysupgrade if you add `/etc/apgo/` to
`/etc/sysupgrade.conf`).

## Firewall

- **Transport in (optional but recommended)**: allow UDP `6969` on WAN so
  this router is directly reachable — it then acts as the well-connected
  node that relays for phones behind hard NATs:

  ```
  uci add firewall rule
  uci set firewall.@rule[-1].name='APGO'
  uci set firewall.@rule[-1].src='wan'
  uci set firewall.@rule[-1].proto='udp'
  uci set firewall.@rule[-1].dest_port='6969'
  uci set firewall.@rule[-1].target='ACCEPT'
  uci commit firewall && /etc/init.d/firewall reload
  ```

- **Overlay zone**: to let overlay peers reach the router (or LAN), cover
  `ovl0` with a zone:

  ```
  uci add firewall zone
  uci set firewall.@zone[-1].name='apgo'
  uci set firewall.@zone[-1].device='ovl0'
  uci set firewall.@zone[-1].input='ACCEPT'
  uci set firewall.@zone[-1].forward='REJECT'
  uci set firewall.@zone[-1].output='ACCEPT'
  uci commit firewall && /etc/init.d/firewall reload
  ```

  Add a forwarding from `apgo` to `lan` if overlay peers should reach LAN
  devices (peers also need a route for your LAN subnet via this router's
  overlay IP).

## Exit node

`exit_node: true` NAT setup in-process uses iptables; on modern
(nftables-based) OpenWrt either install `iptables-nft`, or add the
masquerade yourself: enable `masq` on the `wan` zone for the overlay subnet
(`uci set firewall.@zone[1].masq_src='10.28.55.0/24'` style) and forward
`apgo` → `wan`.
