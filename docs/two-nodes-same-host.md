# Two overlay nodes on one machine: making them peer (and outproxy) each other

## Situation

One physical machine runs **two** overlay nodes, both on host networking:

| node            | overlay IP    | udp_listen_port | tun  |
|-----------------|---------------|-----------------|------|
| Kubernetes      | 10.22.55.22   | 6970            | ovl0 |
| Podman/standalone | 10.22.55.3  | 6969            | ovl1 |

Both come up fine, and each is reachable from the Mac and from inside the
cluster. The **only** thing that doesn't work: the two nodes can't tunnel to
each other, so neither can act as an outproxy/exit for the other.

## Why (it is not discovery, ports, or crashes)

The two nodes never form an overlay **session** with each other. Two mechanisms
that normally help same-LAN peers both defeat themselves here:

- **Same-site direct dials are suppressed.** `connectToPeer` skips a candidate
  whose IP equals our own public IP (NAT-hairpin traps desync the session), and
  only tries a last-resort hairpin after a 60s grace. Both nodes share the
  machine's single public IP, so each treats the other as "same-site" and holds
  off.
- **Same-host LAN discovery can't fire.** LAN discovery relies on broadcast /
  sweep on the physical NIC, but both nodes share the host's IPs, so each sees
  the other's beacon coming from one of *its own* addresses and drops it as
  self; the infohash-derived discovery port also can't be bound twice in the
  one host netns.

With no session between them, there's no route for one node's traffic to reach
the other over the overlay — which is exactly what an outproxy needs.

## Fix: pin them to each other with `static_peers` over loopback

`static_peers` are dialed directly (`connectToPeer`) and bypass the tracker/PEX
filters that reject loopback/private/same-site addresses — so a loopback static
peer actually establishes. Because both nodes share the host network namespace,
each can reach the other's transport on `127.0.0.1:<other-port>`.

In each node's `client.yaml` add the **other** node's port:

```yaml
# Kubernetes node (10.22.55.22, listens on 6970) — point at the podman node:
static_peers:
  - "127.0.0.1:6969"
```

```yaml
# Podman node (10.22.55.3, listens on 6969) — point at the k8s node:
static_peers:
  - "127.0.0.1:6970"
```

For the K8s node the config is the inline `client.yaml` block in `apgo.yaml`
(the deployment already sets `udp_listen_port: 6970` there). For the podman node
it's the mounted `config/client.yaml`.

Restart both. You should see `handshake to 127.0.0.1:69xx established` in each
node's log, both nodes then appear in each other's peer list, and either can be
selected as the other's exit/outproxy.

## Two caveats specific to same-host tunneling

1. **Pinging the *overlay* IP directly** (`.22` -> `.3`) is a poor test on one
   host: both overlay IPs are local addresses, so the host kernel may short-
   circuit that particular packet via loopback instead of the tunnel. The
   meaningful test is the outproxy path — route real (internet-bound) traffic
   from one node through the other and confirm it egresses from the exit node's
   uplink. That path is addressed to internet IPs, goes through the TUN, and is
   carried by the session you just established, so it is not affected by the
   local-IP shortcut.

2. **Exit node forwarding must be enabled** on whichever node is the outproxy
   (`EXIT_NODE=1`, plus host `net.ipv4.ip_forward=1` since `/proc/sys` is
   read-only in the container). `compose.yml` already documents this; the K8s
   node needs it set on the node it schedules onto.

## If you'd rather not pin manually

Alternative: give the podman node its own network namespace with its own LAN IP
(e.g. a macvlan network) instead of host networking. Then it is a genuinely
separate host, ordinary LAN discovery works, and no `static_peers` entry is
needed. The trade-off is losing host-mode NAT hole-punching for that node and
needing a macvlan host-shim so the host (and the K8s node on it) can reach it.
Pinning with `static_peers` is simpler if you want to keep both on host
networking.
