# Ingress replicas: NPM on every node, each client uses the nearest

`*.kube.sunairies.com` resolves to `10.22.22.22`, the `apgo` pod. Before this,
every request crossed the WAN to wherever that pod ran, even from a laptop
sitting next to a node.

Now:

* the `apgo-ingress` DaemonSet runs a **read-only copy of NPM** on every node.
  It is *not* an overlay node: no overlay client, no key, nothing to approve,
  nothing in any peer list. It listens on the node through hostPorts
  `6980 -> 80` and `6943 -> 443`, so overlay traffic reaches it through that
  node's own podman APGO client (`10.22.22.7`, `.11`, …), like any other
  traffic to the node.
* the `apgo` pod, which owns `10.22.22.22`, tells every client where the copies
  run (`REPLICA_PORTS` / `REPLICA_NODES`). It health-checks each copy through
  the overlay every 10 s and lists only the ones that answer.
* a client with this build sends each **new** connection to
  `10.22.22.22:80/443` to whichever of {the `apgo` pod, each copy} answers its
  pings fastest. It rewrites the address and port on the way out and back, so
  browsers only ever see `10.22.22.22`, and keeps the connection there.
* anything else for `10.22.22.22` (NPM admin on :81, the apgo admin on :8789,
  ping, older clients, the iOS app) goes to the `apgo` pod exactly as before.

Code: `client/replicas.go` (+ tests), the `REPLICA_*` env on the `apgo` pod,
and the `apgo-ingress` DaemonSet at the end of `apgo.yaml`.

This replaces the 2026-10-26 "anycast" version, in which every ingress pod was
its own overlay node (`ingress-zx7t`, …) needing approval and a service grant.

## Security model

* **Only the owner of an address can publish copies of it.** A client accepts
  the list only from the key the overlay binds to `10.22.22.22`, and only if
  that key is approved. That key could already proxy its traffic anywhere, so
  the list gives it no new power. There are no new keys, secrets or signed
  records.
* **A copy is used only over a direct, proven session with the key that owns
  the copy's address**: never through a relay, and never through a node that
  merely claims the address.
* **Replies are rewritten back only for connections the client itself sent to
  that copy** (same protocol, node, port and local port). Nothing else can
  appear to come from `10.22.22.22`.
* **Only the overlay can reach a copy.** A hostPort answers on every node
  address, public and LAN included, and ufw does not see that traffic. The
  `replica-firewall` init container drops any connection to the copy whose
  source is not `10.22.22.0/24` or loopback. Overlay source addresses survive
  the hostPort DNAT, so this holds whatever the node's firewall does.

## Roll-out

Every step is safe to pause at. Clients without the new build keep using the
`apgo` pod.

1. **Build and push the client image** (repo root, on a node that reaches the
   registry):

   ```bash
   podman build -t localhost:5000/apgo-client:latest -f apgo-client.containerfile .
   podman push  localhost:5000/apgo-client:latest
   kubectl -n apgo rollout restart ds/apgo-prepull
   kubectl -n apgo rollout status  ds/apgo-prepull
   ```

2. **Check `REPLICA_NODES`** in `apgo.yaml` (the `apgo` Deployment's
   `overlay-client`) against the nodes' InternalIPs, which here are their
   overlay addresses:

   ```bash
   kubectl get nodes -o wide
   ```

   It lists `.3 .5 .7 .11 .13 .15`.

3. **Apply.** This replaces the DaemonSet, so the six `ingress-*` overlay
   nodes go away. It also takes 6971 out of natpin, and the `apgo` pod restarts
   once, now publishing the copies:

   ```bash
   kubectl apply -f apgo.yaml
   kubectl -n apgo get pods -o wide -l app=apgo-ingress -w
   ```

   The old pods were never approved, so nothing has to be revoked. Their
   `ingress-*` rows leave the peer lists once their sessions time out.

4. **Check the copies are reachable**, from any overlay device (repeat per
   node):

   ```bash
   curl -sk -o /dev/null -w '%{http_code}\n' --resolve forgejo.kube.sunairies.com:6943:10.22.22.7 \
     https://forgejo.kube.sunairies.com:6943/
   kubectl -n apgo exec deploy/apgo -c overlay-client -- apgo services
   ```

   The second command's first line shows each copy as `ok` or `DOWN`, as the
   `apgo` pod sees it.

5. **Update the clients that should use the nearest copy**: laptops, the Mac
   app, and the host podman clients (each node's own traffic). Rebuild and
   restart them as usual. Then, on any of them:

   ```bash
   apgo services     # or: podman exec apgo-client-backbone apgo services
   curl -sk -o /dev/null -w 'ttfb %{time_starttransfer}s\n' https://forgejo.kube.sunairies.com/
   ```

   `*` marks where new connections go. From home it should be a home node,
   at about 1 ms.

Optional clean-up:

* `sudo ufw delete allow 6971/udp` on each node, if you opened it yesterday;
* `sudo rm -rf /var/lib/apgo-ingress` on each node (the old ingress keys);
* remove `- "127.0.0.1:6971"` from each host's `/config/client.yaml` if you
  added it.

## Day to day

* **Edit proxy hosts only in the `apgo` pod's NPM** (the `npm-admin` Service /
  `nginx.kube.sunairies.com`). Its state-sync pushes the change into the
  `npm-data-snap` Secret; each copy restarts onto it within ~1–3 minutes,
  staggered at random. While a copy restarts it fails the health check, and
  clients use another one.
* **Certificates renew only in the `apgo` pod.** The copies have the ACME
  endpoints pointed at 127.0.0.1, so they cannot use up the Let's Encrypt rate
  limit.
* **Proxy hosts that point at the `apgo` pod itself** on `127.0.0.1`,
  `localhost` or `10.22.22.22` (ports :8789 or :81) are rewritten in each copy
  to the `apgo-admin` / `npm-admin` Services. `10.22.22.22` on any other port
  works as is: the copy reaches the `apgo` pod through its node's overlay
  client. Loopback on any other port is logged as a WARNING, because it only
  works when the client lands on the `apgo` pod.
* **Adding a node**: the DaemonSet puts a copy there by itself. Add the
  node's address to `REPLICA_NODES` and re-apply.

## Rollback

`kubectl -n apgo delete ds apgo-ingress`. Within ~20 s the `apgo` pod's health
check withdraws every copy, and new connections go back to the `apgo` pod. To stop
publishing altogether, remove `REPLICA_PORTS` / `REPLICA_NODES` and re-apply.

## Limits

* A node's own podman client never sends to the copy on that same node.
  Traffic from the node itself goes to the `apgo` pod or another node's copy.
* Only copies with a **direct** session are candidates. A node reachable only
  through a relay is never faster than the owner path.
* A TCP connection idle for more than 15 minutes may be reset if the fastest
  copy changed in the meantime, because the per-connection table is bounded.
  IP fragments always take the owner path.
* The iOS core is a separate implementation and keeps using the `apgo` pod.
* The backends behind NPM are still wherever Kubernetes puts them. To keep a
  home request on home backends too, label nodes by site
  (`topology.kubernetes.io/zone`) and set `trafficDistribution: PreferClose` on
  the backend Services.
