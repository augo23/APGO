# APGO rendezvous server

A tiny discovery server for networks that **block BitTorrent**. It's a drop-in
alternative to a BitTorrent tracker: a node POSTs its network id (info-hash) and
public endpoint, and gets back the other endpoints in that network. It speaks
plain HTTP(S), so behind TLS on port 443 it's indistinguishable from any HTTPS
service and sails through filters that block torrent traffic.

It only exchanges endpoints — the same metadata a tracker sees. It never handles
keys or the PSK, so it **cannot join or read** your overlay; membership stays
gated by the Noise handshake + PSK on the nodes.

## When you need it

The overlay's *data* traffic is Noise-encrypted UDP and doesn't look like
BitTorrent, so it isn't blocked. Only peer **discovery** uses BitTorrent
trackers. If a node sits on a network that blocks BitTorrent, run one of these on
a host with a public IP and point your nodes at it.

(You can also skip discovery entirely and list a public node under
`static_peers` — that needs no server at all. The rendezvous is the option when
you want automatic discovery like the trackers give you.)

## Run it

Anywhere with a public IP (a small VPS is plenty):

```
docker build -t apgo-rendezvous ./rendezvous
docker run -d --name apgo-rendezvous -p 8080:8080 apgo-rendezvous
```

Then put TLS in front on 443 (recommended — that's what makes it look like
ordinary HTTPS). Easiest is Caddy:

```
# Caddyfile
rv.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Or serve HTTPS directly:

```
docker run -d -p 443:8443 \
  -e LISTEN_ADDR=:8443 \
  -e TLS_CERT_FILE=/certs/fullchain.pem -e TLS_KEY_FILE=/certs/privkey.pem \
  -v /etc/letsencrypt/live/rv.example.com:/certs:ro \
  apgo-rendezvous
```

## Point nodes at it

Use the **same value on every node** that should find each other:

- **Docker nodes:** set `RENDEZVOUS_SERVERS=https://rv.example.com` (compose reads
  it from the environment).
- **Mac/Windows app:** Settings → *Discovery servers* → `https://rv.example.com`.
- **iOS/Android:** the mobile core accepts a `rendezvous_servers` array in its
  config JSON (add it to the app's config payload).
- **Raw client config:** `rendezvous_servers: ["https://rv.example.com"]`, or the
  `RENDEZVOUS_SERVERS` env var (comma-separated).

Nodes announce to the rendezvous on the same cadence as trackers and dial back
any peers it returns; trackers still run too, so a mixed fleet (some blocked,
some not) all converges.

## Env

| Var | Default | Meaning |
|-----|---------|---------|
| `LISTEN_ADDR` | `:8080` | bind address |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | serve HTTPS directly (optional) |
| `PEER_TTL_SECONDS` | `300` | how long an endpoint stays advertised |
