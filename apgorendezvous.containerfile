# APGO rendezvous (HTTPS discovery) server image.
# Build from the REPO ROOT as the context:
#   podman build -f apgorendezvous.containerfile -t apgorendezvous:latest .
#
# The rendezvous server is a tiny stateless HTTP service: nodes POST their
# network id (info-hash) + public endpoint and get back the other endpoints in
# that network. It is the alternative to BitTorrent trackers on networks that
# block them. It never sees keys or the PSK, so it cannot join or decrypt the
# overlay — but it CAN see which endpoints announce, so run it authenticated
# (AUTH_TOKENS / AUTH_USERS) and behind TLS.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY rendezvous/ ./
RUN go mod tidy
# Static build: no cgo, so the runtime image needs no libc at all.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/rendezvous ./

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tini
COPY --from=build /out/rendezvous /usr/local/bin/rendezvous

# Runs unprivileged: it binds 8080 (not a privileged port), holds no state on
# disk, and needs no capabilities. Put TLS in front (ingress/NPM) or point
# TLS_CERT_FILE / TLS_KEY_FILE at a mounted cert.
USER 65532:65532

# Env (all optional):
#   LISTEN_ADDR       bind address                (default ":8080")
#   PEER_TTL_SECONDS  endpoint advertise lifetime (default 300)
#   AUTH_TOKENS       comma-separated bearer tokens accepted
#   AUTH_USERS        comma-separated user:password pairs (HTTP Basic)
#   TLS_CERT_FILE / TLS_KEY_FILE   serve HTTPS directly (optional)
#
# With neither AUTH_TOKENS nor AUTH_USERS set the server runs OPEN and logs a
# warning — fine on a private network, not on the public internet.
EXPOSE 8080
ENTRYPOINT ["tini", "--", "/usr/local/bin/rendezvous"]
