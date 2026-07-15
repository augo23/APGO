# APGO overlay client image. Build from the REPO ROOT as the context:
#   podman build -f apgoclient.containerfile -t apgoclient:latest .
# Go 1.24: the Windows Wintun dep (golang.zx2c4.com/wireguard/tun, resolved by
# `go mod tidy` across all platforms) requires >= 1.23.1. It is only COMPILED on
# Windows; on this Linux build it is resolved then excluded by build tags.
FROM golang:1.24-alpine AS build
RUN apk add --no-cache git gcc musl-dev
WORKDIR /src
COPY client/ ./
# Resolve deps (incl. the optional post-quantum circl library) and write go.sum.
RUN go mod tidy
RUN CGO_ENABLED=1 go build -o /out/overlay-client ./

FROM alpine:3.21
# iptables is needed for EXIT_NODE (internet outproxy) NAT.
RUN apk add --no-cache ca-certificates iputils iproute2 iptables tini
COPY --from=build /out/overlay-client /usr/local/bin/overlay-client
ENTRYPOINT ["tini", "--", "/usr/local/bin/overlay-client"]
