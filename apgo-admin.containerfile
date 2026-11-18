# APGO admin dashboard image. Build from the REPO ROOT as the context:
#   podman build -f apgo-admin.containerfile -t apgo-admin:latest .
# Pinned to the go.mod minimum (1.26.11): the official image runs with
# GOTOOLCHAIN=local, so an older cached 1.26.x would refuse to build. Bump both together.
FROM golang:1.26.11-alpine AS build
WORKDIR /src
COPY admin/ ./
# Resolve the go-qrcode dependency (writes go.sum) then build.
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/overlay-admin ./

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tini
COPY --from=build /out/overlay-admin /usr/local/bin/overlay-admin
EXPOSE 8788
ENTRYPOINT ["tini", "--", "/usr/local/bin/overlay-admin"]
