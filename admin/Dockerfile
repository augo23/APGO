# overlay-admin: standalone web dashboard for an APGO node. Pure Go standard
# library (no external modules), static binary, tiny image.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/overlay-admin ./

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tini
COPY --from=build /out/overlay-admin /usr/local/bin/overlay-admin
EXPOSE 8088
# Runs as root so it can connect to the client's control socket (root:root,
# mode 0660) on the shared volume.
ENTRYPOINT ["tini", "--", "/usr/local/bin/overlay-admin"]
