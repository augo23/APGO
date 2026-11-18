# Pinned to the go.mod minimum (1.26.11): the official image runs with
# GOTOOLCHAIN=local, so an older cached 1.26.x would refuse to build. Bump both together.
FROM golang:1.26.11-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /rendezvous .

FROM alpine:3.20
COPY --from=build /rendezvous /rendezvous
EXPOSE 8080
ENTRYPOINT ["/rendezvous"]
