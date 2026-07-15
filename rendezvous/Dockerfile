FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /rendezvous .

FROM alpine:3.20
COPY --from=build /rendezvous /rendezvous
EXPOSE 8080
ENTRYPOINT ["/rendezvous"]
