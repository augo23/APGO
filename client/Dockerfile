FROM golang:1.22-alpine AS build
RUN apk add --no-cache git gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /out/overlay-client ./

FROM alpine:3.21
RUN apk add --no-cache ca-certificates iputils iproute2 tini
COPY --from=build /out/overlay-client /usr/local/bin/overlay-client
ENTRYPOINT ["tini", "--", "/usr/local/bin/overlay-client"]
