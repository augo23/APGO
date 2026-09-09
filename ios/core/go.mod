module overlay-mobile-ios

// go 1.24+ enables the `tool` directive that modern gomobile (Go 1.24/1.25/1.26)
// needs to find golang.org/x/mobile in the module graph.
go 1.26.0

require (
	github.com/cloudflare/circl v1.5.0
	github.com/flynn/noise v1.1.0
	github.com/pierrec/lz4/v4 v4.1.26
	golang.org/x/crypto v0.27.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

tool golang.org/x/mobile/cmd/gobind
