# APGO mobile bridge (shared by iOS + Android)

`mobile/` is a small [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile)-bindable
Go package (`overlaymobile`) that the iOS and Android apps call. The platform VPN
layer owns the tunnel; it passes the tunnel file descriptor and a JSON config to
`Start(fd, configJSON)`, and this package runs the overlay over it.

```
Swift/Kotlin app  ──►  overlaymobile.Start(fd, json)  ──►  overlay core (client/)
   (NetworkExtension / VpnService owns the tun fd)
```

## API (exposed to Swift/Kotlin via gomobile)

- `Start(tunFD int, configJSON string) error`
- `Stop()`
- `Running() bool`

`configJSON` marshals the `Config` struct in `bridge.go` (network name, PSK,
overlay CIDR, this device's overlay IP, cipher, STUN servers, admin pubkey).

## The one wiring step

The overlay core lives in `client/` but currently runs from `main()` and creates
its own per-OS TUN. To reuse it here, extract its run loop into an importable
package that accepts an injected `io.ReadWriteCloser` + config, then implement
`overlayRun` in `overlayrun.go` to call it. Everything else (Noise handshake,
sessions, tracker/STUN discovery, endpoint roaming) is already
platform-independent Go and moves over unchanged. Until that's done, `Start`
returns a clear "not yet wired" error.

## Build the bindings

Install gomobile once:

```
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

Then:

```
# iOS (produces an .xcframework the Xcode project imports)
gomobile bind -target=ios -o ios/OverlayMobile.xcframework ./mobile

# Android (produces an .aar the Gradle app imports)
gomobile bind -target=android -androidapi 21 -javapkg=org.apgo \
  -o android/app/libs/overlaymobile.aar ./mobile
```

See `ios/README.md` and `android/README.md` for the platform apps.
