# iOS: LAN peers not found, "direct" sessions at relay speed, mid-stream drops

Diagnosis, fixes, and a comparison against the Aug-7 backup. Nothing here was compiled or run — no
Go toolchain is reachable from this sandbox — so **run `go test ./...` in `ios/core` and `client`
before rebuilding the mobile artifacts.**

---

## The three symptoms and their causes

| Symptom | Cause |
|---|---|
| LAN nodes not found | Sweep suppressed by traffic (A) and by a global "found one" flag (B); iOS has no broadcast fallback |
| Says "not relayed", performs like relayed | The badge meant "a handshake completed", not "packets take this path" (E) — and `RoamData` silently moved live LAN sessions onto the WAN path (F) |
| Streams drop mid-connection | `RoamData` re-keying the session mid-transfer (F) |

### A. The sweep was switched off by any traffic at all

`overlay.go` gated the unicast sweep on `moved-lastMoved <= 200` — a **cumulative** packet count.
`pktActivity` increments on every packet in both directions, so 200 packets (a page load, a
background refresh) cancelled the sweep entirely. iOS cannot broadcast without Apple's multicast
entitlement, which is commented out in both entitlements files, so the unicast sweep is the *only*
discovery the phone has.

**Fixed:** rate-based (`>400 pkt/s`), capped at 3 consecutive deferrals, and it logs when it sweeps
anyway.

### B. One LAN peer stopped the search for every other

`hasEstablishedLANPeer()` is a single global boolean, and finding any LAN peer relaxed the cadence
to **5 minutes**. Two iOS devices could not rescue each other — neither can broadcast, so if both
relax, neither sweeps and neither answers.

**Fixed:** that branch now settles at the steady 30s; it only ends the aggressive 5s opening phase.

### C. Discovery sockets were never pinned to the physical interface

The desktop client pins every discovery socket with `IP_BOUND_IF` ("keep LAN discovery off the VPN
routes", `client/vpnroutes_darwin.go:80`). `ios/core` had no equivalent, and the sweep transmitted
from the *listening* socket.

**Fixed:** new `lanpin_darwin.go` + a no-op `lanpin_other.go` for Android; the sweep gets its own
socket.

### D. The extension's Info.plist had no Local Network keys

The app declared `NSLocalNetworkUsageDescription` and `NSBonjourServices`; the extension — the
process that actually sweeps — declared neither. **Fixed.**

### E. "Not relayed" described the handshake, not the path

`Relayed` was only ever true for rows with no direct session. Meanwhile `ip_learning` can point the
route at a relay (rules 2/3) or at the peer's WAN address instead of its LAN one (rule 4), and both
left `established=true, relayed=false`.

**Fixed:** new `SessionInfo.path` computed by `pathLabel()` from the same table the send path reads
— `lan` / `direct` / `wan` / `relay` / `unknown` — surfaced as a badge and a yellow dot. Also added
to the desktop client for parity.

### F. `RoamData` demoted live LAN sessions

`overlay.go` trial-decrypted any data frame from an unknown address against every established
session and, on success, **unconditionally** moved the session there. No liveness check, no
route-class preference, no hysteresis — all three of which `ip_learning.Learn` implements next door.
A hairpin duplicate therefore moved a live same-wire session onto the router path: in-flight packets
lost, throughput at hairpin speed, and no UI change because it is the same session and key.

**Fixed:** declines when the incumbent is live *and* the candidate is a strictly worse route class.
Genuine roaming is untouched. Applied to `ios/core` and `client`.

### G. No-route traffic is flooded 2× to every peer — left alone

`run.go` sends every packet with no learned route to every peer twice. This is the bootstrap
mechanism, and `relaysteal_test.go`'s `TestSendPathHasNoLivenessGate` explicitly forbids porting the
desktop's damping here — that mistake has been made before in this repo. Now **visible** via
`tx_flood`.

### H. The app's data-path diagnostics were dead code

`TunnelManager` decoded nine fields (`tx_direct`, `rx_data`, …) that `NetworkStatusJSON()` never
sent, because `ios/core/datastats.go` was an empty stub. The panel could never appear.

**Fixed:** counters restored from `client/datastats.go`, wired at the same call sites, and merged
flat into `NetworkStatusJSON` with `admission_required` / `self_approved`. Also restored the missing
`ip_derived` field, which had the identical defect.

---

## Comparison against the Aug-7 backup (`f8550d2`)

The `~/Desktop` backup is the same repository at commit `f8550d2`, Aug 7. Current HEAD is `e7ee8aa`,
Aug 10, plus a large uncommitted working tree. ~40 commits in between, ~14 touching `ios/`.

**The regression is narrower than it looked.** The backup's sweep loop has no `pktActivity` gate
(the symbol does not exist anywhere in that tree) and no `hasEstablishedLANPeer()` branch in the
cadence — just `wait := 30s; if sweepNo < 12 { wait = 5s }`. Fixes A and B restore exactly that.

**What the backup does *not* fix**, because it has the same code: `RoamData` is identical and
unguarded, the 2× flood is identical (`run.go:318-319`), `SetMemoryLimit(30<<20)` is already there,
keepalive/stale are already 10s/45s. Those predate the "known-good" build and were latent.

**A wholesale revert would not have built.** The backup's gomobile surface is
`Start / Stop / Running / PeersJSON / PendingAddress / ResetState` — no `NetworkStatusJSON`, no
`ExitsJSON` — and both the iOS extension *and* Android's `MainActivity` call those.

### Targeted revert applied

Kept the new API, `resolver.go`, `selfendpoints.go`, `statusapi.go` and the `ip_learning`
route-class rules. Reverted to the pre-Aug-7 shape:

| Reverted | Where |
|---|---|
| In-place AEAD decrypt over the receive buffer | `overlay.go` `recvPacket` → `Decrypt(nil, ...)` |
| In-place PQ unwrap | `pq.go` `pqUnwrap` → `Open(nil, ...)` |
| Salt+counter PQ nonce | `pq.go` → `crypto/rand` per packet; `nonceSalt`/`nonceCtr`/`newPQPeer`/`nextNonce` removed |
| Pooled PQ wrap buffer | `pqWrapTo`/`pqWrapPool` removed; `sendPacket` calls plain `pqWrap` |
| `touchSession` on the receive path | `run.go` → `TouchLastSeen(raddr)` |
| 7 MB socket buffers | `setSocketBuffers` is now a no-op (call sites kept) |

**Kept deliberately:** the 512-packet replay window — a correctness fix, and the narrow one produced
exactly the "dies part-way through a transfer" symptom this started from — plus `framePool`,
`maxFrameSize` and the lz4 pools, which already existed in the backup.

**Left in, outside the agreed scope:** `compressPool`, `relayFramePool`, `sliceWriterPool` and
`compressAndFrameTo` are also post-Aug-7, but they are plain output buffers with explicit lifetimes
that never alias the receive buffer.

Tests adjusted: `hotpath_test.go` lost `TestPacketPathDoesNotAllocate` and `TestPQNonceNeverRepeats`
(they pinned the reverted code) and gained `TestPQNoncesAreDistinct`, which asserts probabilistically
what the counter guaranteed by construction. `rxpath_test.go`'s
`TestReceivePathDoesNotRelookupTheSession` is retired in favour of one that catches a half-applied
revert. `sweepgate_test.go` was rewritten — it had pinned the *broken* sweep behaviour.

---

## Android

`android/build-aar.sh:10` sets `CORE_DIR="$ANDROID_DIR/../ios/core"` — **Android builds the same Go
package**, and `MainActivity.kt` calls the same surface (`running`, `peersJSON`, `exitsJSON`,
`networkStatusJSON`, `pendingAddress`).

- Every regression above reached Android; every fix reaches it automatically.
- The sweep gate hurt Android **less**: no multicast-entitlement restriction there, so the broadcast
  beacon still worked and the unicast sweep was a fallback rather than the only mechanism. That is
  consistent with iOS being the platform that broke visibly.
- `lanpin_other.go` (`//go:build !darwin`) keeps Android compiling; pinning is correctly a no-op,
  since `VpnService` already excludes the owning app from its own tunnel.
- Android decodes peer JSON with `org.json` + `optString`, so the added `path` field is ignored
  safely by older builds.
- Android's Kotlin barely moved between the backup and now: one commit plus uncommitted
  `MainActivity.kt` edits.

**Both artifacts need rebuilding** — `ios/build-xcframework.sh` and `android/build-aar.sh`.

---

## On-device checklist

In the Console log, filtered to the extension:

- `[local-discovery] status: N sweep target(s) … established LAN peer=…` — every 6th sweep. `N == 0`
  means no usable subnet (Local Network permission).
- `[local-discovery] sweeping despite sustained traffic` — the new deferral cap firing. Expected
  during a transfer, rare otherwise.
- `[roam] declined … this is a second path to the same peer, not a move` — **seeing this line is the
  confirmation that F was real.**
- `[roam] peer moved …` — should now only appear on real network changes.

In the app: `tx_flood` climbing while `tx_direct` stays flat is finding G. A `LAN` badge means the
route is on an attached subnet; `direct` means private but not on one of *this device's* subnets
(different VLAN, a secondary NIC, or a Docker/bridge address the peer advertised).
