# Release flow: build on the Mac, publish from the pipeline

    Mac                              Forgejo Actions
    ───────────────────────────      ─────────────────────────────────────────
    ./build-releases.sh
      ├─ build-releases.sh           (all installers, torrents, magnets.json)
      └─ force-push release-staging ─▶ release.yml
                                        └─ build-releases.sh --publish-only
                                           = tagged Forgejo Release
                                             └─▶ website-sync.yml (release event)
                                                   └─ dispatches apgo-website Deploy
                                                      = site rebuilds with the
                                                        new downloads baked in

The build stays on the Mac (the .pkg needs pkgbuild + Cocoa; iOS/Android
need your signing setup). Everything after the push is automatic.

## One-time setup

1. **RELEASE_TOKEN secret** on the P2P-Overlay-Network repo
   (Settings → Actions → Secrets): a Forgejo access token with
   `write:repository`. Used by release.yml to upload assets and by
   website-sync.yml to dispatch the website Deploy. Your Mac needs no
   token — build-releases.sh pushes a branch with your normal git credentials.

2. Commit these files (already in the repo):
   - `build-releases.sh`
   - `.forgejo/workflows/release.yml`
   - `.forgejo/workflows/website-sync.yml`

## Releasing

    APGO_VERSION=1.0.1 ./build-releases.sh

or, if release/ is already built and you just want to ship it:

    APGO_VERSION=1.0.1 ./build-releases.sh --push-only

That's the whole ceremony. Watch progress under the repo's Actions tab.

## How the artifacts travel without bloating the repo

`release/*` is gitignored on main — deliberately, forever. build-releases.sh
instead commits the finished folder as a SINGLE commit on the
`release-staging` branch and force-pushes it. The branch never accumulates
history: each release replaces the previous commit entirely, and Forgejo's
periodic gc reclaims the orphaned blobs. main stays at ~20MB no matter how
many releases you ship.

The staged commit carries a `BUILD_VERSION` file so the publish job tags
exactly what the Mac built — the two sides cannot disagree on the version.

## Notes

- The release repo must stay anonymously readable; the website image build
  fetches assets without credentials. `--publish-only` verifies this and
  warns if the instance blocks anonymous reads.
- Re-publishing the same version replaces the release's assets (the script
  clears them first) — safe to re-run.
- Each release makes fresh torrents with new infohashes; previously shared
  magnet links lose their seeds, and the site picks up the new magnets.json
  automatically.
- A push to `release-staging` from anything but build-releases.sh will fail
  the publish job fast (no BUILD_VERSION) rather than publish garbage.
