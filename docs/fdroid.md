# Publishing APGO on F-Droid

F-Droid does not accept uploaded APKs. It builds the app itself from the public
source (the GitHub mirror), signs it with F-Droid's key, and publishes it. Once
the app is accepted, every new release is picked up automatically.

## How releases reach F-Droid

1. The Forgejo **Release** workflow cuts a tag (`vX.Y.Z`) and builds the
   installers, as before.
2. Its last step runs `push-github.sh`, which publishes a filtered snapshot of
   the source to `github.com/augo23/APGO` (no private files, no committed
   binaries). Because the commit carries a release tag, the snapshot also gets:
   - the same tag on GitHub, and
   - `android/app/version.properties` (`versionName` / `versionCode`), which
     Gradle uses when no `-PapgoVersion` is given.
3. F-Droid's update checker sees the new tag, reads the version from
   `version.properties`, and builds the `fdroid` flavour from
   [`fdroid/org.apgo.app.yml`](../fdroid/org.apgo.app.yml).

The `fdroid` flavour has no Google Play Billing and no other Google code. Its
Support screen shows the website, Cash App and Monero links only. The `play`
flavour (Google Play, and the APK on the Releases page) keeps Play Billing.

Build either one locally with `APGO_FLAVOR=fdroid bash android/build-apk.sh`
(default `play`).

## One-time setup

### 1. Let the release workflow push to GitHub

Create a GitHub **fine-grained personal access token**:
- Resource owner: `augo23`; repository access: only `augo23/APGO`.
- Permissions: **Contents: Read and write** (nothing else).

Add it to the Forgejo repository as the secret **`GITHUB_MIRROR_TOKEN`**
(Settings → Actions → Secrets). Without it the step is skipped and F-Droid never
sees new releases.

### 2. Cut a release that contains the F-Droid changes

Commit everything, then run the Release workflow. The recipe is written for
**v1.0.17** (versionCode 10017). If the next release gets a different number,
change `versionName`, `versionCode`, `commit`, `CurrentVersion` and
`CurrentVersionCode` in `fdroid/org.apgo.app.yml` to match.

Check that GitHub has the tag and the version file:
`https://github.com/augo23/APGO/blob/v1.0.17/android/app/version.properties`.

### 3. Submit the app to F-Droid

1. Make an account on gitlab.com and fork
   `https://gitlab.com/fdroid/fdroiddata`.
2. Copy `fdroid/org.apgo.app.yml` to `metadata/org.apgo.app.yml` in your fork.
3. Optional, but it catches most review comments: install `fdroidserver`, then
   in the fork run `fdroid lint org.apgo.app` and
   `fdroid build -v -l org.apgo.app`.
4. Open a merge request using the "App inclusion" template.

The store text and description come from
[`fastlane/metadata/android/en-US/`](../fastlane/metadata/android/en-US/) in
this repository. Add screenshots to
`fastlane/metadata/android/en-US/images/phoneScreenshots/` (PNG or JPEG) and
F-Droid shows them.

Review usually takes days to a few weeks. Reviewers may ask about the public
services the app contacts by default (public BitTorrent trackers and the Google
STUN servers) and may label the listing with an anti-feature for them.

## Things to know

- **Different signatures.** F-Droid signs with its own key and Google Play with
  yours, under the same package name `org.apgo.app`. Android will not update
  one with the other, so moving between the Play and F-Droid versions means
  uninstalling first. If you later want F-Droid to ship *your* signature,
  F-Droid supports that for reproducible builds (`Binaries` /
  `AllowedAPKSigningKeys` in the recipe).
- **Delay.** A release usually reaches F-Droid users one to a few days after
  the tag.
- **Go and gomobile versions** are pinned in the recipe (Go 1.26.11, with its
  checksum) and in `ios/core/go.mod` (x/mobile). When you raise the Go minimum,
  update the download URL and SHA-256 in the recipe too.
