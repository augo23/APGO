#!/usr/bin/env bash
#
# Fast inner loop for testing on redroid / an emulator: build a debug APK for
# x86_64 only and install it on the connected device.
#
#   ./build-apk.sh     # once, to install the toolchain (Go, SDK, NDK, Gradle)
#   ./dev-apk.sh       # then this, after every change
#
# Faster than build-apk.sh because it:
#   * builds the Go core for x86_64 only (redroid is x86_64), not all 4 ABIs;
#   * skips the Go core entirely when nothing under ios/core changed;
#   * skips every setup step (sdkmanager, gomobile init, go mod tidy);
#   * keeps Gradle's daemon and build cache warm between runs.
# The APK it makes runs on x86_64 devices only. Releases use build-apk.sh.
set -euo pipefail
APGO_FLAVOR="${APGO_FLAVOR:-play}"
case "$APGO_FLAVOR" in play|fdroid) ;; *) echo "APGO_FLAVOR must be play or fdroid" >&2; exit 1 ;; esac
APGO_FLAVOR_CAP="$(printf %s "${APGO_FLAVOR:0:1}" | tr a-z A-Z)${APGO_FLAVOR:1}"

say() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

ANDROID_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(cd "$ANDROID_DIR/../ios/core" && pwd)"
AAR="$ANDROID_DIR/app/libs/overlaymobile.aar"
APK="$ANDROID_DIR/app/build/outputs/apk/$APGO_FLAVOR/debug/app-$APGO_FLAVOR-debug.apk"

: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
export ANDROID_HOME ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.3.11579264"
export PATH="$(go env GOPATH)/bin:$PATH"
[ -d "$ANDROID_NDK_HOME" ] && command -v gomobile >/dev/null 2>&1 \
  || die "toolchain not installed yet: run ./build-apk.sh once first"

# --- Go core: only when it changed -------------------------------------------
changed="$( [ -f "$AAR" ] && find "$CORE_DIR" \( -name '*.go' -o -name go.mod -o -name go.sum \) \
            -newer "$AAR" -print -quit )" || true
if [ ! -f "$AAR" ] || [ -n "$changed" ]; then
  say "Building the Go core for x86_64${changed:+ ($(basename "$changed") changed)}…"
  cd "$CORE_DIR"
  grep -q 'golang.org/x/mobile' go.mod || go get -tool golang.org/x/mobile/cmd/gobind
  gomobile bind -target=android/amd64 -androidapi 24 -javapkg=org.apgo -o "$AAR" .
else
  say "Go core unchanged: reusing app/libs/overlaymobile.aar"
fi

# --- APK -----------------------------------------------------------------------
say "Assembling the debug APK…"
cd "$ANDROID_DIR"
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew --build-cache -PapgoVersion="${APGO_VERSION:-1.0.0}" :app:assemble${APGO_FLAVOR_CAP}Debug

# --- install -------------------------------------------------------------------
# The workspace's own adb, so the existing connection to redroid is kept
# (the SDK's adb is a different version and would restart the adb server).
if command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then
  say "Installing on $(adb get-serialno)…"
  adb install -r -d "$APK"     # -d: allow a lower versionCode than a release build
else
  say "No device connected; APK is at $APK"
fi
