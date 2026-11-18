#!/usr/bin/env bash
# Build the gomobile .aar (the overlay core) into app/libs/overlaymobile.aar.
# Reuses the self-contained Go core in ios/core (it's platform-neutral Go).
# Requires: Go, the Android NDK, and gomobile:
#   (cd ios/core && go install golang.org/x/mobile/cmd/gomobile@$(go list -m -f '{{.Version}}' golang.org/x/mobile))
#   gomobile init
# (the same x/mobile version ios/core/go.mod pins, so gomobile and gobind match)
set -euo pipefail
ANDROID_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(cd "$ANDROID_DIR/../ios/core" && pwd)"

mkdir -p "$ANDROID_DIR/app/libs"
cd "$CORE_DIR"

# Modern gomobile (Go 1.24+) needs golang.org/x/mobile in the module graph, or
# `gomobile bind` fails with "missing golang.org/x/mobile dependency". Record it
# (tool directive on Go 1.24+, plain require otherwise) before tidy + bind.
#
# Only when it is MISSING: an unversioned `go get` upgrades to the newest
# x/mobile on every build, which silently changed go.mod and made builds
# unreproducible (F-Droid rebuilds from the tag and must get the same result).
if ! grep -q 'golang.org/x/mobile' go.mod; then
  if ! go get -tool golang.org/x/mobile/cmd/gobind 2>/dev/null; then
    go get golang.org/x/mobile/bind
  fi
  go mod tidy
fi

# Java package becomes org.apgo.overlaymobile, class Overlaymobile.
# GOMOBILE_TARGET=android/amd64 builds only the x86_64 ABI (redroid, emulators):
# about a quarter of the time of all four. Releases keep the default.
gomobile bind -target="${GOMOBILE_TARGET:-android}" -androidapi 24 -javapkg=org.apgo \
  -o "$ANDROID_DIR/app/libs/overlaymobile.aar" .
echo "Built android/app/libs/overlaymobile.aar"
