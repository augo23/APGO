#!/usr/bin/env bash
# Build the gomobile .aar (the overlay core) into app/libs/overlaymobile.aar.
# Reuses the self-contained Go core in ios/core (it's platform-neutral Go).
# Requires: Go, the Android NDK, and gomobile:
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   go install golang.org/x/mobile/cmd/gobind@latest
#   gomobile init
set -euo pipefail
ANDROID_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(cd "$ANDROID_DIR/../ios/core" && pwd)"

mkdir -p "$ANDROID_DIR/app/libs"
cd "$CORE_DIR"

# Modern gomobile (Go 1.24+) needs golang.org/x/mobile in the module graph, or
# `gomobile bind` fails with "missing golang.org/x/mobile dependency". Record it
# (tool directive on Go 1.24+, plain require otherwise) before tidy + bind.
if ! go get -tool golang.org/x/mobile/cmd/gobind 2>/dev/null; then
  go get golang.org/x/mobile/bind
fi
go mod tidy

# Java package becomes org.apgo.overlaymobile, class Overlaymobile.
gomobile bind -target=android -androidapi 24 -javapkg=org.apgo \
  -o "$ANDROID_DIR/app/libs/overlaymobile.aar" .
echo "Built android/app/libs/overlaymobile.aar"
