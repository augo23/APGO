#!/usr/bin/env bash
# Build the APGO menu-bar app and package it as a proper macOS .app bundle.
# Run this ON a Mac (it links against Cocoa via getlantern/systray).
set -euo pipefail
cd "$(dirname "$0")"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "This must be built on macOS (the menu-bar app links against Cocoa)." >&2
  exit 1
fi

echo "==> Resolving dependencies (go mod tidy)"
go mod tidy

echo "==> Building menu-bar binary"
go build -trimpath -o APGO .

echo "==> Building the native overlay client (../client)"
( cd ../client && go build -trimpath -o overlay-client . )

APP="APGO.app"
echo "==> Packaging $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp APGO "$APP/Contents/MacOS/APGO"
cp ../client/overlay-client "$APP/Contents/MacOS/overlay-client"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>APGO</string>
  <key>CFBundleIdentifier</key><string>org.apgo.macos</string>
  <key>CFBundleExecutable</key><string>APGO</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <!-- LSUIElement hides the Dock icon so it's a pure menu-bar app -->
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

echo "==> Done: $(pwd)/$APP"
echo "Launch it with:  open $APP     (or double-click in Finder)"
