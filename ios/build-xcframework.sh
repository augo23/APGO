#!/usr/bin/env bash
#
# Builds Overlaymobile.xcframework from the vendored overlay core in ios/core,
# installing every prerequisite it needs along the way. Safe to re-run: each
# step is skipped if it's already satisfied.
#
# What it installs (only if missing):
#   - Xcode Command Line Tools   (Apple, via xcode-select)
#   - Homebrew                    (package manager)
#   - Go                          (brew)
#   - XcodeGen                    (brew — turns project.yml into APGO.xcodeproj)
#   - gomobile + gobind           (go install) and `gomobile init`
#
# You still need the full Xcode app from the App Store to build/sign/run the app
# itself (the CLT alone can't build iOS app targets).
set -euo pipefail

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

IOS_DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(uname -s)" = "Darwin" ] || die "This script must be run on macOS."

# --- 0. Never run under sudo -----------------------------------------------
# Running this with sudo creates root-owned files in ~/go and ~/Library/Caches,
# which then breaks every later non-sudo `go`/`gomobile` invocation with
# "permission denied". If we're root, bail with the exact repair command.
if [ "$(id -u)" = "0" ]; then
  real="${SUDO_USER:-$USER}"
  die "Do NOT run this with sudo. If a previous sudo run left root-owned Go files, repair with:
    sudo chown -R $real \"\${HOME}/go\" \"\${HOME}/Library/Caches/go-build\" 2>/dev/null
  then re-run WITHOUT sudo:  ./build-xcframework.sh"
fi

# --- 1. Xcode Command Line Tools -------------------------------------------
if ! xcode-select -p >/dev/null 2>&1; then
  say "Installing Xcode Command Line Tools (a GUI dialog will pop up)…"
  xcode-select --install || true
  echo "Finish the Command Line Tools installer, then re-run this script."
  exit 0
fi

# --- 2. Homebrew ------------------------------------------------------------
if ! command -v brew >/dev/null 2>&1; then
  say "Installing Homebrew…"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
# Make brew available on this shell (Apple Silicon vs Intel paths).
if [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"
elif [ -x /usr/local/bin/brew ]; then eval "$(/usr/local/bin/brew shellenv)"; fi
command -v brew >/dev/null 2>&1 || die "Homebrew install did not complete."

# --- 3. Go ------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  say "Installing Go…"
  brew install go
fi
say "Go version: $(go version)"

# Ensure the Go bin dir (where gomobile/gobind land) is on PATH for this run.
GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"

# --- 4. XcodeGen ------------------------------------------------------------
if ! command -v xcodegen >/dev/null 2>&1; then
  say "Installing XcodeGen…"
  brew install xcodegen
fi

# --- 5. gomobile + gobind ---------------------------------------------------
if ! command -v gomobile >/dev/null 2>&1; then
  say "Installing gomobile + gobind…"
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
fi
# `gomobile init` is idempotent; it sets up the NDK/SDK shims it needs.
say "Initializing gomobile…"
gomobile init || warn "gomobile init reported an issue; continuing."

# --- 6. Build the framework -------------------------------------------------
say "Resolving Go modules (go mod tidy)…"
cd "$IOS_DIR/core"

# Modern gomobile (Go 1.24+) requires golang.org/x/mobile to be present in the
# module graph, not just installed as a binary — otherwise `gomobile bind`
# fails with "missing golang.org/x/mobile dependency". Record it as a tool
# dependency (preferred on Go 1.24+); fall back to a plain require for older Go.
if ! go get -tool golang.org/x/mobile/cmd/gobind 2>/dev/null; then
  go get golang.org/x/mobile/bind
fi
go mod tidy

say "Building Overlaymobile.xcframework (gomobile bind)…"
# gomobile prints 'skipping unsupported' warnings for the core's internal API —
# that's expected; it still exports Start / Stop / Running.
gomobile bind -target=ios -o "$IOS_DIR/Overlaymobile.xcframework" .

say "Done. Built: $IOS_DIR/Overlaymobile.xcframework"
echo
echo "Next:"
echo "  cd \"$IOS_DIR\" && xcodegen generate && open APGO.xcodeproj"
echo "  Then set your Team on both targets and Run on your iPhone."
echo "  Full walkthrough: ios/INSTALL-ON-IPHONE.md"
