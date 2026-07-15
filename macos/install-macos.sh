#!/usr/bin/env bash
#
# APGO macOS installer / updater — run on your Mac from anywhere in the repo:
#
#     bash macos/install-macos.sh        (or: cd macos && bash install-macos.sh)
#
# It: quits & uninstalls any previous version, installs prerequisites (Xcode
# CLT check, Go), builds the native client + menu-bar app in a temporary dir,
# installs a fresh APGO.app to /Applications, then deletes all build artifacts.

set -euo pipefail

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname)" == "Darwin" ]] || die "This installer is for macOS."

# The script now lives in macos/, so the repo root is its parent directory.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
[[ -d client && -d macos ]] || die "Could not find the APGO repo (client/ and macos/ not found)."

# Resolve the REAL user + home, even when run under sudo (otherwise ~ would be
# root's home, /var/root, not the person's ~/.apgo).
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  REAL_USER="$SUDO_USER"
  USER_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
else
  REAL_USER="$(id -un)"
  USER_HOME="$HOME"
fi
[[ -n "$USER_HOME" ]] || USER_HOME="/Users/$REAL_USER"

# Temp build dir, always cleaned up (even on error).
BUILD="$(mktemp -d /tmp/apgo-build.XXXXXX)"
cleanup() {
  rm -rf "$BUILD"
  # Remove any stray build outputs from earlier runs of build.sh / older installers.
  rm -rf "$REPO_ROOT/macos/APGO.app" "$REPO_ROOT/macos/APGO" "$REPO_ROOT/client/overlay-client"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Quit & uninstall any previous version
# ---------------------------------------------------------------------------
log "Stopping any running APGO…"
osascript -e 'quit app "APGO"' >/dev/null 2>&1 || true
killall APGO >/dev/null 2>&1 || true
# Stop the overlay client too (it runs as root): by pid, then by name.
if [[ -f "$USER_HOME/.apgo/client.pid" ]]; then
  sudo kill "$(cat "$USER_HOME/.apgo/client.pid")" >/dev/null 2>&1 || true
fi
sudo pkill -f overlay-client >/dev/null 2>&1 || pkill -f overlay-client >/dev/null 2>&1 || true
sleep 1

# Fresh session: wipe the per-user state so old keys/config/sockets don't linger
# (avoids stale admin keys, node identity, and control sockets). Uses the real
# user's home even under sudo.
log "Clearing previous session state ($USER_HOME/.apgo)…"
rm -rf "$USER_HOME/.apgo" 2>/dev/null || sudo rm -rf "$USER_HOME/.apgo" 2>/dev/null || true

log "Removing old install…"
rm -rf "/Applications/APGO.app" 2>/dev/null || sudo rm -rf "/Applications/APGO.app"

# ---------------------------------------------------------------------------
# 2. Xcode Command Line Tools (needed to compile the Cocoa menu-bar app)
# ---------------------------------------------------------------------------
if ! xcode-select -p >/dev/null 2>&1; then
  log "Installing Xcode Command Line Tools — complete the popup dialog…"
  xcode-select --install >/dev/null 2>&1 || true
  die "Finish the Command Line Tools install in the dialog, then re-run this script."
fi

# ---------------------------------------------------------------------------
# 3. Go toolchain
# ---------------------------------------------------------------------------
ensure_go() {
  command -v go >/dev/null 2>&1 && return
  if [[ -x /usr/local/go/bin/go ]]; then export PATH="/usr/local/go/bin:$PATH"; return; fi
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "$b" ]]; then
      log "Installing Go via Homebrew…"
      "$b" install go
      export PATH="$("$b" --prefix)/bin:$PATH"
      return
    fi
  done
  local ver="go1.24.5" arch tgz
  case "$(uname -m)" in
    arm64)  arch="arm64" ;;
    x86_64) arch="amd64" ;;
    *)      die "unsupported architecture: $(uname -m)" ;;
  esac
  tgz="${ver}.darwin-${arch}.tar.gz"
  log "Downloading ${tgz}…"
  curl -fsSL -o "${BUILD}/${tgz}" "https://go.dev/dl/${tgz}" || die "Go download failed."
  log "Installing Go to /usr/local/go (may ask for your password)…"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "${BUILD}/${tgz}"
  export PATH="/usr/local/go/bin:$PATH"
}
ensure_go
command -v go >/dev/null 2>&1 || die "Go is still not on PATH."
log "Using $(go version)"

# ---------------------------------------------------------------------------
# 4. Build (into the temp dir — nothing is left in the repo)
# ---------------------------------------------------------------------------
log "Building overlay-client…"
( cd client && go mod tidy && go build -trimpath -o "${BUILD}/overlay-client" . )

log "Building menu-bar app (shared desktop module, resolving deps)…"
( cd desktop && go mod tidy && go build -trimpath -o "${BUILD}/APGO" . )

log "Assembling APGO.app…"
APP="${BUILD}/APGO.app"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
cp "${BUILD}/APGO"           "${APP}/Contents/MacOS/APGO"
cp "${BUILD}/overlay-client" "${APP}/Contents/MacOS/overlay-client"

# App icon: compile the .iconset into AppIcon.icns (Finder / Launchpad / Dock).
if [ -d "$REPO_ROOT/macos/AppIcon.iconset" ]; then
  iconutil -c icns -o "${APP}/Contents/Resources/AppIcon.icns" "$REPO_ROOT/macos/AppIcon.iconset" \
    || warn "iconutil failed; app will use the default icon."
fi
cat > "${APP}/Contents/Info.plist" <<'PLIST'
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
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# ---------------------------------------------------------------------------
# 5. Install fresh copy to /Applications
# ---------------------------------------------------------------------------
log "Installing to /Applications…"
cp -R "${APP}" /Applications/ 2>/dev/null || sudo cp -R "${APP}" /Applications/
xattr -dr com.apple.quarantine /Applications/APGO.app 2>/dev/null || true

# ---------------------------------------------------------------------------
# 6. Launch the new version (build artifacts are removed by the EXIT trap)
# ---------------------------------------------------------------------------
log "Launching APGO…"
# A menu-bar (GUI) app must launch as the logged-in user, not root. If this
# script was run with sudo, drop back to the invoking user to open it — and
# open by path (more reliable than -a right after install).
if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
  sudo -u "$SUDO_USER" open "/Applications/APGO.app" || warn "Could not auto-launch — open /Applications/APGO.app yourself."
else
  open "/Applications/APGO.app" || warn "Could not auto-launch — open /Applications/APGO.app yourself."
fi

echo
log "Installed and updated: /Applications/APGO.app"
echo "Click the menu-bar mesh icon → Settings… (one window) → Connect."
echo "Log:  ~/.apgo/overlay-client.log  (also via the app's \"Open log\" item)"
