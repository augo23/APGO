#!/usr/bin/env bash
#
# APGO macOS installer / updater — run on your Mac from anywhere in the repo:
#
#     bash macos/install-macos.sh        (or: cd macos && bash install-macos.sh)
#
# It: quits & uninstalls any previous version, installs prerequisites (Xcode
# CLT check, Go), builds the native client + menu-bar app in a temporary dir,
# installs a fresh APGO.app to /Applications, then deletes all build artifacts.
#
#     --fresh    ALSO delete this Mac's node identity and settings (~/.apgo).
#
# Settings and identity are KEPT by default. They did not used to be, and the
# consequence was severe enough to be worth spelling out: ~/.apgo holds
# node.key, this machine's cryptographic identity on the overlay. Deleting it
# means the Mac rejoins as a brand-new, unknown device — new key fingerprint,
# and on a network with admission control it lands in "pending" and passes no
# data until an admin approves it again. Reinstalling to fix a problem should
# not, by itself, evict the machine from its own network.

set -euo pipefail

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- flags ------------------------------------------------------------------
FRESH=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $arg (did you mean --fresh?)" ;;
  esac
done

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
#
# WHY THIS SECTION IS SO CAREFUL
#
# The overlay client binds a FIXED UDP port. If any previous instance survives
# this step, the newly installed client dies at startup with
#
#     udp listen: listen udp 0.0.0.0:6969: bind: address already in use
#
# and — because the TUN is created before the socket is bound — it leaks a
# configured utun on the way out. Every reconnect attempt then leaks another
# (utun5, utun6, utun9 …) while the menu bar reports only "Client didn't come
# up". Nothing about that failure points at a surviving process, so the stop
# sequence has to VERIFY its work rather than fire-and-forget.
#
# The old sequence sent one SIGTERM, slept for one second, and swallowed every
# error with `|| true`. A client mid-shutdown (tearing down the TUN, removing
# routes) routinely needs longer than that, and nothing ever checked whether
# the port was actually free.

# Cache sudo credentials up front so the password prompt appears here, next to
# an explanation, instead of interrupting a later step.
log "Stopping any running APGO…"
sudo -v 2>/dev/null || true

# Which UDP ports must end up free.
#
# Reading udp_listen_port from the existing config is necessary but NOT
# sufficient, and the gap is exactly the first-install case: on a clean machine
# there is no ~/.apgo/client.yaml, so the config lookup yields nothing and this
# falls back to the 6969 default — while the client already running might be on
# 6970, or 32555, or anything else. The check then passes, the install
# proceeds, and the new client dies on "address already in use" with the port
# never having been looked at.
#
# So ask the RUNNING PROCESSES what they hold, and take the union. That covers
# a first install, a client started from a config we cannot see, and a build
# left over from an older layout.
APGO_PORTS_SEED=6969
if [[ -f "$USER_HOME/.apgo/client.yaml" ]]; then
  _p="$(awk -F':' '/^[[:space:]]*udp_listen_port:/ {gsub(/[^0-9]/,"",$2); print $2; exit}' \
        "$USER_HOME/.apgo/client.yaml" 2>/dev/null || true)"
  [[ "$_p" =~ ^[0-9]+$ ]] && (( _p > 0 && _p < 65536 )) && APGO_PORTS_SEED="$APGO_PORTS_SEED $_p"
fi

# apgo_ports: the seed above, plus every UDP port currently held by a running
# overlay-client, whatever it was configured with and wherever it was launched
# from. Re-evaluated on each call, so it shrinks as processes die.
apgo_ports() {
  {
    printf '%s\n' $APGO_PORTS_SEED
    sudo lsof -nP -a -c overlay-client -iUDP 2>/dev/null \
      | awk 'NR>1 { n=split($9,a,":"); if (a[n] ~ /^[0-9]+$/) print a[n] }'
  } | grep -E '^[0-9]+$' | sort -un
}

# wait_gone <seconds> <predicate…> — poll until the predicate FAILS (i.e. the
# thing is gone). Returns 0 as soon as it is, 1 if it outlives the deadline.
# Polling beats a fixed sleep in both directions: it returns immediately in the
# common case, and it actually waits when a shutdown is slow.
wait_gone() {
  local deadline=$1; shift
  local i
  for (( i = 0; i < deadline * 10; i++ )); do
    "$@" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
  return 1
}

# --- STOP LAUNCHD FIRST, or none of the killing below sticks ---------------
#
# The boot daemon is installed with KeepAlive=true (see bootDaemonPlist in
# desktop/autostart_darwin.go). That is correct for normal operation — it is
# what restarts the client if it ever crashes — and it is fatal here: launchd
# relaunches the client within a second of any SIGTERM or SIGKILL, so the stop
# sequence below was racing a supervisor whose entire job is to undo it. The
# port would be reclaimed before the check ran, or freed just long enough for
# the check to pass and then taken again while the installer built.
#
# So unload the jobs BEFORE touching any process, and remember which were
# active so they can be restored afterwards. The plists point at
# /Applications/APGO.app/…, a path this installer replaces in place, so
# re-bootstrapping at the end picks up the NEW binary automatically.
BOOT_PLIST="/Library/LaunchDaemons/com.apgo.client.plist"
AGENT_PLIST="$USER_HOME/Library/LaunchAgents/com.apgo.desktop.plist"
HAD_BOOT_DAEMON=0
HAD_LOGIN_AGENT=0

if [[ -f "$BOOT_PLIST" ]]; then
  HAD_BOOT_DAEMON=1
  log "Unloading the APGO boot daemon (KeepAlive would restart the client)…"
  sudo launchctl bootout system/com.apgo.client >/dev/null 2>&1 \
    || sudo launchctl bootout system "$BOOT_PLIST" >/dev/null 2>&1 \
    || sudo launchctl unload "$BOOT_PLIST" >/dev/null 2>&1 || true
fi

if [[ -f "$AGENT_PLIST" ]]; then
  HAD_LOGIN_AGENT=1
  launchctl bootout "gui/$(id -u "$REAL_USER")/com.apgo.desktop" >/dev/null 2>&1 \
    || launchctl unload "$AGENT_PLIST" >/dev/null 2>&1 || true
fi

# --- the menu-bar app (runs as the logged-in user) -------------------------
osascript -e 'quit app "APGO"' >/dev/null 2>&1 || true
wait_gone 5 pgrep -x APGO || killall    APGO >/dev/null 2>&1 || true
wait_gone 3 pgrep -x APGO || killall -9 APGO >/dev/null 2>&1 || true

# --- the overlay client (runs as root) -------------------------------------
# By recorded PID first: the most precise handle we have. kill -0 tests for
# existence without signalling, so a stale PID file is a no-op rather than a
# signal sent to whatever recycled that PID.
if [[ -f "$USER_HOME/.apgo/client.pid" ]]; then
  _pid="$(tr -dc '0-9' < "$USER_HOME/.apgo/client.pid" 2>/dev/null || true)"
  if [[ -n "$_pid" ]] && sudo kill -0 "$_pid" 2>/dev/null; then
    sudo kill "$_pid" 2>/dev/null || true
    wait_gone 5 sudo kill -0 "$_pid" || sudo kill -9 "$_pid" 2>/dev/null || true
  fi
fi

# By exact process NAME. Deliberately `pkill -x`, never `pkill -f`: step 4 of
# this script runs `go build -trimpath -o "${BUILD}/overlay-client" .`, so a
# full-command-line match can kill an in-flight build — its own, or one a
# colleague is running on the same machine. `-x` matches argv[0] only.
if pgrep -x overlay-client >/dev/null 2>&1; then
  sudo pkill -x overlay-client 2>/dev/null || pkill -x overlay-client 2>/dev/null || true
  if ! wait_gone 5 pgrep -x overlay-client; then
    warn "overlay-client ignored SIGTERM — escalating to SIGKILL"
    sudo pkill -9 -x overlay-client 2>/dev/null || pkill -9 -x overlay-client 2>/dev/null || true
    wait_gone 3 pgrep -x overlay-client || true
  fi
fi

# --- whatever still holds the UDP port -------------------------------------
# The authoritative check. The new client does not care what a process is
# called, only that the port is free — so ask the kernel. This catches an
# older build installed under a different name, a copy running from a stale
# path, and any unrelated process that happened to take the port.
# Every PID holding any of the ports we care about.
port_holders() {
  local p
  for p in $(apgo_ports); do
    sudo lsof -ti "UDP:${p}" 2>/dev/null || true
  done | sort -un
}

_holders="$(port_holders)"
if [[ -n "$_holders" ]]; then
  warn "UDP port(s) $(apgo_ports | tr '\n' ' ')still held by PID(s): $(echo "$_holders" | tr '\n' ' ')"
  for _pid in $_holders; do
    sudo kill "$_pid" 2>/dev/null || true
  done
  sleep 1
  for _pid in $(port_holders); do
    sudo kill -9 "$_pid" 2>/dev/null || true
  done
  sleep 1
fi

# Refuse to continue with the port occupied. Installing over a live instance
# produces an app that cannot start, and the resulting log line points at the
# socket rather than at the cause — exactly the trail that is hard to follow
# later. Better to stop here and say so.
_holders="$(port_holders)"
if [[ -n "$_holders" ]]; then
  echo >&2
  for _p in $(apgo_ports); do sudo lsof -nP -iUDP:"${_p}" >&2 2>/dev/null || true; done
  echo >&2
  die "The UDP port(s) above are still in use, so a new client could not start.
       If that is a container (podman/docker) rather than a process, stop the
       container — killing the PID will not release the port. Otherwise reboot
       and re-run this installer."
fi

# Leaked utun interfaces are a useful second opinion. A utun exists only while
# some process holds its file descriptor, so one carrying an overlay address
# after all of the above means a client we failed to identify is still alive.
_leaked="$(ifconfig 2>/dev/null | awk '/^utun[0-9]+:/ {i=substr($1,1,length($1)-1)}
                                       /^[[:space:]]*inet 10\./ {print i}' | sort -u || true)"
if [[ -n "$_leaked" ]]; then
  warn "utun interface(s) still carrying an overlay address: $(echo "$_leaked" | tr '\n' ' ')"
  warn "They vanish when their owner exits; if they persist, reboot before using APGO."
fi

log "UDP port(s) $(apgo_ports | tr '\n' ' ')are free."

# Per-user state (~/.apgo): node identity, settings, admin key, control sockets.
#
# KEPT unless --fresh. This used to be wiped unconditionally, and the note that
# stood here described the damage accurately while calling it intentional:
# deleting node.key makes the Mac rejoin the mesh AS A NEW DEVICE — new
# identity, new fingerprint, and re-approval required if the network uses
# admission control. Combined with enforcement being on, the ordinary act of
# reinstalling silently locked this machine out of its own network. A stale
# socket is worth clearing; a cryptographic identity is not the installer's to
# throw away.
#
# Stale control sockets ARE cleared either way: they are the thing that
# genuinely goes bad across a reinstall, and they carry no identity.
if [[ "$FRESH" == "1" ]]; then
  # A full wipe: config, approvals, provisions, policy, cached endpoints, logs,
  # sockets AND node.key. Nothing is preserved.
  #
  # The one consequence worth stating plainly, because it is invisible from
  # this Mac: node.key is the machine's identity on the overlay, and peers
  # route to KEYS, not machines -- an admin provision binds an overlay address
  # to a public key. A new key therefore needs a new provision. Until an admin
  # provisions this Mac's address onto its NEW fingerprint, the Mac will
  # establish sessions in both directions, report every counter healthy, and
  # receive nothing, because peers still resolve that address to the previous
  # key. The installer prints the new fingerprint at the end for that reason.
  log "--fresh: erasing $USER_HOME/.apgo (settings, state and node identity)…"
  warn "This Mac rejoins as a NEW device: new key, re-approval if admission"
  warn "control is on, and an admin must provision its overlay address onto"
  warn "the new key or it will look connected and receive nothing."
  rm -rf "$USER_HOME/.apgo" 2>/dev/null || sudo rm -rf "$USER_HOME/.apgo" 2>/dev/null || true

elif [[ -d "$USER_HOME/.apgo" ]]; then
  log "Keeping existing settings and node identity ($USER_HOME/.apgo). Use --fresh to reset."
  rm -f "$USER_HOME/.apgo"/*.sock "$USER_HOME/.apgo/client.pid" 2>/dev/null \
    || sudo rm -f "$USER_HOME/.apgo"/*.sock "$USER_HOME/.apgo/client.pid" 2>/dev/null || true
fi

# Recreate it NOW, owned by the real user.
#
# Whoever gets there first creates this directory 0700 and owns it — and the
# overlay client runs as ROOT (privileged Connect, and the boot LaunchDaemon).
# If root wins the race the directory is root-owned 0700, and the menu-bar app,
# which runs as the logged-in user, can no longer write inside it:
#
#     Could not save: open ~/.apgo/webui-credentials.json.tmp: permission denied
#
# The client is happy either way — it only needs the directory to be writable by
# root, which it is. So create it up front with the right owner and let the
# root-run client inherit it.
mkdir -p "$USER_HOME/.apgo"
chown "$REAL_USER" "$USER_HOME/.apgo" 2>/dev/null || sudo chown "$REAL_USER" "$USER_HOME/.apgo" 2>/dev/null || true
chmod 700 "$USER_HOME/.apgo" 2>/dev/null || true

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
# Restore whatever autostart was configured before, now pointing at the new
# binary (same path, replaced in place).
if (( HAD_BOOT_DAEMON )); then
  log "Restoring the APGO boot daemon…"
  sudo launchctl bootstrap system "$BOOT_PLIST" >/dev/null 2>&1 \
    || sudo launchctl load "$BOOT_PLIST" >/dev/null 2>&1 || true
fi
if (( HAD_LOGIN_AGENT )); then
  launchctl bootstrap "gui/$(id -u "$REAL_USER")" "$AGENT_PLIST" >/dev/null 2>&1 \
    || launchctl load "$AGENT_PLIST" >/dev/null 2>&1 || true
fi

# Launch the menu-bar app — but ONLY if launchd has not already done it.
#
# The login agent plist carries RunAtLoad=true (see loginAgentPlist in
# desktop/autostart_darwin.go), so the bootstrap above starts APGO.app by
# itself. Calling `open` unconditionally after that produced TWO running
# instances: one launched by launchd directly from the executable, one via
# LaunchServices. macOS does not collapse them, because only the second went
# through LaunchServices — so you get two menu-bar icons, two admin panels
# fighting over the same port, and two writers on ~/.apgo.
#
# Give launchd a moment, then check. This also covers the plain case where
# autostart is off and nothing has started the app at all.
if (( HAD_LOGIN_AGENT )); then
  for _i in $(seq 1 10); do
    pgrep -x APGO >/dev/null 2>&1 && break
    sleep 0.3
  done
fi

if pgrep -x APGO >/dev/null 2>&1; then
  log "APGO already started by its login agent — not opening a second copy."
else
  log "Launching APGO…"
  # A menu-bar (GUI) app must launch as the logged-in user, not root. If this
  # script was run with sudo, drop back to the invoking user to open it — and
  # open by path (more reliable than -a right after install).
  if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" open "/Applications/APGO.app" || warn "Could not auto-launch — open /Applications/APGO.app yourself."
  else
    open "/Applications/APGO.app" || warn "Could not auto-launch — open /Applications/APGO.app yourself."
  fi
fi

# Belt and braces: if anything above raced and produced two, drop the extras.
# Keeping the OLDEST is deliberate — that is the launchd-supervised one, so
# killing it would only get it restarted.
_apgo_pids="$(pgrep -x APGO 2>/dev/null | sort -n || true)"
if [[ "$(echo "$_apgo_pids" | grep -c . || true)" -gt 1 ]]; then
  warn "More than one APGO instance is running — keeping the first, closing the rest."
  echo "$_apgo_pids" | tail -n +2 | while read -r _p; do
    [[ -n "$_p" ]] && kill "$_p" 2>/dev/null || true
  done
fi

# Verify the client actually came up, instead of reporting success and leaving
# the person to discover otherwise. Only meaningful when the boot daemon was
# restored — without it the client starts when you click Connect, not now.
if (( HAD_BOOT_DAEMON )); then
  log "Waiting for the overlay client…"
  _up=0
  for _i in $(seq 1 20); do
    if pgrep -x overlay-client >/dev/null 2>&1; then _up=1; break; fi
    sleep 0.5
  done
  if (( _up )); then
    log "Overlay client is running (pid $(pgrep -x overlay-client | head -1))."
  else
    warn "Overlay client did not start within 10s — check ~/.apgo/overlay-client.log"
    warn "and 'sudo launchctl print system/com.apgo.client' for the launchd error."
  fi
fi

echo
log "Installed and updated: /Applications/APGO.app"
echo "Click the menu-bar mesh icon → Settings… (one window) → Connect."
echo "Log:  ~/.apgo/overlay-client.log  (also via the app's \"Open log\" item)"
