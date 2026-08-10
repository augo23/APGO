#!/usr/bin/env bash
#
# One-shot APK build: installs every prerequisite (Go, gomobile, JDK 17,
# Android SDK + NDK, Gradle), builds the overlay core into an .aar, then
# assembles a debug APK. Works on macOS (Homebrew) and Debian/Ubuntu (apt).
# Re-runnable: each step is skipped if already satisfied.
#
# Output: app/build/outputs/apk/debug/app-debug.apk
set -euo pipefail

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

ANDROID_DIR="$(cd "$(dirname "$0")" && pwd)"
OS="$(uname -s)"

# --- package-manager helpers ------------------------------------------------
pm_install() { # pm_install <brew-name> <apt-name>
  if [ "$OS" = "Darwin" ]; then brew install "$1"
  else sudo apt-get update -y && sudo apt-get install -y "$2"; fi
}

# --- 1. Base toolchains -----------------------------------------------------
if [ "$OS" = "Darwin" ] && ! command -v brew >/dev/null 2>&1; then
  say "Installing Homebrew…"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if   [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -x /usr/local/bin/brew ];    then eval "$(/usr/local/bin/brew shellenv)"; fi
fi

command -v go   >/dev/null 2>&1 || { say "Installing Go…";   pm_install go golang-go; }
command -v git  >/dev/null 2>&1 || pm_install git git
command -v unzip >/dev/null 2>&1 || pm_install unzip unzip
say "Go: $(go version)"

# JDK 17
if ! /usr/libexec/java_home -v 17 >/dev/null 2>&1 && ! (command -v javac >/dev/null 2>&1 && javac -version 2>&1 | grep -q ' 17'); then
  say "Installing JDK 17…"
  if [ "$OS" = "Darwin" ]; then brew install openjdk@17; else sudo apt-get install -y openjdk-17-jdk; fi
fi
if [ "$OS" = "Darwin" ]; then export JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"; fi

# gomobile / gobind
export PATH="$(go env GOPATH)/bin:$PATH"
command -v gomobile >/dev/null 2>&1 || {
  say "Installing gomobile + gobind…"
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
}

# --- 2. Android SDK + NDK ---------------------------------------------------
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-$HOME/Android/sdk}}"
export ANDROID_HOME ANDROID_SDK_ROOT="$ANDROID_HOME"
SDKMGR="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "$SDKMGR" ]; then
  say "Installing Android command-line tools into ${ANDROID_HOME}…"
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  case "$OS" in
    Darwin) CLT_URL="https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip";;
    *)      CLT_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip";;
  esac
  tmp="$(mktemp -d)"
  curl -fsSL "$CLT_URL" -o "$tmp/clt.zip"
  unzip -q "$tmp/clt.zip" -d "$tmp"
  mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
  mv "$tmp/cmdline-tools/"* "$ANDROID_HOME/cmdline-tools/latest/"
  rm -rf "$tmp"
fi

say "Accepting SDK licenses and installing platform, build-tools, NDK…"
yes | "$SDKMGR" --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
"$SDKMGR" --sdk_root="$ANDROID_HOME" \
  "platform-tools" "platforms;android-34" "build-tools;34.0.0" "ndk;26.3.11579264" >/dev/null
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.3.11579264"

# Tell Gradle where the SDK is.
echo "sdk.dir=$ANDROID_HOME" > "$ANDROID_DIR/local.properties"

# --- 3. gomobile init + build the .aar --------------------------------------
say "Initializing gomobile (uses the NDK above)…"
gomobile init || warn "gomobile init reported an issue; continuing."
say "Building overlay core .aar…"
bash "$ANDROID_DIR/build-aar.sh"

# --- 4. Gradle ---------------------------------------------------------------
cd "$ANDROID_DIR"
if [ -x ./gradlew ]; then
  GRADLE="./gradlew"
elif command -v gradle >/dev/null 2>&1; then
  say "Generating Gradle wrapper…"
  gradle wrapper --gradle-version 8.7 >/dev/null
  GRADLE="./gradlew"
else
  say "Installing Gradle…"
  pm_install gradle gradle
  gradle wrapper --gradle-version 8.7 >/dev/null || true
  GRADLE="$([ -x ./gradlew ] && echo ./gradlew || echo gradle)"
fi

say "Assembling debug APK…"
$GRADLE :app:assembleDebug

APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
say "Done. APK: $APK"
echo "Install on a device with:  adb install -r \"$APK\""
