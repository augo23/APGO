#!/usr/bin/env bash
#
# bump-build.sh — increment the iOS build number (CURRENT_PROJECT_VERSION) in
# project.yml. Run before `xcodegen generate`; mac-ios-easy.sh does this for you.
#
#     bash ios/bump-build.sh               version patch +1 AND build +1
#                                          (1.0.1 build 2 -> 1.0.2 build 3)
#     bash ios/bump-build.sh --build-only  build number only, version untouched
#     bash ios/bump-build.sh --show        print the current versions, change nothing
#
# WHY THE BUILD NUMBER AND THE MARKETING VERSION MOVE SEPARATELY
#
# App Store Connect enforces two different rules, and conflating them is what
# produces the confusing rejections:
#
#   * CURRENT_PROJECT_VERSION (CFBundleVersion) must be UNIQUE for every upload,
#     forever. Re-uploading byte-identical code needs a new build number. It is
#     invisible to users. So this is bumped automatically, every time.
#
#   * MARKETING_VERSION (CFBundleShortVersionString) must be HIGHER than the
#     last APPROVED version (error 90062), and a released version's pre-release
#     train closes to new builds (90186). It is what users see.
#
# Both are bumped by default here, so every run produces a version that App
# Store Connect will accept under either rule without anyone having to work out
# which one applies. The cost is that version numbers advance for builds that
# are never submitted -- the counter runs ahead of what shipped. That is a
# cosmetic price for never hitting a rejection after a full archive and upload.
# Use --build-only when iterating locally and you would rather not spend a
# version number.
#
# Both Info.plist files read these via $(...), so this one file is the source of
# truth for the app and its network extension together — they must match, or
# Apple rejects the pair.

set -euo pipefail
cd "$(dirname "$0")"

PROJ="project.yml"
[[ -f "$PROJ" ]] || { echo "ERROR: $PROJ not found" >&2; exit 1; }

read_val() { sed -n "s/^[[:space:]]*$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$PROJ" | head -1; }

CUR_BUILD="$(read_val CURRENT_PROJECT_VERSION)"
CUR_MKT="$(read_val MARKETING_VERSION)"

MODE="${1:-}"
case "$MODE" in
  --show)
    echo "MARKETING_VERSION=$CUR_MKT  CURRENT_PROJECT_VERSION=$CUR_BUILD"
    exit 0 ;;
  ""|--build-only|--marketing) ;;   # --marketing kept as a no-op alias: it is now the default
  *) echo "unknown option: $MODE (try --build-only or --show)" >&2; exit 1 ;;
esac

[[ "$CUR_BUILD" =~ ^[0-9]+$ ]] || {
  echo "ERROR: CURRENT_PROJECT_VERSION is '$CUR_BUILD', which is not a plain integer." >&2
  echo "       Fix it in $PROJ before using this script." >&2
  exit 1
}
NEW_BUILD=$(( CUR_BUILD + 1 ))

NEW_MKT="$CUR_MKT"
if [[ "$MODE" != "--build-only" ]]; then
  if [[ "$CUR_MKT" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    NEW_MKT="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$(( BASH_REMATCH[3] + 1 ))"
  elif [[ "$CUR_MKT" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
    # "1.0" -> "1.0.1": adding a patch component is the smallest increase that
    # still counts as higher, so a released 1.0 is superseded without spending
    # 1.1 on what may just be a bug fix.
    NEW_MKT="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.1"
  else
    echo "ERROR: MARKETING_VERSION '$CUR_MKT' is not x.y or x.y.z — bump it by hand." >&2
    exit 1
  fi
fi

# Edit in place. Anchored to the key at the start of a line so a version-looking
# string elsewhere in the file cannot be hit by accident.
tmp="$(mktemp)"
sed -e "s/^\([[:space:]]*CURRENT_PROJECT_VERSION:[[:space:]]*\).*$/\1\"$NEW_BUILD\"/" \
    -e "s/^\([[:space:]]*MARKETING_VERSION:[[:space:]]*\).*$/\1\"$NEW_MKT\"/" \
    "$PROJ" > "$tmp"

# Verify before replacing: a bad sed that emptied the value would otherwise be
# discovered by App Store Connect rather than here.
if ! grep -q "CURRENT_PROJECT_VERSION: \"$NEW_BUILD\"" "$tmp" \
   || ! grep -q "MARKETING_VERSION: \"$NEW_MKT\"" "$tmp"; then
  rm -f "$tmp"
  echo "ERROR: rewrite did not produce the expected values — $PROJ left unchanged." >&2
  exit 1
fi
# Write through the existing file rather than renaming over it: a rename
# replaces the inode, which loses file permissions on some setups and is
# refused outright on others (network mounts, sandboxed folders). `cat >` keeps
# the original file and only changes its contents.
cat "$tmp" > "$PROJ"
rm -f "$tmp"

if [[ "$NEW_MKT" != "$CUR_MKT" ]]; then
  echo "==> version $CUR_MKT -> $NEW_MKT, build $CUR_BUILD -> $NEW_BUILD"
else
  echo "==> build $CUR_BUILD -> $NEW_BUILD (version $NEW_MKT unchanged)"
fi
