#!/usr/bin/env bash
# Install the latest agenomic CLI.
# Usage: curl -fsSL https://agenomic.io/install.sh | sh
set -eu

REPO="treansai/agenomic-cli"
VERSION="${AGENOMIC_VERSION:-latest}"
INSTALL_DIR="${AGENOMIC_INSTALL_DIR:-$HOME/.local/bin}"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  else
    wget -qO- "$1"
  fi
}

resolve_latest_tag() {
  # GitHub's /releases/latest endpoint excludes prereleases; use /releases
  # and pick the first entry so the installer works before a stable release.
  fetch "https://api.github.com/repos/$REPO/releases" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n1
}

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s/$uname_m" in
  Linux/x86_64)   target="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64)  target="aarch64-unknown-linux-gnu" ;;
  Linux/arm64)    target="aarch64-unknown-linux-gnu" ;;
  Darwin/x86_64)  target="x86_64-apple-darwin" ;;
  Darwin/arm64)   target="aarch64-apple-darwin" ;;
  *)
    echo "unsupported platform: $uname_s/$uname_m" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$(resolve_latest_tag)"
  if [ -z "$VERSION" ]; then
    echo "failed to resolve latest release tag for $REPO" >&2
    exit 1
  fi
fi
url_base="https://github.com/$REPO/releases/download/$VERSION"

archive="agenomic-${target}.tar.gz"
url="$url_base/$archive"

mkdir -p "$INSTALL_DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp/$archive"
  curl -fsSL "$url_base/checksums.txt" -o "$tmp/checksums.txt"
else
  wget -qO "$tmp/$archive" "$url"
  wget -qO "$tmp/checksums.txt" "$url_base/checksums.txt"
fi

# checksums.txt may list archives bare (`agenomic-<t>.tar.gz`) or under a
# per-target subdir (`./agenomic-<t>/agenomic-<t>.tar.gz`) depending on the
# release workflow. Match by basename and verify by recomputing.
expected="$(awk -v a="$archive" '
  {
    path = $2
    sub(/^\.\//, "", path)
    n = split(path, parts, "/")
    if (parts[n] == a) { print $1; exit }
  }
' "$tmp/checksums.txt")"

if [ -z "$expected" ]; then
  echo "no checksum entry for $archive in checksums.txt" >&2
  exit 1
fi

actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"

if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch for $archive" >&2
  echo "  expected: $expected" >&2
  echo "  actual:   $actual" >&2
  exit 1
fi

tar -xzf "$tmp/$archive" -C "$tmp"
src="$tmp/agenomic-${target}"

for bin in agenomic agm; do
  if [ -f "$src/$bin" ]; then
    mv "$src/$bin" "$INSTALL_DIR/$bin"
    chmod +x "$INSTALL_DIR/$bin"
    echo "installed $bin to $INSTALL_DIR/$bin"
  fi
done

echo "ensure $INSTALL_DIR is in your PATH"
