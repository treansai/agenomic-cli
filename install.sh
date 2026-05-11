#!/usr/bin/env bash
# Install the latest agenomic CLI.
# Usage: curl -fsSL https://agenomic.dev/install.sh | sh
set -eu

REPO="agenomic/agenomic-cli"
VERSION="${AGENOMIC_VERSION:-latest}"
INSTALL_DIR="${AGENOMIC_INSTALL_DIR:-$HOME/.local/bin}"

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
  url_base="https://github.com/$REPO/releases/latest/download"
else
  url_base="https://github.com/$REPO/releases/download/$VERSION"
fi

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

(cd "$tmp" && grep "$archive" checksums.txt | shasum -a 256 -c -) || {
  echo "checksum verification failed" >&2
  exit 1
}

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
