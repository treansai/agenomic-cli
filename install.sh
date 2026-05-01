#!/usr/bin/env bash
# Install the latest agentlock CLI.
# Usage: curl -fsSL https://agentlock.dev/install.sh | sh
set -eu

REPO="agentlock/agentlock-cli"
VERSION="${AGENTLOCK_VERSION:-latest}"
INSTALL_DIR="${AGENTLOCK_INSTALL_DIR:-$HOME/.local/bin}"

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

archive="agentlock-${target}.tar.gz"
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
mv "$tmp/agentlock-${target}" "$INSTALL_DIR/agentlock"
chmod +x "$INSTALL_DIR/agentlock"

echo "installed agentlock to $INSTALL_DIR/agentlock"
echo "ensure $INSTALL_DIR is in your PATH"
