#!/bin/sh
# CryptoCensus installer. One command, no sudo:
#   curl -fsSL https://raw.githubusercontent.com/MaqsatKendjebekov/cryptocensus/master/install.sh | sh
# It downloads the release binary for this OS and CPU, checks its SHA-256 against the
# release's SHA256SUMS, runs the binary's self-test, and only then installs it to ~/.local/bin.
# Options (environment): CRYPTOCENSUS_BIN_DIR (default ~/.local/bin),
# CRYPTOCENSUS_VERSION (default latest, or a release such as 1.1.0).
set -eu

REPO="MaqsatKendjebekov/cryptocensus"
BIN_DIR="${CRYPTOCENSUS_BIN_DIR:-$HOME/.local/bin}"
VERSION="${CRYPTOCENSUS_VERSION:-latest}"
SRC="cargo install --locked --git https://github.com/$REPO"

say() { printf '  %s\n' "$*"; }
die() { printf '  error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-musl ;;
  MINGW* | MSYS* | CYGWIN*) die "on Windows run this in PowerShell: irm https://raw.githubusercontent.com/$REPO/master/install.ps1 | iex" ;;
  *) die "no prebuilt binary for $(uname -s). Build it from source: $SRC" ;;
esac
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) die "no prebuilt binary for $(uname -m). Build it from source: $SRC" ;;
esac
# a shell running under Rosetta reports x86_64 on Apple Silicon: take the native build
if [ "$os" = apple-darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then arch=aarch64; fi
target="$arch-$os"
asset="cryptocensus-$target.tar.gz"
case "$VERSION" in
  latest) base="https://github.com/$REPO/releases/latest/download" ;;
  *) base="https://github.com/$REPO/releases/download/v${VERSION#v}" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "needs curl or wget"; fi
}
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

say "downloading cryptocensus ($target, $VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
want=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
got=$(sha256 "$tmp/$asset")
[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $asset, nothing installed"
say "checksum ok"
tar -xzf "$tmp/$asset" -C "$tmp"

# run the new binary before it replaces anything
version=$("$tmp/cryptocensus" --version) || die "the binary does not run on this system, nothing installed"
check=$("$tmp/cryptocensus" selftest --no-color 2>&1) || {
  printf '%s\n' "$check" | tail -n 5 >&2
  die "self-test failed, nothing installed"
}

mkdir -p "$BIN_DIR"
# copy then rename, so a running copy is never overwritten in place
cp "$tmp/cryptocensus" "$BIN_DIR/.cryptocensus.new"
chmod 755 "$BIN_DIR/.cryptocensus.new"
mv -f "$BIN_DIR/.cryptocensus.new" "$BIN_DIR/cryptocensus"
say "$version installed to $BIN_DIR"
say "$(printf '%s\n' "$check" | tail -n 1)"

found=$(command -v cryptocensus 2>/dev/null || true)
if [ -z "$found" ]; then
  case "$(basename "${SHELL:-sh}")" in
    fish) say "add it to your PATH:  fish_add_path $BIN_DIR" ;;
    zsh) say "add it to your PATH:  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc  (then open a new terminal)" ;;
    bash) say "add it to your PATH:  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc  (then open a new terminal)" ;;
    *) say "add it to your PATH:  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile  (then log in again)" ;;
  esac
elif [ "$found" != "$BIN_DIR/cryptocensus" ]; then
  say "note: $found comes first in your PATH and runs instead of this one"
fi
say "try:  cryptocensus scan --targets <server IP> --out audit"
say "only scan systems you own or are allowed to test"
