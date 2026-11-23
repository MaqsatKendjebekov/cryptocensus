#!/bin/bash
# Builds every release asset into target/dist on an Apple Silicon Mac with Docker (about 3 GB free):
#   macOS arm64 and x86_64 (native), Linux arm64 and x86_64 (static musl, Docker),
#   Windows x86_64 (mingw, Docker), .deb for apt (amd64, arm64), .pkg.tar.zst for pacman
#   (x86_64), SHA256SUMS, plus the Homebrew formula (target/cryptocensus.rb) and the AUR
#   PKGBUILD (packaging/aur) filled in with the real checksums.
# Publish, in this order: commit and git push origin master; git tag vVERSION and
# git push origin vVERSION; gh release create vVERSION --verify-tag target/dist/*; then
# commit target/cryptocensus.rb to the homebrew-tap repo as Formula/cryptocensus.rb and
# push packaging/aur to the AUR repo cryptocensus-bin.
set -euo pipefail
cd "$(dirname "$0")"
V=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
REPO=cryptocensus/cryptocensus
D=target/dist
rm -rf "$D"; mkdir -p "$D"
CACHE=(-v cc-cargo-registry:/usr/local/cargo/registry)
tgz() { tar -czf "$D/cryptocensus-$1.tar.gz" -C "$2" cryptocensus; }
sum() { shasum -a 256 "$D/$1" | cut -d' ' -f1; }

echo "== macOS"
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --quiet --target "$t"
  tgz "$t" "target/$t/release"
done

echo "== Linux (static musl)"
for a in aarch64:arm64 x86_64:amd64; do
  docker run --rm --platform "linux/${a#*:}" -v "$PWD":/src -w /src "${CACHE[@]}" rust:1-alpine \
    cargo build --release --quiet --target-dir "target/linux-${a%%:*}"
  tgz "${a%%:*}-unknown-linux-musl" "target/linux-${a%%:*}/release"
done

echo "== Windows"
# mingw-w64-gcc is packaged for x86_64 Alpine only
docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src "${CACHE[@]}" \
  -e RUSTFLAGS="-C target-feature=+crt-static" rust:1-alpine sh -c \
  'apk add -q mingw-w64-gcc && rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1 &&
   cargo build --release --quiet --target x86_64-pc-windows-gnu --target-dir target/win'
zip -q -j "$D/cryptocensus-x86_64-pc-windows-gnu.zip" target/win/x86_64-pc-windows-gnu/release/cryptocensus.exe

echo "== .deb (apt)"
for a in amd64:x86_64 arm64:aarch64; do
  P="target/deb-${a%%:*}"
  rm -rf "$P"; mkdir -p "$P/DEBIAN" "$P/usr/bin"
  cp "target/linux-${a#*:}/release/cryptocensus" "$P/usr/bin/"
  cat > "$P/DEBIAN/control" <<EOF
Package: cryptocensus
Version: $V
Architecture: ${a%%:*}
Maintainer: CryptoCensus <cryptocensus@users.noreply.github.com>
Section: net
Priority: optional
Installed-Size: $(du -sk "$P/usr" | cut -f1)
Homepage: https://github.com/$REPO
Suggests: openssh-client
Description: SSH and TLS crypto audit with post-quantum readiness scoring
 CryptoCensus reads the cryptography that SSH and TLS servers advertise, grades
 every algorithm for post-quantum readiness, proves weak ones with a live key
 exchange, and writes a hardened sshd config and a CycloneDX CBOM.
EOF
done
docker run --rm -v "$PWD":/src -w /src debian:stable-slim sh -c \
  'for a in amd64 arm64; do dpkg-deb --root-owner-group --build target/deb-$a target/dist/cryptocensus_$a.deb >/dev/null; done'

echo "== .pkg.tar.zst (pacman) and the AUR files"
P=target/arch
rm -rf "$P"; mkdir -p "$P/local" "$P/aur"
cp target/linux-x86_64/release/cryptocensus "$P/local/"
cat > "$P/local/PKGBUILD" <<EOF
pkgname=cryptocensus
pkgver=$V
pkgrel=1
pkgdesc="SSH and TLS crypto audit with post-quantum readiness scoring"
arch=('x86_64')
url="https://github.com/$REPO"
license=('unknown')
options=('!strip' '!debug')
source=('cryptocensus')
sha256sums=('SKIP')
package() { install -Dm755 "\$srcdir/cryptocensus" "\$pkgdir/usr/bin/cryptocensus"; }
EOF
U="https://github.com/$REPO/releases/download/v\$pkgver"
cat > "$P/aur/PKGBUILD" <<EOF
# Maintainer: CryptoCensus <cryptocensus@users.noreply.github.com>
pkgname=cryptocensus-bin
pkgver=$V
pkgrel=1
pkgdesc="SSH and TLS crypto audit with post-quantum readiness scoring (release binary)"
arch=('x86_64' 'aarch64')
url="https://github.com/$REPO"
license=('unknown')
provides=('cryptocensus')
conflicts=('cryptocensus')
options=('!strip' '!debug')
source_x86_64=("cryptocensus-\$pkgver-x86_64.tar.gz::$U/cryptocensus-x86_64-unknown-linux-musl.tar.gz")
source_aarch64=("cryptocensus-\$pkgver-aarch64.tar.gz::$U/cryptocensus-aarch64-unknown-linux-musl.tar.gz")
sha256sums_x86_64=('$(sum cryptocensus-x86_64-unknown-linux-musl.tar.gz)')
sha256sums_aarch64=('$(sum cryptocensus-aarch64-unknown-linux-musl.tar.gz)')
package() { install -Dm755 "\$srcdir/cryptocensus" "\$pkgdir/usr/bin/cryptocensus"; }
EOF
# makepkg refuses root and a bind mount may not be writable for another user, so build in /b
# (--disable-sandbox: pacman 7's download sandbox needs seccomp, which x86 emulation lacks)
docker run --rm --platform linux/amd64 -v "$PWD/$P":/pkg archlinux:latest bash -c \
  'pacman -Sy --noconfirm --needed --disable-sandbox fakeroot >/dev/null && useradd -m b &&
   cp -r /pkg/local /b && cp -r /pkg/aur /b/aur && chown -R b /b &&
   su b -c "cd /b && makepkg -f >/dev/null && cd /b/aur && makepkg --printsrcinfo > .SRCINFO" &&
   pacman -U --noconfirm /b/cryptocensus-*.pkg.tar.zst >/dev/null && cryptocensus --version &&
   cp /b/cryptocensus-*.pkg.tar.zst /pkg/ && cp /b/aur/.SRCINFO /pkg/aur/'
cp "$P"/cryptocensus-*-x86_64.pkg.tar.zst "$D/cryptocensus-x86_64.pkg.tar.zst"
mkdir -p packaging/aur
cp "$P/aur/PKGBUILD" "$P/aur/.SRCINFO" packaging/aur/

echo "== checksums and the Homebrew formula"
(cd "$D" && shasum -a 256 cryptocensus* > SHA256SUMS)
U="https://github.com/$REPO/releases/download/v$V"
cat > target/cryptocensus.rb <<EOF
class Cryptocensus < Formula
  desc "SSH and TLS crypto audit with post-quantum readiness scoring"
  homepage "https://github.com/$REPO"

  on_macos do
    on_arm do
      url "$U/cryptocensus-aarch64-apple-darwin.tar.gz"
      sha256 "$(sum cryptocensus-aarch64-apple-darwin.tar.gz)"
    end
    on_intel do
      url "$U/cryptocensus-x86_64-apple-darwin.tar.gz"
      sha256 "$(sum cryptocensus-x86_64-apple-darwin.tar.gz)"
    end
  end

  on_linux do
    on_arm do
      url "$U/cryptocensus-aarch64-unknown-linux-musl.tar.gz"
      sha256 "$(sum cryptocensus-aarch64-unknown-linux-musl.tar.gz)"
    end
    on_intel do
      url "$U/cryptocensus-x86_64-unknown-linux-musl.tar.gz"
      sha256 "$(sum cryptocensus-x86_64-unknown-linux-musl.tar.gz)"
    end
  end

  def install
    bin.install "cryptocensus"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cryptocensus --version")
  end
end
EOF
ls -la "$D"
cat "$D/SHA256SUMS"
