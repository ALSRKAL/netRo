#!/usr/bin/env bash
# Build release artifacts for the current host platform.
# Cross-platform release builds are produced by .github/workflows/release.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux) PLATFORM="linux" ;;
  darwin) PLATFORM="macos" ;;
  mingw*|msys*|cygwin*) PLATFORM="windows" ;;
  *) PLATFORM="$OS" ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH_NAME="x64" ;;
  aarch64|arm64) ARCH_NAME="arm64" ;;
  *) ARCH_NAME="$ARCH" ;;
esac

echo "building netro $VERSION for $PLATFORM-$ARCH_NAME"
cargo build --release --all-features

mkdir -p dist
if [[ "$PLATFORM" == "windows" ]]; then
  ARTIFACT="netro-windows-${ARCH_NAME}.exe"
  cp "target/release/netro.exe" "dist/$ARTIFACT"
else
  ARTIFACT="netro-${PLATFORM}-${ARCH_NAME}"
  cp "target/release/netro" "dist/$ARTIFACT"
  chmod +x "dist/$ARTIFACT"
fi
./target/release/netro version > dist/VERSION.txt
echo "artifact: dist/$ARTIFACT"
cat dist/VERSION.txt
