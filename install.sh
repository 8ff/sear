#!/bin/sh
set -eu

REPO="8ff/sear"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    i386|i686) ARCH="386" ;;
    *) printf "Unsupported architecture: %s\n" "$ARCH" >&2; exit 1 ;;
esac

case "$OS" in
    linux|darwin|freebsd|openbsd) ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) printf "Unsupported OS: %s\n" "$OS" >&2; exit 1 ;;
esac

EXT=""
if [ "$OS" = "windows" ]; then EXT=".exe"; fi
BINARY="sear-${OS}-${ARCH}${EXT}"

VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
if [ -z "$VERSION" ]; then
    printf "Failed to fetch latest version\n" >&2
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"
printf "Installing sear %s (%s/%s) to %s\n" "$VERSION" "$OS" "$ARCH" "$INSTALL_DIR"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

curl -fsSL -o "$TMP" "$URL"
chmod +x "$TMP"
mv "$TMP" "${INSTALL_DIR}/sear${EXT}"

printf "Done: sear %s\n" "$("${INSTALL_DIR}/sear${EXT}" version 2>/dev/null || echo "$VERSION")"
