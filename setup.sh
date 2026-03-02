#!/bin/bash
# Torxy Setup - Downloads Tor Expert Bundle for all platforms
# Run this once: ./setup.sh

set -e
cd "$(dirname "$0")"

VERSION="15.0.7"
BASE="https://dist.torproject.org/torbrowser"
PLATFORMS="macos-aarch64:macos:aarch64 macos-x86_64:macos:x86_64 linux-x86_64:linux:x86_64 windows-x86_64:windows:x86_64"

# Use Homebrew curl (OpenSSL) if available, since system curl (LibreSSL) 
# often fails TLS negotiation with dist.torproject.org
if [ -x /opt/homebrew/opt/curl/bin/curl ]; then
    CURL=/opt/homebrew/opt/curl/bin/curl
elif [ -x /usr/local/opt/curl/bin/curl ]; then
    CURL=/usr/local/opt/curl/bin/curl
else
    CURL=curl
    echo "NOTE: Using system curl. If downloads fail with SSL errors, run:"
    echo "  brew install curl"
    echo "Then re-run this script."
    echo ""
fi

echo "Using: $($CURL --version | head -1)"
echo ""

for ENTRY in $PLATFORMS; do
    IFS=: read -r FOLDER OS ARCH <<< "$ENTRY"
    FILE="tor-expert-bundle-${OS}-${ARCH}-${VERSION}.tar.gz"
    URL="${BASE}/${VERSION}/${FILE}"
    DEST="bin/${FOLDER}"

    mkdir -p "$DEST"

    if [ -f "$DEST/tor/tor" ] || [ -f "$DEST/tor/tor.exe" ]; then
        echo "[skip] ${FOLDER} - already extracted"
        continue
    fi

    echo "[download] ${FILE}"
    $CURL -fSL --connect-timeout 20 -o "${DEST}/${FILE}" "${URL}"

    echo "[extract]  -> ${DEST}/"
    tar xzf "${DEST}/${FILE}" -C "${DEST}"
    rm "${DEST}/${FILE}"
done

# Make tor binaries executable and clear macOS quarantine
find bin -name "tor" -type f -exec chmod +x {} \;
if [ "$(uname)" = "Darwin" ]; then
    echo "Clearing macOS quarantine flags..."
    xattr -cr bin/ 2>/dev/null
    find bin -name "tor" -type f -exec codesign --force --deep --sign - {} \; 2>/dev/null
    find bin -name "*.dylib" -type f -exec codesign --force --deep --sign - {} \; 2>/dev/null
fi

echo ""
echo "Done! Bundled Tor binaries:"
for d in bin/*/tor; do
    [ -d "$d" ] && echo "  $d/ ($(ls -1 "$d" | wc -l | tr -d ' ') files)"
done
