#!/usr/bin/env bash
# Creates an AppImage for jwtdebug from a GoReleaser build artifact.
# Called as a post-build hook for each Linux target.
#
# Usage: build-appimage.sh <artifact_path> <project_name> <version>
#   artifact_path: path to the built binary (e.g. dist/jwtdebug_linux_amd64/jwtdebug)

set -euo pipefail

BINARY_PATH="${1:?Usage: build-appimage.sh <binary_path> <project_name> <version>}"
PROJECT="${2:?}"
VERSION="${3:?}"

# Skip if this isn't a Linux binary (shouldn't happen with current config, but be safe)
case "${BINARY_PATH}" in
  *_linux_*) ;;
  *) exit 0 ;;
esac

# Derive arch from artifact dir name.
# GoReleaser dirs look like: linux_linux_amd64_v1 or linux_linux_arm64_v8.0
ARTIFACT_DIR="$(dirname "${BINARY_PATH}")"
RAW_ARCH="${ARTIFACT_DIR##*_linux_}"
# Strip _v* suffix (e.g. amd64_v1 -> amd64, arm64_v8.0 -> arm64)
ARCH="${RAW_ARCH%%_v*}"
case "${ARCH}" in
  amd64) APPIMAGE_ARCH="x86_64" ;;
  arm64) APPIMAGE_ARCH="aarch64" ;;
  *) echo "WARNING: unsupported arch ${RAW_ARCH}, skipping AppImage"; exit 0 ;;
esac

APPDIR="$(mktemp -d)"
DIST_DIR="$(dirname "${ARTIFACT_DIR}")"
OUTPUT="${DIST_DIR}/${PROJECT}-${VERSION}-${APPIMAGE_ARCH}.AppImage"

# Build AppDir layout
mkdir -p "${APPDIR}/usr/bin"
cp "${BINARY_PATH}" "${APPDIR}/usr/bin/${PROJECT}"
chmod 755 "${APPDIR}/usr/bin/${PROJECT}"

# AppRun (symlink to binary)
ln -s "usr/bin/${PROJECT}" "${APPDIR}/AppRun"

# .desktop file
cat > "${APPDIR}/${PROJECT}.desktop" <<DESKTOP
[Desktop Entry]
Name=${PROJECT}
Exec=${PROJECT}
Icon=${PROJECT}
Type=Application
Categories=Development;
Terminal=true
Comment=Decode and debug JSON Web Tokens
DESKTOP

# Copy icon if present, otherwise use a placeholder
if [ -f packaging/icon.png ]; then
  cp packaging/icon.png "${APPDIR}/${PROJECT}.png"
else
  # Minimal 1x1 transparent PNG as placeholder
  printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > "${APPDIR}/${PROJECT}.png"
fi

# AppStream metadata
mkdir -p "${APPDIR}/usr/share/metainfo"
cat > "${APPDIR}/usr/share/metainfo/${PROJECT}.appdata.xml" <<'META'
<?xml version="1.0" encoding="UTF-8"?>
<component type="console-application">
  <id>com.github.rselbach.jwtdebug</id>
  <name>jwtdebug</name>
  <summary>Decode and debug JSON Web Tokens</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <url type="homepage">https://github.com/rselbach/jwtdebug</url>
  <description>
    <p>jwtdebug is a command-line tool for decoding, inspecting, and verifying
    JSON Web Tokens (JWTs). Tokens are processed locally and never leave
    your machine.</p>
  </description>
</component>
META

# Build the AppImage
if command -v appimagetool &>/dev/null; then
  TOOL=appimagetool
elif command -v AppImageKit &>/dev/null; then
  TOOL=AppImageKit
else
  echo "ERROR: appimagetool not found" >&2
  rm -rf "${APPDIR}"
  exit 1
fi

ARCH="${APPIMAGE_ARCH}" "${TOOL}" --no-appstream --appimage-extract-and-run \
  "${APPDIR}" "${OUTPUT}" 2>/dev/null \
  || ARCH="${APPIMAGE_ARCH}" "${TOOL}" --no-appstream \
  "${APPDIR}" "${OUTPUT}"

chmod 755 "${OUTPUT}"
echo "Created AppImage: $(basename "${OUTPUT}")"

rm -rf "${APPDIR}"
