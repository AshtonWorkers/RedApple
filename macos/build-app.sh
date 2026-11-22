#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo "RedApple.app requires macOS and Xcode Command Line Tools." >&2
    exit 1
fi

PACKAGE_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$PACKAGE_DIR/dist"
APP="$OUTPUT/RedApple.app"
swift build --package-path "$PACKAGE_DIR" --configuration release
BIN_DIR="$(swift build --package-path "$PACKAGE_DIR" --configuration release --show-bin-path)"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/RedApple" "$APP/Contents/MacOS/RedApple"
cp "$PACKAGE_DIR/Info.plist" "$APP/Contents/Info.plist"
# SwiftPM puts Bundle.module resources in a sibling .bundle on macOS.
for bundle in "$BIN_DIR/"*.bundle; do
    [[ -d "$bundle" ]] || continue
    ditto "$bundle" "$APP/Contents/Resources/$(basename "$bundle")"
done
printf 'APPL????' > "$APP/Contents/PkgInfo"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
ditto -c -k --keepParent "$APP" "$OUTPUT/RedApple-macOS.zip"
echo "Built $APP"
echo "Run: open \"$APP\""
