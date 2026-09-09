#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --release -p mailbench
swift build --package-path macos -c release
app_dir="$PWD/dist/Mailbench.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp target/release/mailbench "$app_dir/Contents/Resources/mailbench"
cp macos/.build/release/Mailbench "$app_dir/Contents/MacOS/Mailbench"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Mailbench</string>
<key>CFBundleIdentifier</key><string>io.mailtoolkit.mailbench</string>
<key>CFBundleExecutable</key><string>Mailbench</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$app_dir/Contents/Resources/mailbench"
codesign --force --sign - "$app_dir"
echo "Built $app_dir (local ad-hoc signature; not notarized)"
