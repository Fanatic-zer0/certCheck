#!/bin/bash

# Build Certcheck.app - Creates macOS app bundle with icon
# No Xcode required! Uses Swift Package Manager + macOS command-line tools

set -e

APP_NAME="Certcheck"
BUNDLE_ID="com.certcheck.app"
VERSION="1.0.0"
ICON_SOURCE="Resources/icon.png"

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   🔨 Building ${APP_NAME}.app with Icon       ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -f "Package.swift" ]; then
    echo "❌ Error: Not in Certcheck directory"
    exit 1
fi

# Step 1: Build the executable
echo "📦 Step 1/5: Building Swift executable..."
swift build -c release
echo "   ✅ Build complete"
echo ""

# Step 2: Create app bundle structure
echo "🏗️  Step 2/5: Creating app bundle structure..."
APP_DIR="${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

# Remove old bundle if exists
rm -rf "${APP_DIR}"

# Create directories
mkdir -p "${MACOS_DIR}"
mkdir -p "${RESOURCES_DIR}"

echo "   ✅ Created ${APP_DIR}/Contents/{MacOS,Resources}"
echo ""

# Step 3: Copy executable
echo "📋 Step 3/5: Installing executable..."
cp ".build/release/${APP_NAME}" "${MACOS_DIR}/${APP_NAME}"
chmod +x "${MACOS_DIR}/${APP_NAME}"
echo "   ✅ Executable installed"
echo ""

# Step 4: Create Info.plist
echo "📄 Step 4/5: Creating Info.plist..."
cat > "${CONTENTS_DIR}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 Certcheck. All rights reserved.</string>
</dict>
</plist>
EOF
echo "   ✅ Info.plist created"
echo ""

# Step 5: Create app icon
echo "🎨 Step 5/5: Creating app icon..."

if [ -f "${ICON_SOURCE}" ]; then
    # Create iconset directory
    ICONSET_DIR="${RESOURCES_DIR}/AppIcon.iconset"
    mkdir -p "${ICONSET_DIR}"
    
    # Generate all required icon sizes using sips
    echo "   📐 Generating icon sizes..."
    
    # Standard resolutions
    sips -z 16 16     "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_16x16.png" > /dev/null 2>&1
    sips -z 32 32     "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_16x16@2x.png" > /dev/null 2>&1
    sips -z 32 32     "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_32x32.png" > /dev/null 2>&1
    sips -z 64 64     "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_32x32@2x.png" > /dev/null 2>&1
    sips -z 128 128   "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_128x128.png" > /dev/null 2>&1
    sips -z 256 256   "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_128x128@2x.png" > /dev/null 2>&1
    sips -z 256 256   "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_256x256.png" > /dev/null 2>&1
    sips -z 512 512   "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_256x256@2x.png" > /dev/null 2>&1
    sips -z 512 512   "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_512x512.png" > /dev/null 2>&1
    sips -z 1024 1024 "${ICON_SOURCE}" --out "${ICONSET_DIR}/icon_512x512@2x.png" > /dev/null 2>&1
    
    # Convert iconset to icns
    iconutil -c icns "${ICONSET_DIR}" -o "${RESOURCES_DIR}/AppIcon.icns"
    
    # Clean up iconset directory
    rm -rf "${ICONSET_DIR}"
    
    echo "   ✅ App icon created (AppIcon.icns)"
else
    echo "   ⚠️  No icon found at ${ICON_SOURCE}"
    echo "   💡 To add an icon:"
    echo "      1. Save your PNG image as Resources/icon.png"
    echo "      2. Run this script again"
    echo ""
    echo "   📱 App will use default icon for now"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║            ✅ BUILD COMPLETE!                 ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "📦 App bundle created: ${APP_DIR}"
echo ""
echo "🚀 Launch Options:"
echo ""
echo "   Double-click: open ${APP_DIR}"
echo "   Command line: open ${APP_DIR}"
echo "   Direct exec:  ${APP_DIR}/Contents/MacOS/${APP_NAME}"
echo ""

# Check if icon was added
if [ -f "${RESOURCES_DIR}/AppIcon.icns" ]; then
    echo "🎨 Icon: ✅ Included"
else
    echo "🎨 Icon: ⚠️  Using default (add Resources/icon.png and rebuild)"
fi

echo ""
echo "💡 Tips:"
echo "   • Drag ${APP_DIR} to Applications folder to install"
echo "   • Drag to Dock for quick access"
echo "   • First launch may ask for security permission"
echo ""
