#!/bin/bash
set -e

APP_NAME="Certcheck"
DMG_NAME="${APP_NAME}.dmg"
STAGING="dist_staging"
VERSION=1.0.1

echo "╔══════════════════════════════════════╗"
echo "║   Certcheck — Distribution Builder   ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Build the .app bundle ─────────────────────────────────────────────────
echo "▶ Building ${APP_NAME}.app …"
./build-app.sh 2>&1 | grep -E "✅|BUILD COMPLETE|error:" || true

if [ ! -d "${APP_NAME}.app" ]; then
  echo "❌ Build failed — ${APP_NAME}.app not found"
  exit 1
fi
echo "✅ App bundle ready"

# ── 2. Remove any Apple quarantine attributes ─────────────────────────────────
# This prevents Gatekeeper blocking the copy you keep locally.
xattr -rc "${APP_NAME}.app" 2>/dev/null || true

# ── 3. Build the DMG staging folder ──────────────────────────────────────────
rm -rf "${STAGING}"
mkdir -p "${STAGING}"
cp -r "${APP_NAME}.app" "${STAGING}/"
# Symlink to /Applications so users can drag-to-install
ln -sf /Applications "${STAGING}/Applications"

# Add a simple readme for recipients
cat > "${STAGING}/README – First Launch.txt" << 'EOF'
Certcheck – How to open on macOS
══════════════════════════════════

macOS blocks apps that are not from the App Store or a notarised developer.
Choose ONE of the options below:

Option A  (easiest – one command)
  Open Terminal and run:
    xattr -rd com.apple.quarantine /path/to/Certcheck.app
  Then double-click the app normally.

Option B  (right-click method)
  1. Right-click Certcheck.app
  2. Click "Open"
  3. Click "Open" again in the dialog that appears
  This only needs to be done once.

Option C  (System Settings)
  1. Try to open the app — macOS will block it.
  2. Open System Settings → Privacy & Security
  3. Scroll down and click "Open Anyway" next to Certcheck.
EOF

# ── 4. Create the DMG ─────────────────────────────────────────────────────────
rm -f "${DMG_NAME}"
echo ""
echo "▶ Creating ${DMG_NAME} …"
hdiutil create \
  -volname "${APP_NAME}" \
  -srcfolder "${STAGING}" \
  -ov \
  -format UDZO \
  -o "${DMG_NAME}" \
  > /dev/null

rm -rf "${STAGING}"

# ── 5. Summary ────────────────────────────────────────────────────────────────
DMG_SIZE=$(du -sh "${DMG_NAME}" | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║            ✅ DISTRIBUTION READY              ║"
echo "╠══════════════════════════════════════════════╣"
printf  "║  File   : %-34s ║\n" "${DMG_NAME}"
printf  "║  Size   : %-34s ║\n" "${DMG_SIZE}"
printf  "║  Version: %-34s ║\n" "${VERSION}"
echo "╠══════════════════════════════════════════════╣"
echo "║  Share the .dmg — recipients:               ║"
echo "║   • Drag Certcheck.app → Applications       ║"
echo "║   • Right-click → Open (first launch)       ║"
echo "╚══════════════════════════════════════════════╝"
