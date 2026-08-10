# Building Certcheck.app with Icon

Complete guide to building a native macOS `.app` bundle with custom icon using **Swift only** (no Xcode required).

---

## 🚀 Quick Build

```bash
# With your custom icon
cp /path/to/your/certificate-badge.png Resources/icon.png
./build-app.sh

# Or build without icon (uses default)
./build-app.sh
```

That's it! You'll get `Certcheck.app` ready to use.

---

## 📋 What This Does

The `build-app.sh` script:

1. ✅ Builds Swift executable with `swift build -c release`
2. ✅ Creates proper macOS `.app` bundle structure
3. ✅ Converts PNG icon to `.icns` format (all sizes)
4. ✅ Generates `Info.plist` with app metadata
5. ✅ Makes it launchable like any Mac app
6. ✅ **No Xcode needed!** Uses only command-line tools

---

## 🎨 Adding Your Icon

### Option 1: Use Your Certificate Badge

```bash
# Save your certificate badge image
cp /path/to/badge.png Resources/icon.png

# Build
./build-app.sh
```

### Option 2: Create from Scratch

If you have a certificate icon/image:

```bash
# Make sure Resources directory exists
mkdir -p Resources

# Copy your PNG (any size, will be auto-resized)
cp ~/Downloads/cert-icon.png Resources/icon.png

# Build
./build-app.sh
```

### Option 3: Use Default Icon

Just run without adding an icon:

```bash
./build-app.sh
```

The app will use macOS default icon. You can add a custom icon later and rebuild.

---

## 📦 What Gets Created

```
Certcheck.app/
└── Contents/
    ├── Info.plist              # App metadata
    ├── MacOS/
    │   └── Certcheck          # Executable
    └── Resources/
        └── AppIcon.icns       # Your icon (all sizes)
```

This is a **proper macOS application bundle** that:
- Shows your icon in Finder
- Can be dragged to Applications folder
- Can be added to Dock
- Appears in Spotlight search
- Works like any native Mac app

---

## 🏃 Running the App

### Method 1: Double-Click (Finder)
```bash
open Certcheck.app
```

### Method 2: Command Line
```bash
./Certcheck.app/Contents/MacOS/Certcheck
```

### Method 3: Drag to Applications
```bash
# Install system-wide
cp -r Certcheck.app /Applications/

# Then launch from Spotlight or Launchpad
```

---

## 🔧 How the Icon Generation Works

The script uses macOS built-in tools:

1. **`sips`** - Resizes PNG to all required sizes:
   - 16x16, 32x32, 128x128, 256x256, 512x512, 1024x1024
   - Both regular and @2x retina versions
   
2. **`iconutil`** - Converts iconset to `.icns` format:
   ```bash
   iconutil -c icns AppIcon.iconset -o AppIcon.icns
   ```

3. **No external tools needed!** Everything is built-in to macOS.

---

## 📐 Icon Requirements

- **Format:** PNG (JPEG also works but PNG recommended)
- **Size:** Any size (will be auto-resized)
- **Recommended:** 1024x1024 for best quality
- **Minimum:** 512x512
- **Transparency:** Supported (PNG)
- **Location:** `Resources/icon.png`

---

## ⚠️ First Launch Security

When you first run the app, macOS may show:

> "Certcheck.app" cannot be opened because the developer cannot be verified.

**Solution:**
1. Go to System Settings → Privacy & Security
2. Click "Open Anyway" next to the Certcheck message
3. Or right-click app → Open (then click Open)

This only happens once per build.

---

## 🔄 Rebuilding

To rebuild with updated icon or code:

```bash
# Update your icon
cp /path/to/new-icon.png Resources/icon.png

# Rebuild
./build-app.sh

# The old .app is automatically replaced
```

---

## 📁 Installing System-Wide

```bash
# Copy to Applications folder
sudo cp -r Certcheck.app /Applications/

# Or just drag and drop in Finder!
```

Now it appears in:
- Spotlight search
- Launchpad
- Applications folder
- Can be added to Dock

---

## 🆚 Comparison: build-app.sh vs launch.sh

| Feature | `launch.sh` | `build-app.sh` |
|---------|-------------|----------------|
| Builds executable | ✅ | ✅ |
| Creates .app bundle | ❌ | ✅ |
| Custom icon | ❌ | ✅ |
| Launchable from Finder | ❌ | ✅ |
| Drag to Applications | ❌ | ✅ |
| Add to Dock | ❌ | ✅ |
| Runs immediately | ✅ | ❌ (run after) |

**Use `launch.sh` for:** Quick testing during development  
**Use `build-app.sh` for:** Creating distributable app with icon

---

## 💡 Pro Tips

### Tip 1: Quick Rebuild Workflow
```bash
# Make code changes
vim Sources/Certcheck/...

# Rebuild and launch
./build-app.sh && open Certcheck.app
```

### Tip 2: Keep in Dock
```bash
# Build and launch
./build-app.sh
open Certcheck.app

# Then right-click dock icon → Options → Keep in Dock
```

### Tip 3: Create Alias
```bash
# Add to ~/.zshrc or ~/.bashrc
alias certcheck="open /Applications/Certcheck.app"

# Then just run
certcheck
```

### Tip 4: Bundle Identifier
The app uses bundle ID: `com.certcheck.app`

Change it by editing `build-app.sh`:
```bash
BUNDLE_ID="com.yourcompany.certcheck"
```

### Tip 5: Verify Icon
```bash
# Check if icon was created
ls -lh Certcheck.app/Contents/Resources/AppIcon.icns

# View icon sizes
sips -g pixelWidth -g pixelHeight Certcheck.app/Contents/Resources/AppIcon.icns
```

---

## 🐛 Troubleshooting

### "Command not found: sips"
Not possible - `sips` is built into macOS. But if you see this:
```bash
which sips  # Should show: /usr/bin/sips
```

### "Command not found: iconutil"
Not possible - `iconutil` is built into macOS since 10.7. But:
```bash
which iconutil  # Should show: /usr/bin/iconutil
```

### Icon doesn't appear
1. Check if icon file exists:
   ```bash
   ls -lh Resources/icon.png
   ```
2. Rebuild:
   ```bash
   ./build-app.sh
   ```
3. Clear icon cache:
   ```bash
   sudo rm -rf /Library/Caches/com.apple.iconservices.store
   sudo find /private/var/folders/ -name com.apple.dock.iconcache -exec rm {} \;
   killall Dock
   ```

### App won't open
1. Check executable:
   ```bash
   ls -l Certcheck.app/Contents/MacOS/Certcheck  # Should be -rwxr-xr-x
   ```
2. Test directly:
   ```bash
   ./Certcheck.app/Contents/MacOS/Certcheck
   ```
3. Check for errors in Console.app

---

## 📊 Build Output Example

```
╔═══════════════════════════════════════════════╗
║   🔨 Building Certcheck.app with Icon         ║
╚═══════════════════════════════════════════════╝

📦 Step 1/5: Building Swift executable...
   ✅ Build complete

🏗️  Step 2/5: Creating app bundle structure...
   ✅ Created Certcheck.app/Contents/{MacOS,Resources}

📋 Step 3/5: Installing executable...
   ✅ Executable installed

📄 Step 4/5: Creating Info.plist...
   ✅ Info.plist created

🎨 Step 5/5: Creating app icon...
   📐 Generating icon sizes...
   ✅ App icon created (AppIcon.icns)

╔═══════════════════════════════════════════════╗
║            ✅ BUILD COMPLETE!                 ║
╚═══════════════════════════════════════════════╝

📦 App bundle created: Certcheck.app

🚀 Launch Options:

   Double-click: open Certcheck.app
   Command line: open Certcheck.app
   Direct exec:  Certcheck.app/Contents/MacOS/Certcheck

🎨 Icon: ✅ Included

💡 Tips:
   • Drag Certcheck.app to Applications folder to install
   • Drag to Dock for quick access
   • First launch may ask for security permission
```

---

## 🎯 Complete Workflow Example

```bash
# 1. Get your certificate badge icon
# (Download or create a 1024x1024 PNG)

# 2. Save it
cp ~/Downloads/certificate-badge.png Resources/icon.png

# 3. Build the app
./build-app.sh

# 4. Test it
open Certcheck.app

# 5. Install system-wide
sudo cp -r Certcheck.app /Applications/

# 6. Add to Dock (drag from Applications folder)

# Done! 🎉
```

---

## 🔍 Technical Details

### Info.plist Keys
The script generates a complete `Info.plist` with:
- `CFBundleIconFile` - Points to AppIcon.icns
- `CFBundleIdentifier` - Unique app ID
- `CFBundleExecutable` - Executable name
- `LSMinimumSystemVersion` - macOS 13.0+ required
- `NSHighResolutionCapable` - Retina display support

### Icon Sizes Generated
- 16x16, 16x16@2x (32x32)
- 32x32, 32x32@2x (64x64)
- 128x128, 128x128@2x (256x256)
- 256x256, 256x256@2x (512x512)
- 512x512, 512x512@2x (1024x1024)

All required for Finder, Dock, Spotlight, etc.

### Bundle Structure
Follows Apple's standard bundle layout:
- https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html

---

## ✅ Summary

**Yes, you can build with icon in Swift only!**

- ✅ No Xcode required
- ✅ Uses macOS built-in tools (sips, iconutil)
- ✅ Creates proper .app bundle
- ✅ Custom icon support (any PNG)
- ✅ Drag to Applications folder
- ✅ Add to Dock
- ✅ Appears in Spotlight
- ✅ Professional macOS app

Just run:
```bash
./build-app.sh
```

🎉 **That's it!**
