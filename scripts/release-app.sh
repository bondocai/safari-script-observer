#!/bin/zsh
# Builds a Release version signed with your Developer ID, has Apple notarize it,
# attaches the notarization ticket, and installs it in ~/Applications. Safari
# then treats the extension as properly signed: it stays on across restarts,
# without "Allow unsigned extensions".
#
#   scripts/release-app.sh
#
# Needs, once (with your own Apple ID; never stored in this repository):
#   1. Xcode > Settings > Accounts > Manage Certificates > + > Developer ID Application
#   2. An app-specific password (account.apple.com > Sign-In and Security)
#   3. xcrun notarytool store-credentials "safari-observer-notary" --apple-id <you> --team-id <team>
set -euo pipefail

here=${0:A:h}
project="$here/../xcode/Safari Script Observer"
out="$here/../xcode/release"
app="$out/export/Safari Script Observer.app"
installed="$HOME/Applications/Safari Script Observer.app"
team=${TEAM:?Set TEAM to your Apple Developer team ID, e.g. TEAM=ABCDE12345}
profile=${NOTARY_PROFILE:-safari-observer-notary}

identity=$(security find-identity -v -p codesigning | awk -v t="($team)" '/"Developer ID Application: / && index($0, t) {print $2; exit}')
if [[ -z $identity ]]; then
  print "No Developer ID Application certificate for team $team in your Keychain (step 1 above)." >&2
  exit 1
fi
if ! xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1; then
  print "No notarization credentials stored as \"$profile\" (step 3 above)." >&2
  exit 1
fi

# Scripts sharing a page must not declare the same name twice (the later one
# would not run at all).
if ! node "$here/../eval/scope-check.mjs" >/dev/null; then
  node "$here/../eval/scope-check.mjs" | grep FAIL >&2
  print "Fix the extension's scripts before releasing." >&2
  exit 1
fi

print "Building and exporting for Developer ID distribution..."
# Archive, then export with method "developer-id": the export re-signs the app for
# distribution and leaves out development-only entitlements (get-task-allow).
rm -rf "$out"
mkdir -p "$out"
cat > "$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>Developer ID Application</string>
  <key>teamID</key><string>$team</string>
</dict></plist>
PLIST
# Build products stay inside $out (not Xcode's shared DerivedData), so no stray copy
# of the app is left where macOS could register it.
(cd "$project" && xcodebuild -scheme "Safari Script Observer" -configuration Release -archivePath "$out/app.xcarchive" \
  -derivedDataPath "$out/derived" \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$identity" DEVELOPMENT_TEAM="$team" PROVISIONING_PROFILE_SPECIFIER="" \
  ENABLE_HARDENED_RUNTIME=YES OTHER_CODE_SIGN_FLAGS="--timestamp" \
  archive 2>&1 | grep -E "^\*\* ARCHIVE|error:")
xcodebuild -exportArchive -archivePath "$out/app.xcarchive" -exportPath "$out/export" \
  -exportOptionsPlist "$out/ExportOptions.plist" 2>&1 | grep -E "^\*\* EXPORT|error:"
codesign --verify --deep --strict "$app"
# Safari extensions must be sandboxed; Apple rejects builds that allow debugging.
for part in "$app" "$app/Contents/PlugIns/Safari Script Observer Extension.appex"; do
  if ! codesign -d --entitlements - "$part" 2>/dev/null | grep -q app-sandbox; then
    print "${part:t} is not sandboxed." >&2
    exit 1
  fi
done
if codesign -d --entitlements - "$app" 2>/dev/null | grep -q get-task-allow; then
  print "The build carries the debugging entitlement (get-task-allow); Apple would reject it." >&2
  exit 1
fi

# Every file the extension's manifest names must be in the app: the Xcode project
# lists extension files one by one, and a new file left off that list makes the
# background script fail to load in Safari.
resources="$app/Contents/PlugIns/Safari Script Observer Extension.appex/Contents/Resources"
missing=$(/usr/bin/python3 -I - "$resources" "$here/../extension" <<'PY'
import json, os, sys
bundle, source = sys.argv[1], sys.argv[2]
manifest = json.load(open(os.path.join(source, "manifest.json")))
wanted = set(manifest["background"]["scripts"])
wanted |= {f for c in manifest["content_scripts"] for f in c["js"]}
wanted |= {f for w in manifest.get("web_accessible_resources", []) for f in w["resources"]}
wanted |= {manifest["action"]["default_popup"], manifest["options_ui"]["page"]}
wanted |= {f for f in os.listdir(source) if f.endswith((".js", ".html"))}
print(" ".join(sorted(f for f in wanted if not os.path.exists(os.path.join(bundle, f)))))
PY
)
if [[ -n $missing ]]; then
  print "Not in the app (add them to the Xcode project's extension resources): $missing" >&2
  exit 1
fi

print "Sending to Apple for notarization (usually a few minutes)..."
zip="$out/Safari Script Observer.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait
xcrun stapler staple "$app"
spctl --assess --type execute -vv "$app"

print "Installing in ~/Applications..."
mkdir -p "$HOME/Applications"
rm -rf "$installed"
ditto "$app" "$installed"
# Exactly one copy for Safari: every other build of the app (same identity) is
# unregistered and the intermediate ones deleted. Otherwise Safari may load a
# copy that isn't notarized at launch and switch the extension off.
for copy in "$here/../xcode/build/Build/Products/Debug/Safari Script Observer.app" "$app" \
            "$out/app.xcarchive/Products/Applications/Safari Script Observer.app" \
            "$out/derived/Build/Intermediates.noindex/ArchiveIntermediates/Safari Script Observer/InstallationBuildProductsLocation/Applications/Safari Script Observer.app"; do
  pluginkit -r "$copy/Contents/PlugIns/Safari Script Observer Extension.appex" 2>/dev/null || true
done
rm -rf "$out/app.xcarchive" "$out/derived" "$out/export"
open "$installed"
sleep 2
copies=$(pluginkit -m -A -D -v -i com.example.SafariScriptObserver.Extension | grep -c "\.appex$" || true)
pluginkit -m -A -D -v -i com.example.SafariScriptObserver.Extension
[[ $copies == 1 ]] || print "Warning: $copies registered copies of the extension; Safari should see exactly one." >&2
print "\nDone. In Safari: Settings > Extensions > tick Safari Script Observer; then untick Develop > Allow Unsigned Extensions."
