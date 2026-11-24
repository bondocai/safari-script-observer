#!/bin/zsh
# Builds the app with your Apple Development certificate and installs it in
# ~/Applications, the copy Safari uses.
#
#   scripts/install-app.sh            (TEAM=<team id> to pick another team)
#
# Development only: Safari treats a development-signed extension as unsigned
# (it needs "Allow unsigned extensions" after every restart), and this replaces
# the notarized copy in ~/Applications. For everyday use run release-app.sh.
set -euo pipefail

here=${0:A:h}
project="$here/../xcode/Safari Script Observer"
built="$here/../xcode/build/Build/Products/Debug/Safari Script Observer.app"
installed="$HOME/Applications/Safari Script Observer.app"
team=${TEAM:?Set TEAM to your Apple Developer team ID, e.g. TEAM=ABCDE12345}

# The newest "Apple Development" certificate of the team (by hash: several may share a name).
identity=$(security find-identity -v -p codesigning | awk '/"Apple Development: /{print $2}' | while read -r hash; do
  subject=$(security find-certificate -a -Z -p | awk -v h="$hash" '/SHA-1 hash:/{p=($3==h)} p' |
            sed -n '/BEGIN/,/END/p' | openssl x509 -noout -subject -enddate 2>/dev/null | tr '\n' ' ')
  [[ $subject == *"OU=$team"* ]] && print -r -- "${subject##*notAfter=}|$hash"
done | sort -t'|' -k1 | tail -1 | cut -d'|' -f2)
if [[ -z $identity ]]; then
  print "No Apple Development certificate for team $team. In Xcode: Settings > Accounts > Manage Certificates > +." >&2
  exit 1
fi

print "Building, signed by team $team..."
(cd "$project" && xcodebuild -scheme "Safari Script Observer" -configuration Debug -derivedDataPath ../build \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$identity" DEVELOPMENT_TEAM="$team" PROVISIONING_PROFILE_SPECIFIER="" \
  build 2>&1 | grep -E "^\*\* BUILD|error:" )
codesign --verify --deep --strict "$built"

print "Installing in ~/Applications..."
mkdir -p "$HOME/Applications"
rm -rf "$installed"
ditto "$built" "$installed"
codesign --verify --deep --strict "$installed"

# One copy only: Safari should use the installed app, not the build folder.
pluginkit -r "$built/Contents/PlugIns/Safari Script Observer Extension.appex" 2>/dev/null || true
open "$installed"
sleep 2
pluginkit -m -v -i com.example.SafariScriptObserver.Extension
print "\nInstalled $(defaults read "$installed/Contents/Info" CFBundleShortVersionString 2>/dev/null || true):" \
      "extension $(grep '"version"' "$installed/Contents/PlugIns/Safari Script Observer Extension.appex/Contents/Resources/manifest.json" | tr -dc '0-9.')"
print "In Safari: Settings > Extensions > tick Safari Script Observer (once)."
