#!/bin/zsh
# Checks the Mac app's HTTP code (SafariWebExtensionHandler.swift) without Safari:
# investigation lookups reach only public addresses (also via names and redirects),
# the model server on the local network still works, responses stop at 2 MB, and
# slow-dripping servers are cut off. Uses a local test server on 127.0.0.1:8799,
# plus example.com, localtest.me (a public name for 127.0.0.1) and postman-echo.com
# (a public redirect service), so it needs internet access.
#
#   eval/native-check/run.sh
set -euo pipefail
here=${0:A:h}
work=$(mktemp -d)
trap 'kill $server 2>/dev/null; rm -rf "$work"' EXIT
# The handler's request method is private; the test copy makes it callable.
sed 's/    private func runHTTP/    func runHTTP/' \
  "$here/../../xcode/Safari Script Observer/Safari Script Observer Extension/SafariWebExtensionHandler.swift" > "$work/handler.swift"
xcrun swiftc -swift-version 5 -target arm64-apple-macos26.0 "$work/handler.swift" "$here/main.swift" -o "$work/check"
node "$here/server.mjs" & server=$!
sleep 1
"$work/check" | tee "$work/out.txt"
! grep -q FAIL "$work/out.txt" && print "\nAll checks passed."
