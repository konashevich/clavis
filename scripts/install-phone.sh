#!/bin/bash
# Install and launch the holder on the NAS phone. ADB runs only inside the queue.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
apk="$root/runs/clavis-holder-debug.apk"
serial=R5CT92MDXRH
if [[ ! -f "$apk" ]]; then
  echo "missing $apk" >&2
  exit 1
fi

dump=$(/home/pi/.local/bin/android-device-queue run --project CLAVIS -- bash -lc \
  "adb -s $serial install -r '$apk' && adb -s $serial shell am start -n clavis.holder/.MainActivity && sleep 2 && adb -s $serial shell uiautomator dump /sdcard/clavis-ui.xml >/dev/null && adb -s $serial shell cat /sdcard/clavis-ui.xml")

printf '%s\n' "$dump"
printf '%s\n' "$dump" | grep -F 'Согласие' >/dev/null
printf '%s\n' "$dump" | grep -F 'ed25519' >/dev/null
echo "consent screen shows the Rust profile"
