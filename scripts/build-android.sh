#!/bin/bash
# Compile the Android holder. Beast does the heavy compile when it answers.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
runs="$root/runs"
mkdir -p "$runs"

share=/home/pi/Documents/shared/hosts/beast
key_name=$(sed -n 's/^ssh -i \([^ ]*\).*/\1/p' "$share/HOW_TO_SSH.txt" | head -1)
tmp_key=$(mktemp)
cp "$share/$key_name" "$tmp_key"
chmod 600 "$tmp_key"
cleanup() { rm -f "$tmp_key"; }
trap cleanup EXIT

ssh_beast=(ssh -i "$tmp_key" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes)
beast=beast@192.168.1.112

beast_up=0
if ping -c 1 -W 2 192.168.1.112 >/dev/null 2>&1 && "${ssh_beast[@]}" "$beast" 'true' >/dev/null 2>&1; then
  beast_up=1
fi

if [[ "$beast_up" -ne 1 ]]; then
  echo "Beast does not answer. Android compile stays on this computer." >&2
  echo "This script's NAS fallback is not configured: the Android SDK lives on Beast." >&2
  exit 1
fi

rsync -az --delete \
  --exclude target \
  --exclude .git \
  --exclude runs \
  --exclude '.gradle' \
  --exclude 'apps/android/app/build' \
  --exclude 'apps/android/local.properties' \
  --exclude 'apps/android/app/src/main/jniLibs' \
  -e "ssh -i $tmp_key -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes" \
  "$root/" "$beast:/home/beast/src/clavis/"

"${ssh_beast[@]}" "$beast" 'bash -s' << 'REMOTE'
set -euo pipefail
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/home/beast/Android/Sdk
export PATH="$HOME/.cargo/bin:$JAVA_HOME/bin:$PATH"
if [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  . "$HOME/.cargo/env"
fi
rustup target add aarch64-linux-android
ndk="$ANDROID_HOME/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$ndk/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$ndk/llvm-ar"
cd /home/beast/src/clavis
cargo build -p clavis-ffi --target aarch64-linux-android
jni=/home/beast/src/clavis/apps/android/app/src/main/jniLibs/arm64-v8a
mkdir -p "$jni"
cp target/aarch64-linux-android/debug/libclavis_ffi.so "$jni/"
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > /home/beast/src/clavis/apps/android/local.properties
gradle_home=/home/beast/sdks/gradle-8.7
if [[ ! -x "$gradle_home/bin/gradle" ]]; then
  mkdir -p /home/beast/sdks
  curl -fsSL -o /tmp/gradle-8.7-bin.zip https://services.gradle.org/distributions/gradle-8.7-bin.zip
  unzip -qo /tmp/gradle-8.7-bin.zip -d /home/beast/sdks
fi
if [[ ! -e /usr/lib/jvm/java-17-openjdk-arm64 ]]; then
  extra=(-Dorg.gradle.java.home=/usr/lib/jvm/java-17-openjdk-amd64)
else
  extra=()
fi
cd /home/beast/src/clavis/apps/android
"$gradle_home/bin/gradle" --no-daemon "${extra[@]}" assembleDebug
REMOTE

scp -i "$tmp_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  "$beast:/home/beast/src/clavis/apps/android/app/build/outputs/apk/debug/app-debug.apk" \
  "$runs/clavis-holder-debug.apk"
echo "$runs/clavis-holder-debug.apk"
