#!/bin/bash
# Build libclavis_ffi.a for the iOS device target. Fail if the SDK or the archive is missing.
set -euo pipefail

project_dir=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$project_dir/../.." && pwd)

if [ -n "${HOME:-}" ] && [ -x "${HOME}/.cargo/bin/cargo" ]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

if ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
  echo "error: Apple iOS SDK is not available" >&2
  exit 1
fi

cd "$repo"
cargo rustc -p clavis-ffi --crate-type staticlib --target aarch64-apple-ios --no-default-features

lib="${repo}/target/aarch64-apple-ios/debug/libclavis_ffi.a"
if [ ! -s "$lib" ]; then
  echo "error: staticlib was not produced: ${lib}" >&2
  exit 1
fi
