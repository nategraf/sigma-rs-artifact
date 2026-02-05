#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/ios/OoniAuthBindings"
HEADER_DIR="$ROOT/ooniauth-ffi/include"

build_target() {
  local target="$1"
  cargo build -p ooniauth-ffi --release --target "$target"
}

build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios

LIB_DEVICE="$ROOT/target/aarch64-apple-ios/release/libooniauth_ffi.a"
LIB_SIM="$ROOT/target/aarch64-apple-ios-sim/release/libooniauth_ffi.a"
LIB_SIM_X86="$ROOT/target/x86_64-apple-ios/release/libooniauth_ffi.a"
LIB_SIM_UNIVERSAL="$ROOT/target/ios-sim-universal/libooniauth_ffi.a"

mkdir -p "$(dirname "$LIB_SIM_UNIVERSAL")"
if command -v lipo >/dev/null 2>&1; then
  lipo -create "$LIB_SIM" "$LIB_SIM_X86" -output "$LIB_SIM_UNIVERSAL"
else
  echo "error: lipo not found; cannot create universal simulator library" >&2
  exit 1
fi

rm -rf "$OUT_DIR/OoniAuthFFI.xcframework"

xcodebuild -create-xcframework \
  -library "$LIB_DEVICE" -headers "$HEADER_DIR" \
  -library "$LIB_SIM_UNIVERSAL" -headers "$HEADER_DIR" \
  -output "$OUT_DIR/OoniAuthFFI.xcframework"

echo "Generated $OUT_DIR/OoniAuthFFI.xcframework"
