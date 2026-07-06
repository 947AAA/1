#!/bin/bash
# Build patch_kernel_root for Android ARM64
# Prerequisites:
#   - Rust toolchain: rustup target add aarch64-linux-android
#   - Android NDK: set NDK environment variable or install via Android Studio
#   - cargo-ndk: cargo install cargo-ndk

set -e

if ! command -v cargo-ndk &> /dev/null && [ -z "$CARGO_NDK" ]; then
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk
fi

echo "Building for Android ARM64 (arm64-v8a)..."
cargo ndk -t arm64-v8a -o output build --release

echo ""
echo "Binary: output/arm64-v8a/patch_kernel_root"
echo ""
echo "Usage on device:"
echo "  adb push output/arm64-v8a/patch_kernel_root /data/local/tmp/"
echo "  adb shell chmod +x /data/local/tmp/patch_kernel_root"
echo "  adb shell /data/local/tmp/patch_kernel_root -i /data/local/tmp/kernel --auto-key -o /data/local/tmp/kernel_patched"
