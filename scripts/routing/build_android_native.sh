#!/usr/bin/env bash
# Reproducible unified AWG/routing JNI payload; caller supplies the Android SDK
# and Go version pinned by native/routing/go.mod. No standalone Go .so is added.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
: "${RUNNER_TEMP:?Set RUNNER_TEMP to a private build directory}"
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK}"
: "${ABI:?Set ABI to an existing supported Android ABI}"
output="${1:?Supply the absolute output directory}"
export GOTOOLCHAIN=local GOTELEMETRY=off
git clone --depth 1 --branch v3.1.20260814 https://github.com/amnezia-vpn/amneziawg-android.git "$RUNNER_TEMP/routing-awg"
test "$(git -C "$RUNNER_TEMP/routing-awg" rev-parse HEAD)" = 5c16489e2cd9ed3a0a7a27c7445bba5238132f86
python3 "$repo/native/routing/prepare_android.py" --module "$RUNNER_TEMP/routing-awg/tunnel/tools/libwg-go" --go-root "$(go env GOROOT)" --patched-go-root "$RUNNER_TEMP/routing-go"
export GOROOT="$RUNNER_TEMP/routing-go"
export PATH="$GOROOT/bin:$PATH"
case "$ABI" in
  arm64-v8a) export GOARCH=arm64; target=aarch64-linux-android28 ;;
  armeabi-v7a) export GOARCH=arm GOARM=7; target=armv7a-linux-androideabi28 ;;
  x86) export GOARCH=386; target=i686-linux-android28 ;;
  x86_64) export GOARCH=amd64; target=x86_64-linux-android28 ;;
  *) exit 1 ;;
esac
tools="$ANDROID_HOME/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC="$tools/$target-clang"
export CGO_ENABLED=1 GOOS=android
export CGO_LDFLAGS='-Wl,-soname=libwg-go.so -Wl,-z,max-page-size=16384'
mkdir -p "$output"
(cd "$RUNNER_TEMP/routing-awg/tunnel/tools/libwg-go" && go build -mod=readonly -tags linux,with_gvisor,amnezia_android_bridge -trimpath -buildvcs=false -buildmode=c-shared -o "$output/libwg-go.so" .)
"$tools/llvm-readelf" --dyn-syms -W "$output/libwg-go.so" > "$output/symbols.txt"
for symbol in Java_org_amnezia_awg_GoBackend_awgTurnOn Java_org_amnezia_awg_RoutingBackend_validate Java_org_amnezia_awg_RoutingBackend_start Java_org_amnezia_awg_RoutingBackend_stop Java_org_amnezia_awg_RoutingBackend_stats; do
  grep -F "$symbol" "$output/symbols.txt"
done
test "$(grep -c '_cgo_topofstack$' "$output/symbols.txt")" = 1
"$tools/llvm-readelf" -l -W "$output/libwg-go.so" > "$output/elf-layout.txt"
sha256sum "$output/libwg-go.so" > "$output/SHA256SUMS"
