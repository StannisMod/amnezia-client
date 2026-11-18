#!/usr/bin/env bash
# emulator-runner executes each script input line in a separate sh process.
# Keep compound commands in this file so their shell scope is preserved.
set -euo pipefail
transport=${1:?transport required}
api=${2:?API required}
source_sha=$(python3 -c 'import json;print(json.load(open("tested-apk-source.json"))["head_sha"])')
if [[ "$transport" == awg && "$api" != 28 ]]; then
    kill "$(cat "$RUNNER_TEMP/fixture.pid")"
    rm -f "$RUNNER_TEMP/fixture.pid"
    sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT python3 scripts/routing/xray_ipv6_fixture.py \
        --xray "$RUNNER_TEMP/xray-fixture" --work "$RUNNER_TEMP/xray-peer" > xray-fixture.log 2>&1 &
    echo $! > "$RUNNER_TEMP/xray-fixture.pid"
    for i in $(seq 1 30); do
        sudo test -s "$RUNNER_TEMP/xray-peer/fixture.json" && break
        sleep 1
    done
    sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT env "PATH=$PATH" "ANDROID_HOME=$ANDROID_HOME" \
        "ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$ANDROID_HOME}" python3 scripts/routing/run_android_acceptance.py \
        --xray-ipv6-only --apk "$FEATURE_APK" --fixture "$RUNNER_TEMP/xray-peer/fixture.json" \
        --quic-probe "$RUNNER_TEMP/android-traffic-probe" --quic-ca "$RUNNER_TEMP/xray-peer/quic.der" \
        --work "$RUNNER_TEMP/android-xray-ipv6" --apk-source-sha "$source_sha"
    # OpenVPN owns some of the same synthetic loopback destinations. Let
    # Xray's SIGTERM/finally cleanup release them before the next fixture.
    xray_pid=$(cat "$RUNNER_TEMP/xray-fixture.pid")
    sudo kill -TERM "$xray_pid"
    wait "$xray_pid" || [[ $? == 143 ]]
    rm -f "$RUNNER_TEMP/xray-fixture.pid"
fi
if [[ "$transport" == awg && ( "$api" == 35 || "$api" == 28 ) ]]; then
    sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT env "PATH=$PATH" "ANDROID_HOME=$ANDROID_HOME" \
        "ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$ANDROID_HOME}" python3 scripts/routing/run_android_openvpn_acceptance.py \
        --apk "$FEATURE_APK" --work "$RUNNER_TEMP/android-openvpn-ipv6" --apk-source-sha "$source_sha"
fi
