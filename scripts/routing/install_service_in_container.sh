#!/bin/bash
set -euo pipefail
package=$1
helper=$2
QT_QPA_PLATFORM=offscreen "$package" --root /opt/AmneziaVPN --accept-licenses --default-answer --confirm-command install
systemctl daemon-reload
if [[ -n "$helper" ]]; then
    systemctl stop AmneziaVPN
    mapfile -t helpers < <(find /opt/AmneziaVPN -type f -name amnezia-routing)
    test "${#helpers[@]}" -eq 1
    install -m 0755 "$helper" "${helpers[0]}"
fi
systemctl restart AmneziaVPN
