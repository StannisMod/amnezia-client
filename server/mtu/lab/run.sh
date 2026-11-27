#!/bin/bash
set -euo pipefail
python3 - <<'PY'
import json,pathlib,subprocess
assert pathlib.Path('/.dockerenv').exists()
assert {r['ifname'] for r in json.loads(subprocess.check_output(['ip','-j','link']))}=={'lo'}
PY
mkdir -p /results
export AMNEZIA_STABILITY_REPRO=1 AMNEZIA_STABILITY_SEQUENCE=1 AMNEZIA_STABILITY_NO_OUTAGES=1 AMNEZIA_STABILITY_KERNEL_PEER=1 AMNEZIA_STABILITY_LAB=isolated-namespace AMNEZIA_MTU_LAB=1
export AMNEZIA_STABILITY_HELPER=/bin/lab/amnezia-routing AMNEZIA_STABILITY_TRACE=/results
exec unshare --mount --net --fork bash -ec 'mount --make-rprivate /; ip link set lo up; mkdir -p /run/netns; mount -t tmpfs tmpfs /run/netns; exec /bin/lab/engine.test -test.run "^TestConnectionStabilityReproduction$/^amneziawg$/^IPv4$/" -test.v -test.timeout 180s'
