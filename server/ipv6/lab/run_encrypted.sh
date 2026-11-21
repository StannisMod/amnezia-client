set -eu
python3 - <<'GUARD'
import json,subprocess
assert {row['ifname'] for row in json.loads(subprocess.check_output(['ip','-j','link']))} == {'lo'}, 'requires Docker --network none'
GUARD
mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then mknod /dev/net/tun c 10 200; fi
exec unshare --mount --net --fork sh -ec '
mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
ip link set lo up
export AMNEZIA_IPV6_LAB=isolated-namespace
exec /app/engine.test -test.run TestEncryptedIPv6KernelEgress -test.v -test.timeout 90s
'
