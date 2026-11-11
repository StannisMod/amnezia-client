set -eu
python3 - <<'GUARD'
import json,subprocess
assert {row['ifname'] for row in json.loads(subprocess.check_output(['ip','-j','link']))} == {'lo'}, 'requires Docker --network none'
GUARD
exec unshare --mount --net --fork sh -ec '
mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
exec python3 /app/test_forwarding.py
'
