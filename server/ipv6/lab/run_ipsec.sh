set -eu
[ -f /.dockerenv ] || { echo 'requires disposable Docker container' >&2; exit 64; }
mkdir -p /run/netns
exec unshare --mount --net --fork sh -ec '
mount --make-rprivate /
mount -t tmpfs tmpfs /run/netns
exec python3 /app/test_ipsec.py
'
