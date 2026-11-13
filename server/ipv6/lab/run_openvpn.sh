set -eu
[ -f /.dockerenv ] || { echo "requires disposable Docker container" >&2; exit 64; }
mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then mknod /dev/net/tun c 10 200; fi
exec unshare --mount --net --fork sh -ec '
mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
exec python3 /app/test_openvpn.py
'
