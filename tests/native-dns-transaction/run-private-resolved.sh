#!/bin/sh
# Run only in a caller-created container network namespace, never on the host.
set -eu
test "${AMNEZIA_NATIVE_DNS_SERVICE_TEST:-}" = isolated-namespace
test -d /host/usr/lib/x86_64-linux-gnu
runtime=/run/amnezia-private-resolved
mkdir -p "$runtime"
loader=/host/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
libraries=/host/usr/lib/x86_64-linux-gnu:/host/usr/lib/x86_64-linux-gnu/systemd
sha256sum /host/usr/bin/dbus-daemon /host/usr/lib/systemd/systemd-resolved
"$loader" --library-path "$libraries" /host/usr/lib/systemd/systemd-resolved --version
cat > "$runtime/bus.conf" <<EOF
<busconfig>
  <type>system</type>
  <listen>unix:path=$runtime/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
EOF
getent passwd systemd-resolve >/dev/null ||
    useradd --system --no-create-home --shell /usr/sbin/nologin systemd-resolve
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$runtime/bus"
"$loader" --library-path "$libraries" /host/usr/bin/dbus-daemon \
    --config-file="$runtime/bus.conf" --nofork > "$runtime/dbus.log" 2>&1 &
bus_pid=$!
resolved_pid=
cleanup() {
    if test -n "$resolved_pid"; then kill "$resolved_pid" 2>/dev/null || true; fi
    kill "$bus_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    cat "$runtime/dbus.log" "$runtime/resolved.log"
}
trap cleanup EXIT
ip link set lo up
# Wait for a real readiness condition, with a bounded startup deadline.
for attempt in $(seq 1 100); do
    test ! -S "$runtime/bus" || break
    kill -0 "$bus_pid"
    sleep 0.02
done
test -S "$runtime/bus"
mkdir -p /run/systemd/resolve
chown systemd-resolve:systemd-resolve /run/systemd/resolve
SYSTEMD_LOG_LEVEL=debug "$loader" --library-path "$libraries" \
    /host/usr/lib/systemd/systemd-resolved > "$runtime/resolved.log" 2>&1 &
resolved_pid=$!
ready=false
for attempt in $(seq 1 100); do
    if "$loader" --library-path "$libraries" /host/usr/bin/busctl \
        --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property org.freedesktop.resolve1 \
        /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager DNS >/dev/null 2>&1; then
        ready=true
        break
    fi
    kill -0 "$resolved_pid"
    sleep 0.02
done
test "$ready" = true
export AMNEZIA_DNS_REAL_RESOLVED=1
"$@"
