# AWG per-peer MTU controller prototype

Run inside the AWG server network namespace with Python 3, iproute2,
CAP_NET_RAW and CAP_NET_ADMIN.

    python3 controller.py --interface awg0 --source 10.8.1.1 \
      --peer 10.8.1.2 --peer 10.8.1.3 --maximum 1280 --interval 30

The source must be assigned to the server. Each selected peer must already
have a direct IPv4 /32 route on the interface with no explicit MTU metric.
Without --maximum the interface MTU is used, including non-multiples of 16.
An explicit maximum is capped at the interface MTU. No keys or profiles change.

Periodic checks run even during idle periods. Candidate sizes require two
of three replies. Large failures are checked alongside small successes.
Reduction applies immediately to that peer route. Raising requires three
consecutive complete checks with the same result. IP_PMTUDISC_PROBE allows
probes larger than the reduced route MTU. Decisions are JSON on stdout.

SIGTERM or Ctrl-C restores original routes if they still match our last
state. External route changes cause termination without overwriting the
changed route. One controller per interface is enforced with a lock.
SIGKILL or a power failure cannot perform restoration.

Scope: IPv4 and echo-responsive peers, primarily download. Echo traverses
both directions, so an upload limit can conservatively reduce download MTU.
Forwarded TCP recovery requires ICMP Fragmentation Needed reaching its
sender. No five-second guarantee, IPv6, automatic peer discovery, stall
trigger or installation integration yet. Test explicitly selected peers
before applying to a real server.

Validated in Docker with two peers on one AWG interface and an independent
Linux origin. MTU 1280 -> 1104 -> 1280, old TCP retained, healthy peer unchanged.

Production integration in this branch

The AWG startup script starts supervisor.py and stops it before tunnel restart.
The installer uploads both scripts and ensures Python/iproute2 on new or updated
containers. The supervisor reads only allowed-ips and latest-handshakes from
awg/wg, never private key dumps. It selects recently active IPv4 /32 peers.
Missing per-peer routes are created with protocol 186 and removed on shutdown
only when still matching their original owned state. Existing routes are retained.
IPv6 adaptation and global traffic-based stall detection remain unsupported.

Reproduce the encrypted integration test from repository root:

    docker build -f server/mtu/lab/Dockerfile -t awg-mtu-regression .
    mkdir -p mtu-results
    docker run --rm --init --network none --privileged --pids-limit 512 --memory 3g --cpus 4 -v "$PWD/mtu-results:/results" awg-mtu-regression

The container accepts only loopback on entry and creates its own fresh mount
and network namespaces. No Docker socket or host networking is mounted. Its two
real encrypted AWG peers use the production shared core. The independent Linux
origin supplies the original TLS download and websocket streams. A fixture
inventory command supplies allowed-ips/latest-handshakes to the supervisor.
Assertions cover stalled download with live messages, recovery while the size
filter remains active, healthy peer progress, supervisor SIGKILL, restart,
automatic increase and preservation of original accepted TCP connections.

Installer updates upload both scripts into a content-addressed release
folder, validate Python syntax, then atomically switch the current symlink.
Only after successful activation is the new startup script uploaded. Running
supervisors resolve their own release path before spawning workers.
