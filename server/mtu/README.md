# AWG per-peer MTU controller prototype

Run inside the AWG server network namespace with Python 3, iproute2,
CAP_NET_RAW and CAP_NET_ADMIN.

    python3 controller.py --interface awg0 --source 10.8.1.1 \
      --peer 10.8.1.2 --peer 10.8.1.3 --maximum 1280 --interval 30

The source must be assigned to the server. Each selected peer must already
have a direct IPv4 /32 route on the interface with no explicit MTU metric.
The maximum should not exceed the interface MTU. No keys or profiles change.

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
