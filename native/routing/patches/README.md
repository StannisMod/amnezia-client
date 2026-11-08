# TCP recovery candidate

`gvisor-rack-flight.patch` is the selected **experimental backport** for
`gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489`. It remains the review artifact for the original comparison and is applied to
private copies by the stability lab. Normal builds now use immutable fork commits
from `internal/builddeps/lock.json`; they do not apply this file at build time.

It adapts the production-source changes proposed in
[google/gvisor #15432](https://github.com/google/gvisor/pull/15432),
“Don't count RACK-lost TCP segments as in flight.” Upstream gVisor source is
Copyright The gVisor Authors, Apache License 2.0; its existing source headers and
LICENSE remain in the copied module. This backport retains the original license.
The upstream proposal is not merged/reviewed as a completed upstream fix.

The changes recompute flight accounting after RACK loss marking, exclude marked
lost copies, retain loss/ACK flags across splits, and advance `writeNext` after a
fast repair to avoid sending it again through the ordinary send path. They do not
change RTO limits, congestion-control selection, cwnd growth, or retry budgets.

The comparison script checks the generated backport against this reviewable
patch. See [the TCP recovery report](../../../docs/sing-box-routing/TCP-RECOVERY.md)
for acceptance, rejected candidates, and remaining limitations.
