#ifndef VPNENDPOINTSESSION_H
#define VPNENDPOINTSESSION_H

#include <QHostInfo>
#include <QPointer>
#include <QTimer>
#include <functional>
#include "vpnEndpoint.h"

namespace amnezia
{
// A domain endpoint recovery cycle. The owner must acknowledge real backend
// teardown through deactivated(), never a local/synthetic disconnected signal.
class VpnEndpointSession : public QObject
{
public:
    enum class Phase { Idle, Resolving, Connecting, Connected, Stopping, Waiting, Failed };
    enum class Failure { Resolution, AttemptsExhausted, Cleanup };
    struct Timing {
        int resolveMs = 15000;
        int handshakeMs = 45000;
        int cleanupMs = 30000;
        int retryMs = 2000;
        int maxAttempts = 6;
        qint64 staleMs = 240000;
    };
    using Completion = std::function<void(QList<QHostAddress>)>;
    using Resolver = std::function<void(const QString &, Completion)>;

    explicit VpnEndpointSession(QObject *parent = nullptr) : QObject(parent)
    {
        m_timer.setSingleShot(true);
        connect(&m_timer, &QTimer::timeout, this, [this] {
            switch (m_phase) {
            case Phase::Resolving: cancelLookup(); retryWithoutTunnel(); break;
            case Phase::Connecting: recover(); break;
            case Phase::Stopping: fail(Failure::Cleanup); break;
            case Phase::Waiting: attempt(); break;
            default: break;
            }
        });
    }
    ~VpnEndpointSession() override { cancelLookup(); }

    std::function<void(Phase)> changed;
    std::function<void(const QString &)> activate;
    std::function<void()> deactivate;
    std::function<void(Failure)> failed;
    std::function<void()> cancelResolver;
    Resolver resolver; // Optional deterministic resolver for integration tests.
    Timing timing;

    Phase phase() const { return m_phase; }
    bool wanted() const { return m_wanted; }
    QString address() const { return m_address; }

    void start(const QString &host, bool allowIpv6)
    {
        m_host = host;
        m_allowIpv6 = allowIpv6;
        m_wanted = true;
        m_attempts = 0;
        m_nextAddress = 0;
        m_addresses.clear();
        if (m_phase == Phase::Stopping) return; // Wait for the outstanding ack.
        if (m_backendMayExist) { beginTeardown(); return; }
        cancelLookup();
        m_timer.stop();
        attempt();
    }
    void stop()
    {
        m_wanted = false;
        cancelLookup();
        m_timer.stop();
        if (m_phase == Phase::Stopping) {
            // Preserve the cleanup timeout even when the user cancels recovery.
            m_timer.start(timing.cleanupMs);
            return;
        }
        if (m_backendMayExist) { beginTeardown(); return; }
        setPhase(Phase::Idle);
    }
    void connected()
    {
        if (!m_wanted || m_phase != Phase::Connecting) return;
        m_timer.stop();
        m_seenPeer = false;
        setPhase(Phase::Connected);
    }
    // Only after a service status proves another runtime owns the backend.
    // Transport loss is never sufficient: abandoning then must not issue a
    // teardown against the replacement or leave a cleanup timer running.
    void abandonReplacedBackend()
    {
        cancelLookup();
        m_timer.stop();
        m_wanted = false;
        m_backendMayExist = false;
        setPhase(Phase::Idle);
    }
    // Lack of traffic while idle is not a failure. Require outbound traffic,
    // no inbound progress AND no new handshake for the entire stale interval.
    // nowMs comes from a monotonic clock; wall-clock adjustments cannot trip it.
    void observePeer(qint64 handshakeMs, quint64 tx, quint64 rx, qint64 nowMs)
    {
        if (m_phase != Phase::Connected) return;
        const bool sending = m_seenPeer && tx > m_tx;
        if (!m_seenPeer || handshakeMs != m_handshake || rx != m_rx || tx < m_tx) {
            m_lastProgress = nowMs;
            m_outboundPending = false;
            m_seenPeer = true;
        } else if (sending && !m_outboundPending) {
            // The first packet after a long idle period starts a fresh grace
            // interval, rather than inheriting the idle session's old deadline.
            m_lastProgress = nowMs;
            m_outboundPending = true;
        }
        m_handshake = handshakeMs;
        m_tx = tx;
        m_rx = rx;
        if (sending && m_outboundPending && nowMs - m_lastProgress >= timing.staleMs) recover();
    }

    void recover()
    {
        if (!m_wanted || (m_phase != Phase::Connected && m_phase != Phase::Connecting)) return;
        if (m_phase == Phase::Connected) {
            m_attempts = 0;
            m_addresses.clear(); // A new outage must query DNS again.
            m_nextAddress = 0;
        }
        beginTeardown();
    }
    void deactivated()
    {
        if (m_phase != Phase::Stopping) return;
        m_timer.stop();
        m_backendMayExist = false;
        if (!m_wanted) { setPhase(Phase::Idle); return; }
        if (m_attempts == 0) attempt(); // Initial connect or explicit restart.
        else retryWithoutTunnel();
    }

private:
    void setPhase(Phase phase)
    {
        m_phase = phase;
        if (changed) changed(phase);
    }
    void cancelLookup()
    {
        ++m_generation;
        if (cancelResolver) cancelResolver();
        if (m_lookupId >= 0) QHostInfo::abortHostLookup(m_lookupId);
        m_lookupId = -1;
    }
    void fail(Failure reason)
    {
        cancelLookup();
        m_timer.stop();
        m_wanted = false;
        setPhase(Phase::Failed);
        if (failed) failed(reason);
    }
    void beginTeardown()
    {
        cancelLookup();
        m_timer.start(timing.cleanupMs);
        setPhase(Phase::Stopping);
        if (deactivate) deactivate();
    }
    void retryWithoutTunnel()
    {
        if (!m_wanted) { setPhase(Phase::Idle); return; }
        if (m_attempts >= timing.maxAttempts) {
            fail(m_addresses.isEmpty() ? Failure::Resolution : Failure::AttemptsExhausted);
            return;
        }
        setPhase(Phase::Waiting);
        // Bounded exponential backoff; no busy retry loop while offline.
        m_timer.start(qMin(30000, timing.retryMs * (1 << qMin(m_attempts, 4))));
    }
    void attempt()
    {
        if (!m_wanted) return;
        ++m_attempts;
        if (m_nextAddress < m_addresses.size()) { activateNext(); return; }
        m_addresses.clear();
        m_nextAddress = 0;
        cancelLookup();
        const auto generation = m_generation;
        setPhase(Phase::Resolving);
        m_timer.start(timing.resolveMs);
        QPointer<VpnEndpointSession> self(this);
        const auto completion = [self, generation](const QList<QHostAddress> &addresses) {
            if (!self || generation != self->m_generation || self->m_phase != Phase::Resolving || !self->m_wanted) return;
            self->m_lookupId = -1;
            self->m_timer.stop();
            // Keep all usable answers, IPv4 first for the legacy backend.
            for (bool ipv6 : {false, true}) {
                if (ipv6 && !self->m_allowIpv6) continue;
                for (const auto &address : addresses) {
                    if (address.protocol() != (ipv6 ? QAbstractSocket::IPv6Protocol : QAbstractSocket::IPv4Protocol)
                        || !address.scopeId().isEmpty()) continue;
                    const auto text = address.toString();
                    if (!self->m_addresses.contains(text) && self->m_addresses.size() < 16) self->m_addresses.append(text);
                }
            }
            if (self->m_addresses.isEmpty()) self->retryWithoutTunnel();
            else self->activateNext();
        };
        if (resolver) resolver(m_host, completion);
        else m_lookupId = QHostInfo::lookupHost(m_host, this, [completion](const QHostInfo &info) { completion(info.addresses()); });
    }
    void activateNext()
    {
        m_address = m_addresses.at(m_nextAddress++);
        m_backendMayExist = true;
        m_timer.start(timing.handshakeMs);
        setPhase(Phase::Connecting);
        if (activate) activate(m_address);
    }

    QTimer m_timer;
    Phase m_phase = Phase::Idle;
    QString m_host, m_address;
    QStringList m_addresses;
    int m_nextAddress = 0, m_attempts = 0, m_lookupId = -1;
    quint64 m_generation = 0;
    bool m_wanted = false, m_allowIpv6 = false, m_backendMayExist = true; // Service state is unknown until first teardown ack.
    bool m_seenPeer = false, m_outboundPending = false;
    qint64 m_lastProgress = 0, m_handshake = 0;
    quint64 m_tx = 0, m_rx = 0;
};
}
#endif
