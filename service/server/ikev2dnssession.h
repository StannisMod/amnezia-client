#ifndef IKEV2DNSSESSION_H
#define IKEV2DNSSESSION_H

#include <QString>
#include <functional>
#include <utility>

// The native RAS handle and DNS transaction belong to the service. In
// particular, a GUI timeout is not proof that either operation was cancelled.
class Ikev2DnsSession
{
public:
    enum class NativeState { Pending, Connected, Gone, Uncertain };
    enum class State { Idle, Starting, Connected, Stopping, Stopped };
    struct Operations {
        std::function<bool(const QString &)> begin;
        std::function<NativeState()> inspect;
        std::function<bool(const QString &)> publish;
        std::function<bool(const QString &)> healthy;
        std::function<bool(const QString &)> restore;
        std::function<bool()> hangupAndJoin;
        std::function<bool()> releaseFence;
        std::function<bool()> releaseProtection;
    };

    explicit Ikev2DnsSession(Operations operations) : m_operations(std::move(operations)) {}

    bool begin(const QString &owner)
    {
        if (owner.isEmpty() || (m_state != State::Idle && m_state != State::Stopped)
                || m_inStep) return false;
        m_owner = owner;
        m_state = State::Starting;
        m_stopRequested = m_restored = m_joined = m_fenceReleased = false;
        m_inStep = true;
        const bool started = m_operations.begin(owner);
        m_inStep = false;
        if (!started) m_stopRequested = true;
        if (m_stopRequested) step();
        return started && !m_stopRequested;
    }

    void step()
    {
        if (m_inStep || m_state == State::Idle || m_state == State::Stopped) return;
        m_inStep = true;
        if (!m_stopRequested) {
            const auto native = m_operations.inspect();
            if (native == NativeState::Gone || native == NativeState::Uncertain)
                m_stopRequested = true;
            else if (native == NativeState::Connected && m_state == State::Starting) {
                if (!m_operations.publish(m_owner)) m_stopRequested = true;
                // Publication may process a reentrant stop. Never lift the
                // pre-dial DNS fence or announce Connected in that case.
                if (!m_stopRequested) {
                    if (m_operations.releaseFence()) {
                        m_fenceReleased = true;
                        m_state = State::Connected;
                    } else m_stopRequested = true;
                }
            } else if (m_state == State::Connected
                       && (native != NativeState::Connected || !m_operations.healthy(m_owner))) {
                m_stopRequested = true;
            }
        }
        if (m_stopRequested) {
            m_state = State::Stopping;
            if (!m_restored) m_restored = m_operations.restore(m_owner);
            if (m_restored && !m_joined) m_joined = m_operations.hangupAndJoin();
            if (m_joined && !m_fenceReleased) m_fenceReleased = m_operations.releaseFence();
            if (m_joined && m_fenceReleased && m_operations.releaseProtection())
                m_state = State::Stopped;
        }
        m_inStep = false;
    }

    bool stop(const QString &owner)
    {
        if (owner != m_owner) return false;
        m_stopRequested = true;
        step();
        return m_state == State::Stopped;
    }
    bool shutdown() { return m_state == State::Idle || stop(m_owner); }
    State state(const QString &owner) const { return owner == m_owner ? m_state : State::Idle; }
    const QString &owner() const { return m_owner; }

private:
    Operations m_operations;
    QString m_owner;
    State m_state = State::Idle;
    bool m_stopRequested = false;
    bool m_inStep = false;
    bool m_restored = false;
    bool m_joined = false;
    bool m_fenceReleased = false;
};

#endif
