#ifndef WINDOWSIKEV2DNS_H
#define WINDOWSIKEV2DNS_H

#include <winsock2.h>
#include <windows.h>
#include <ras.h>
#include <QObject>
#include <QTimer>
#include <QSet>
#include <atomic>
#include "ikev2dnssession.h"
#include "daemon/dnsutils.h"

// Uses the existing RAS backend, machine certificate store, profile and native
// routing. Only OFF dial/DNS/stop ownership moves to the existing service.
class WindowsIkev2Dns : public QObject
{
public:
    explicit WindowsIkev2Dns(DnsUtils *dns, QObject *parent = nullptr);
    bool start(const QString &owner, const QByteArray &phonebook, const QStringList &endpoints);
    QString state(const QString &owner) const;
    bool stop(const QString &owner);
    bool shutdown();
    bool prepareRecovery();
    bool finishRecovery();
    bool recoveryReady() const { return !m_recoveryBlocked; }
    bool ownsNativeLifecycle() const {
        const auto value = m_session.state(m_session.owner());
        return m_recoveryBlocked || (value != Ikev2DnsSession::State::Idle
                                     && value != Ikev2DnsSession::State::Stopped);
    }
    bool acknowledgeStopped(const QString &owner);

private:
    static DWORD CALLBACK dialNotification(ULONG_PTR context, DWORD, HRASCONN, UINT,
                                           RASCONNSTATE state, DWORD error, DWORD);
    bool begin(const QString &owner);
    Ikev2DnsSession::NativeState inspect();
    bool publish(const QString &owner);
    bool prepareExistingScopes(const QString &owner);
    bool dnsHealthy(const QString &owner) const;
    bool restoreDns(const QString &owner);
    bool hangupAndJoin();
    bool releaseFence();
    bool releaseProtection();
    bool storeRecord(const QString &phase);
    bool removeRecord();
    DnsUtils *m_dns;
    std::vector<std::unique_ptr<DnsUtils>> m_existingScopes;
    Ikev2DnsSession m_session;
    QTimer m_timer;
    HRASCONN m_connection = nullptr;
    HANDLE m_fence = nullptr;
    QString m_phonebook;
    QStringList m_endpoints;
    bool m_hangupRequested = false;
    std::atomic<bool> m_dialSettled{false};
    std::atomic<bool> m_dialFailed{false};
    bool m_nativeHandleObserved = false;
    bool m_dialAttempted = false;
    bool m_policyAttempted = false;
    DWORD m_lastNativeError = ERROR_SUCCESS;
    QString m_ownedDirectory;
    QJsonObject m_record;
    bool m_recoveryBlocked = false;
    bool m_recoveryDnsRestored = false;
    QSet<QString> m_completedOwners;
    QSet<QString> m_recoveryCompletedOwners;
};

#endif
