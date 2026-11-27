#ifndef NATIVEDNSGUARD_H
#define NATIVEDNSGUARD_H

#include <QHostAddress>
#include <QList>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>

// The service implementation owns assigned local addresses and a DNS session
// in its existing Go runtime. Platform DNS utilities alone publish OS settings.
class NativeDnsGuard {
public:
    virtual ~NativeDnsGuard() = default;
    virtual bool prepare(const QString &ifname, const QList<QHostAddress> &original,
                         QList<QHostAddress> &endpoints) = 0;
    virtual bool matches(const QString &ifname, const QList<QHostAddress> &original) const {
        Q_UNUSED(ifname); Q_UNUSED(original);
        return false;
    }
    // Only after confirmed DNS replacement/restoration. A failed retirement
    // retains its ownership record for retry/recovery, never deletes other state.
    virtual bool retire() = 0;
    virtual bool healthy() const { return true; }
    virtual bool quiesce() const { return true; }
    virtual QList<QHostAddress> originalResolvers() const { return {}; }
    // Must be durably committed before the first OS-settings mutation.
    virtual bool storeDnsRecovery(const QJsonObject &) { return false; }
    virtual bool setProtocolMetadata(const QJsonObject &metadata) { return metadata.isEmpty(); }
    // One exact ordered resolver occurrence per entry. Must be supplied before
    // prepare; an implementation that cannot preserve transport must refuse.
    virtual bool setResolverPolicy(const QJsonArray &policy) { return policy.isEmpty(); }
    virtual bool matchesResolverPolicy(const QJsonArray &policy) const { return policy.isEmpty(); }
};

#endif
