#ifndef OPENVPNDNSSELECTION_H
#define OPENVPNDNSSELECTION_H

#include <QHostAddress>
#include <QJsonObject>
#include <QJsonArray>
#include <QList>
#include <QString>
#include <optional>

struct OpenVpnDnsSelection {
    QString interfaceName;
    QList<QHostAddress> servers;
    QJsonObject metadata;
    QJsonObject linkPolicy;
    QJsonArray resolverPolicy;
};

// Reject unrepresentable scope/security/transport instead of silently reducing
// a native DNS policy to an address list. The full metadata remains with owner.
std::optional<OpenVpnDnsSelection> openVpnDnsSelection(const QJsonObject &environment,
                                                     bool scopedLinkSupported = false);

#endif
