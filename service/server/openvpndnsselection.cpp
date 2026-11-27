#include "openvpndnsselection.h"
#include <QMap>
#include <QRegularExpression>
#include <QSet>
#include <QJsonArray>

namespace {
bool append(QList<QHostAddress> &servers, const QString &text)
{
    const QHostAddress address(text);
    if (servers.size() >= 16 || address.isNull() || address.isMulticast()
        || address == QHostAddress::AnyIPv4 || address == QHostAddress::AnyIPv6
        || !address.scopeId().isEmpty()) return false;
    servers.append(address); // Preserve every occurrence, including duplicates/IPv6-only DNS.
    return true;
}
bool contiguous(const QMap<int, QString> &values)
{
    int expected = 1;
    for (auto it = values.begin(); it != values.end(); ++it)
        if (it.key() != expected++) return false;
    return true;
}
bool appendDomain(QJsonArray &domains, const QString &name, bool routing)
{
    static const QRegularExpression valid(
        "^(?:\\.|[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?\\.?)$");
    if (name.size() > 253 || !valid.match(name).hasMatch()) return false;
    domains.append(QJsonObject{{"name", name}, {"routing_only", routing}});
    return true;
}
}

std::optional<OpenVpnDnsSelection> openVpnDnsSelection(const QJsonObject &environment,
                                                     bool scopedLinkSupported)
{
    OpenVpnDnsSelection result;
    result.interfaceName = environment["dev"].toString();
    result.metadata = environment;
    if (result.interfaceName.isEmpty() || result.interfaceName.contains(QChar(0))) return {};
    QMap<int, QMap<int, QString>> modern;
    QMap<int, QMap<int, QString>> ports;
    QMap<int, QMap<int, QString>> scopes;
    QMap<int, QString> search;
    QMap<int, QString> foreign, v4, v6;
    QMap<int, QString> transports, names;
    static const QRegularExpression address("^dns_server_([1-9][0-9]*)_address_([1-9][0-9]*)$");
    static const QRegularExpression port("^dns_server_([1-9][0-9]*)_port_([1-9][0-9]*)$");
    static const QRegularExpression transport("^dns_server_([1-9][0-9]*)_transport$");
    static const QRegularExpression name("^dns_server_([1-9][0-9]*)_sni$");
    static const QRegularExpression scope("^dns_server_([1-9][0-9]*)_resolve_domain_([1-9][0-9]*)$");
    static const QRegularExpression searchKey("^dns_search_domain_([1-9][0-9]*)$");
    static const QRegularExpression legacy("^(foreign_option_|amnezia_legacy_dns([46])_)([1-9][0-9]*)$");
    for (auto it = environment.begin(); it != environment.end(); ++it) {
        if (!it.value().isString()) return {};
        const auto key = it.key(), value = it.value().toString();
        auto match = address.match(key);
        if (match.hasMatch()) {
            bool a, b;
            const int server = match.captured(1).toInt(&a), index = match.captured(2).toInt(&b);
            if (!a || !b) return {};
            modern[server].insert(index, value); continue;
        }
        match = port.match(key);
        if (match.hasMatch()) {
            bool a, b;
            const int server = match.captured(1).toInt(&a), index = match.captured(2).toInt(&b);
            bool validPort;
            const auto number = value.toInt(&validPort);
            if (!a || !b || !validPort || number < 1 || number > 65535 || QString::number(number) != value)
                return {};
            ports[server].insert(index, value); continue;
        }
        match = transport.match(key);
        if (match.hasMatch()) {
            bool ok;
            const int server = match.captured(1).toInt(&ok);
            if (!ok || (value != "plain" && value != "DoT")) return {};
            transports.insert(server, value == "DoT" ? "tls" : "plain");
            continue;
        }
        match = name.match(key);
        if (match.hasMatch()) {
            bool ok;
            const auto server = match.captured(1).toInt(&ok);
            if (!ok || value.size() > 253 || value.contains(QChar(0))) return {};
            names.insert(server, value);
            continue;
        }
        match = scope.match(key);
        if (match.hasMatch()) {
            bool a, b;
            const int group = match.captured(1).toInt(&a), index = match.captured(2).toInt(&b);
            if (!scopedLinkSupported || !a || !b) return {};
            scopes[group].insert(index, value);
            continue;
        }
        match = searchKey.match(key);
        if (match.hasMatch()) {
            bool ok;
            const int index = match.captured(1).toInt(&ok);
            if (!scopedLinkSupported || !ok) return {};
            search.insert(index, value);
            continue;
        }
        // All unhandled scope/security fields remain fail closed. Only the
        // explicitly supported link-policy fields above may reach publication.
        if (key.startsWith("dns_server_") || key.startsWith("dns_search_domain_")
            || key.startsWith("amnezia_legacy_search_") || key == "amnezia_legacy_domain")
            return {};
        match = legacy.match(key);
        if (match.hasMatch()) {
            bool ok;
            const int index = match.captured(3).toInt(&ok);
            if (!ok) return {};
            if (match.captured(1) == "foreign_option_") foreign.insert(index, value);
            else if (match.captured(2) == "4") v4.insert(index, value);
            else v6.insert(index, value);
        } else if (key.startsWith("foreign_option_") || key.startsWith("amnezia_legacy_dns")) return {};
    }
    for (const auto &option : foreign) {
        const auto fields = option.simplified().split(' ');
        if (fields.size() < 2 || fields[0] != "dhcp-option") return {};
        if ((!scopedLinkSupported && fields[1].contains("DOMAIN"))
            || (fields[1].contains("DNS") && fields[1] != "DNS" && fields[1] != "DNS6")) return {};
    }
    if (!modern.isEmpty()) {
        // Distinct modern priority/scope groups require per-group routing,
        // not flattening into one link's resolver pool.
        if (modern.size() != 1) return {};
        int expected = 1;
        for (auto it = modern.begin(); it != modern.end(); ++it) {
            if (it.key() != expected++ || !contiguous(it.value())) return {};
            const auto selectedTransport = transports.value(it.key(), "plain");
            const auto selectedName = names.value(it.key());
            if (selectedTransport == "plain" && !selectedName.isEmpty()) return {};
            for (auto server = it.value().begin(); server != it.value().end(); ++server) {
                if (!append(result.servers, server.value())) return {};
                const int selectedPort = ports.value(it.key()).value(server.key(),
                    selectedTransport == "tls" ? "853" : "53").toInt();
                QJsonObject policy{{"server", result.servers.last().toString()},
                    {"port", selectedPort}, {"transport", selectedTransport}};
                if (selectedTransport == "tls" && !selectedName.isEmpty())
                    policy.insert("server_name", selectedName);
                result.resolverPolicy.append(policy);
            }
        }
        for (auto it = ports.begin(); it != ports.end(); ++it)
            for (auto value = it.value().begin(); value != it.value().end(); ++value)
                if (!modern.value(it.key()).contains(value.key())) return {};
        for (auto it = transports.begin(); it != transports.end(); ++it)
            if (!modern.contains(it.key())) return {};
        for (auto it = names.begin(); it != names.end(); ++it)
            if (!modern.contains(it.key())) return {};
        if (!contiguous(search)) return {};
        QJsonArray domains;
        for (const auto &name : search)
            if (!appendDomain(domains, name, false)) return {};
        for (auto it = scopes.begin(); it != scopes.end(); ++it) {
            if (!modern.contains(it.key()) || !contiguous(it.value())) return {};
            for (const auto &name : it.value())
                if (!appendDomain(domains, name, true)) return {};
        }
        if (!domains.isEmpty()) {
            const bool global = scopes.isEmpty()
                || scopes.first().values().contains(".");
            if (scopes.isEmpty()) appendDomain(domains, ".", true);
            result.linkPolicy = {{"domains", domains}, {"default_route", global}};
        }
        // Native modern options supersede the derived legacy compatibility list.
    } else {
        if (!ports.isEmpty() || !transports.isEmpty() || !names.isEmpty() || !scopes.isEmpty() || !search.isEmpty()
            || !contiguous(foreign) || !contiguous(v4) || !contiguous(v6)) return {};
        QJsonArray domains;
        for (const auto &option : foreign) {
            const auto fields = option.simplified().split(' ');
            if (fields.size() < 2 || fields[0] != "dhcp-option") return {};
            if (fields[1] == "DNS" || fields[1] == "DNS6") {
                if (fields.size() != 3 || !append(result.servers, fields[2])) return {};
            } else if (fields[1] == "DOMAIN" || fields[1] == "DOMAIN-SEARCH" || fields[1] == "DOMAIN-ROUTE") {
                if (!scopedLinkSupported || fields.size() != 3) return {};
                const auto name = fields[2];
                // DOMAIN-ROUTE has no pinned native contract; do not invent one.
                if (fields[1] == "DOMAIN-ROUTE") return {};
                if (!appendDomain(domains, name, false)) return {};
            } else if (fields[1].contains("DOMAIN")) return {};
        }
        if (!domains.isEmpty()) {
            // Search domains alone retain the native global DNS selection.
            domains.append(QJsonObject{{"name", "."}, {"routing_only", true}});
            result.linkPolicy = {{"domains", domains}, {"default_route", true}};
        }
        if (!foreign.isEmpty() && (!v4.isEmpty() || !v6.isEmpty())) return {};
        for (const auto &ip : v4) {
            if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol || !append(result.servers, ip)) return {};
        }
        for (const auto &ip : v6) {
            if (QHostAddress(ip).protocol() != QAbstractSocket::IPv6Protocol || !append(result.servers, ip)) return {};
        }
    }
    if (result.servers.isEmpty()) return {};
    return result;
}
