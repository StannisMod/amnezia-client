#include "linuxdnsrecovery.h"
#include "dbustypeslinux.h"
#include <QNetworkInterface>

namespace LinuxDnsRecovery {
namespace {
const QString service = "org.freedesktop.resolve1";
const QString managerPath = "/org/freedesktop/resolve1";
const QString manager = "org.freedesktop.resolve1.Manager";

QDBusMessage call(const QString &path, const QString &interface, const QString &method,
                  const QList<QVariant> &arguments)
{
    auto message = QDBusMessage::createMethodCall(service, path, interface, method);
    message.setArguments(arguments);
    return QDBusConnection::systemBus().call(message, QDBus::Block, 4000);
}
QJsonArray domainsJson(const DnsLinkDomainList &domains)
{
    QJsonArray result;
    for (const auto &domain : domains)
        result.append(QJsonObject{{"name", domain.domain}, {"routing_only", domain.search}});
    return result;
}
QJsonObject readLink(int index)
{
    const auto iface = QNetworkInterface::interfaceFromIndex(index);
    if (!iface.isValid()) return {{"removed", true}};
    QDBusReply<QDBusObjectPath> path = call(managerPath, manager, "GetLink", {index});
    if (!path.isValid()) return {};
    QDBusReply<QVariantMap> reply = call(path.value().path(), "org.freedesktop.DBus.Properties",
                                       "GetAll", {QString("org.freedesktop.resolve1.Link")});
    if (!reply.isValid()) return {};
    const auto values = reply.value();
    if (!values.contains("DNS") || !values.contains("Domains") ||
            values.value("DefaultRoute").metaType() != QMetaType::fromType<bool>()) return {};
    if (!values["DNS"].canConvert<QDBusArgument>() && !values["DNS"].canConvert<DnsResolverList>()) return {};
    if (!values["Domains"].canConvert<QDBusArgument>() &&
            !values["Domains"].canConvert<DnsLinkDomainList>()) return {};
    QJsonArray dns;
    for (const auto &ip : qdbus_cast<DnsResolverList>(values["DNS"])) {
        if (ip.isNull()) return {};
        dns.append(ip.toString());
    }
    QJsonArray extended;
    if (values.contains("DNSEx")) {
        if (!values["DNSEx"].canConvert<QDBusArgument>()
                && !values["DNSEx"].canConvert<DnsResolverExList>()) return {};
        for (const auto &server : qdbus_cast<DnsResolverExList>(values["DNSEx"])) {
            if (server.address.isNull()) return {};
            extended.append(QJsonObject{{"server", server.address.toString()},
                {"port", server.port}, {"server_name", server.serverName}});
        }
        if (extended.size() != dns.size()) return {};
        for (int i = 0; i < dns.size(); ++i)
            if (extended[i].toObject()["server"] != dns[i]) return {};
    }
    QJsonObject result{{"name", iface.name()}, {"hardware", iface.hardwareAddress()}, {"dns", dns},
            {"domains", domainsJson(qdbus_cast<DnsLinkDomainList>(values["Domains"]))},
            {"default_route", values["DefaultRoute"].toBool()}};
    if (values.contains("DNSEx")) result.insert("dns_ex", extended);
    // Link modes can inherit manager policy. Record both, rather than assuming
    // an empty link string means insecure/default DNS.
    QDBusReply<QVariantMap> globalReply = call(managerPath, "org.freedesktop.DBus.Properties",
                                             "GetAll", {manager});
    if (!globalReply.isValid()) return {};
    const auto global = globalReply.value();
    QJsonObject policy;
    for (const auto &field : {QString("DNSSEC"), QString("DNSOverTLS")}) {
        if (values.value(field).metaType() != QMetaType::fromType<QString>()
                || global.value(field).metaType() != QMetaType::fromType<QString>()) return {};
        policy.insert(field, values[field].toString());
        policy.insert("global_" + field, global[field].toString());
    }
    for (const auto &field : {QString("LLMNR"), QString("MulticastDNS")}) {
        if (values.value(field).metaType() != QMetaType::fromType<QString>()) return {};
        policy.insert(field, values[field].toString());
    }
    if (values.value("DNSSECNegativeTrustAnchors").metaType() != QMetaType::fromType<QStringList>())
        return {};
    policy.insert("negative_trust_anchors", QJsonArray::fromStringList(
        values["DNSSECNegativeTrustAnchors"].toStringList()));
    result.insert("native_policy", policy);
    return result;
}
bool writeLink(int index, const QString &field, const QJsonValue &value)
{
    QString method;
    QVariant argument;
    if (field == "dns_ex" && value.isArray()) {
        DnsResolverExList addresses;
        for (const auto &item : value.toArray()) {
            if (!item.isObject()) return false;
            const auto object = item.toObject();
            const QHostAddress ip(object["server"].toString());
            const auto port = object["port"].toDouble(-1);
            if (object.size() != 3 || ip.isNull() || !object["port"].isDouble()
                    || port < 0 || port > 65535 || port != int(port)
                    || !object["server_name"].isString()
                    || object["server_name"].toString().contains(QChar(0))) return false;
            addresses.append({ip, quint16(port), object["server_name"].toString()});
        }
        method = "SetLinkDNSEx";
        argument = QVariant::fromValue(addresses);
    } else if (field == "dns") {
        DnsResolverList addresses;
        for (const auto &item : value.toArray()) {
            QHostAddress ip(item.toString());
            if (ip.isNull()) return false;
            addresses.append(ip);
        }
        method = "SetLinkDNS";
        argument = QVariant::fromValue(addresses);
    } else if (field == "domains") {
        DnsLinkDomainList domains;
        for (const auto &item : value.toArray()) {
            const auto object = item.toObject();
            if (!object["name"].isString() || !object["routing_only"].isBool()) return false;
            domains.append(DnsLinkDomain(object["name"].toString(), object["routing_only"].toBool()));
        }
        method = "SetLinkDomains";
        argument = QVariant::fromValue(domains);
    } else if (field == "default_route" && value.isBool()) {
        method = "SetLinkDefaultRoute";
        argument = value.toBool();
    } else return false;
    return call(managerPath, manager, method, {index, argument}).type() == QDBusMessage::ReplyMessage;
}
}
Backend systemBackend() {
    DnsMetatypeRegistrationProxy registration;
    return {readLink, writeLink};
}

QJsonObject capture(const QString &ifname, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous, const QJsonObject &linkPolicy)
{
    // Empty policy retains the existing global-DNS contract. An explicit
    // scoped policy must be lossless; never infer a global route from it.
    if (!linkPolicy.isEmpty()) {
        if (linkPolicy.size() != 2 || !linkPolicy["domains"].isArray()
                || !linkPolicy["default_route"].isBool()) return {};
        for (const auto &value : linkPolicy["domains"].toArray()) {
            if (!value.isObject()) return {};
            const auto domain = value.toObject();
            const auto name = domain["name"].toString();
            if (domain.size() != 2 || !domain["name"].isString() || name.isEmpty()
                    || name.contains(QChar(0)) || !domain["routing_only"].isBool()) return {};
        }
    }
    const bool global = linkPolicy.isEmpty()
        || linkPolicy["domains"].toArray().contains(
            QJsonObject{{"name", "."}, {"routing_only", true}});
    DnsMetatypeRegistrationProxy registration;
    const auto iface = QNetworkInterface::interfaceFromName(ifname);
    if (!iface.isValid() || endpoints.isEmpty()) return {};
    QJsonArray links;
    if (!previous.isEmpty()) {
        if (previous["backend"] != QJsonValue("systemd-resolved-v1")
                || previous["native_index"].toInt() != iface.index()) return {};
        links = previous["links"].toArray();
        if (links.isEmpty()) return {};
    }
    {
        QDBusReply<QDBusVariant> reply = call(managerPath, "org.freedesktop.DBus.Properties",
                                             "Get", {manager, QString("Domains")});
        if (!reply.isValid()) return {};
        const auto raw = reply.value().variant();
        if (!raw.canConvert<QDBusArgument>() && !raw.canConvert<DnsDomainList>()) return {};
        const auto domains = qdbus_cast<DnsDomainList>(raw);
        QList<int> affected{iface.index()};
        for (const auto &domain : domains)
            if (global && domain.ifindex > 0 && domain.domain == "." && domain.search
                    && !affected.contains(domain.ifindex)) affected.append(domain.ifindex);
        for (const int index : affected) {
            bool alreadyCaptured = false;
            for (const auto &value : links)
                if (value.toObject()["index"].toInt() == index) alreadyCaptured = true;
            if (alreadyCaptured) continue;
            const auto current = readLink(index);
            if (current.isEmpty() || current["removed"].toBool()) return {};
            if (index == iface.index()) {
                const auto policy = current["native_policy"].toObject();
                for (const auto &field : {QString("DNSSEC"), QString("DNSOverTLS")}) {
                    const auto linkMode = policy[field].toString();
                    const auto effective = linkMode.isEmpty()
                        ? policy["global_" + field].toString() : linkMode;
                    // The local UDP/TCP frontend is not a TLS endpoint and
                    // cannot manufacture signed DNSSEC denial proofs.
                    // Never disable those OS policies to make aliases usable.
                    if (effective != "no") return {};
                }
            }
            QJsonObject before{{"domains", current["domains"]}};
            if (index == iface.index()) {
                // DNS omits ports/SNI. Capture DNSEx whenever the provider has it,
                // including default endpoints, to detect metadata-only edits.
                const auto field = current.contains("dns_ex") ? "dns_ex" : "dns";
                before.insert(field, current[field]);
                before.insert("default_route", current["default_route"]);
            }
            links.append(QJsonObject{{"index", index}, {"name", current["name"]},
                                      {"hardware", current["hardware"]}, {"before", before},
                                      {"native_policy", current["native_policy"]}});
        }
    }
    QJsonArray updated;
    bool foundNative = false;
    for (const auto &value : links) {
        auto link = value.toObject();
        auto after = link["before"].toObject();
        const auto current = readLink(link["index"].toInt());
        if (current.isEmpty() || current["removed"].toBool() || current["name"] != link["name"]
                || current["hardware"] != link["hardware"]) return {};
        if (link.contains("native_policy") && current["native_policy"] != link["native_policy"]) return {};
        if (!previous.isEmpty()) {
            const auto oldAfter = link["after"].toObject();
            for (auto it = oldAfter.begin(); it != oldAfter.end(); ++it)
                if (current[it.key()] != it.value()) return {}; // Do not adopt external edits.
        }
        QJsonArray domains;
        if (link["index"].toInt() == iface.index()) {
            foundNative = true;
            QJsonArray dns;
            for (const auto &ip : endpoints) dns.append(ip.toString());
            if (after.contains("dns_ex")) {
                QJsonArray extended;
                for (const auto &ip : endpoints)
                    extended.append(QJsonObject{{"server", ip.toString()}, {"port", 0}, {"server_name", ""}});
                after.insert("dns_ex", extended);
            } else after.insert("dns", dns);
            after.insert("default_route", linkPolicy.isEmpty()
                         ? QJsonValue(true) : linkPolicy["default_route"]);
            if (linkPolicy.isEmpty())
                domains.append(QJsonObject{{"name", "."}, {"routing_only", true}});
            else domains = linkPolicy["domains"].toArray();
        } else {
            for (const auto &domain : after["domains"].toArray())
                if (!(global && domain.toObject()["name"] == QJsonValue(".") &&
                      domain.toObject()["routing_only"] == QJsonValue(true))) domains.append(domain);
        }
        after.insert("domains", domains);
        link.insert("after", after);
        updated.append(link);
    }
    if (!foundNative) return {};
    return {{"backend", "systemd-resolved-v1"}, {"native_index", iface.index()}, {"links", updated}};
}
}
