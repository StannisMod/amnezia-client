#pragma once

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QVariantMap>
#include <QUrl>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QSet>
#include <algorithm>

#include "routeModes.h"

namespace amnezia::routing {

inline bool validAction(const QString &action)
{
    return action == "direct" || action == "vpn" || action == "block";
}

inline bool normalizePorts(const QString &input, QString &output)
{
    output.clear();
    if (input.trimmed().isEmpty()) return true;
    if (input.size() > 1024) return false;
    QList<QPair<int, int>> ranges;
    static const QRegularExpression digits("^[0-9]+$");
    for (const auto &part : input.split(',')) {
        const auto ends = part.trimmed().split('-');
        if (ends.size() > 2) return false;
        QList<int> numbers;
        for (const auto &end : ends) {
            if (!digits.match(end.trimmed()).hasMatch()) return false;
            bool ok;
            const int port = end.trimmed().toInt(&ok);
            if (!ok || port < 1 || port > 65535) return false;
            numbers.append(port);
        }
        if (numbers.first() > numbers.last()) return false;
        ranges.append({numbers.first(), numbers.last()});
    }
    std::sort(ranges.begin(), ranges.end());
    QList<QPair<int, int>> merged;
    for (const auto &range : ranges) {
        if (!merged.isEmpty() && range.first <= merged.last().second + 1)
            merged.last().second = qMax(merged.last().second, range.second);
        else merged.append(range);
    }
    QStringList parts;
    for (const auto &range : merged)
        parts.append(range.first == range.second ? QString::number(range.first)
                     : QString::number(range.first) + "-" + QString::number(range.second));
    output = parts.join(',');
    return true;
}

inline QJsonObject destinationRule(QString input, const QString &action, bool enabled,
                                   const QString &ports = {}, const QString &network = {})
{
    if (!validAction(action) || (!network.isEmpty() && network != "tcp" && network != "udp")) return {};
    QString canonicalPorts;
    if (!normalizePorts(ports, canonicalPorts)) return {};
    input = input.trimmed();
    QString kind;
    QHostAddress address(input);
    auto subnet = QHostAddress::parseSubnet(input);
    if (!address.scopeId().isEmpty() || !subnet.first.scopeId().isEmpty()) return {};
    if (!address.isNull() || subnet.second >= 0) {
        kind = "cidr";
        if (subnet.second < 0) subnet = {address, address.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128};
        if (subnet.first.protocol() == QAbstractSocket::IPv4Protocol) {
            const quint32 mask = subnet.second == 0 ? 0 : quint32(0xffffffff) << (32 - subnet.second);
            input = QHostAddress(subnet.first.toIPv4Address() & mask).toString();
        } else {
            auto bytes = subnet.first.toIPv6Address();
            for (int i = 0; i < 16; ++i) {
                const int bits = qBound(0, subnet.second - i * 8, 8);
                bytes[i] &= bits == 0 ? 0 : (0xff << (8 - bits));
            }
            input = QHostAddress(bytes).toString();
        }
        input += "/" + QString::number(subnet.second);
    } else {
        kind = input.startsWith("*.") ? "suffix" : "domain";
        if (kind == "suffix") input.remove(0, 2);
        if (input.endsWith('.')) input.chop(1);
        input = QString::fromLatin1(QUrl::toAce(input.toLower()));
        if (!QHostAddress(input).isNull()) return {};
        static const QRegularExpression label("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
        if (input.isEmpty() || input.size() > 253) return {};
        for (const auto &part : input.split('.')) if (!label.match(part).hasMatch()) return {};
    }
    QJsonObject result{{"kind", kind}, {"value", input}, {"action", action}, {"disabled", !enabled}};
    if (!canonicalPorts.isEmpty()) result.insert("ports", canonicalPorts);
    if (!network.isEmpty()) result.insert("network", network);
    return result;
}

inline QString ruleKey(const QJsonObject &rule)
{
    return rule.value("kind").toString() + ":" + rule.value("value").toString()
        + ":" + rule.value("network").toString() + ":" + rule.value("ports").toString();
}

inline bool knownFields(const QJsonObject &object, const QSet<QString> &allowed)
{
    for (auto it = object.begin(); it != object.end(); ++it) if (!allowed.contains(it.key())) return false;
    return true;
}

// Validate the entire portable document before changing settings. Unknown
// fields/versions fail closed so a newer policy cannot lose conditions.
// Keep source order for otherwise equally specific rules; disabled rules too.
inline bool normalizeConfig(const QJsonObject &input, QJsonObject &output, QString &error)
{
    output = {};
    const auto fail = [&](const QString &message) { error = message; return false; };
    if (!knownFields(input, {"version", "default", "rules"})) return fail("Unknown configuration field");
    const double version = input.value("version").toDouble(-1);
    if (version != 1 && version != 2) return fail("Unsupported routing schema version");
    const QString policy = input.value("default").toString();
    if (!validAction(policy) || (version == 1 && policy == "block")) return fail("Invalid default route");
    if (!input.value("rules").isArray()
        && !(version == 1 && (input.value("rules").isNull() || input.value("rules").isUndefined())))
        return fail("Expected a rules array");
    const auto source = input.value("rules").toArray();
    if (source.size() > 4096) return fail("Too many routing rules");
    QJsonArray rules;
    QSet<QString> seen;
    for (int i = 0; i < source.size(); ++i) {
        const auto bad = [&]() { return fail(QString("Invalid or duplicate rule %1").arg(i + 1)); };
        if (!source[i].isObject()) return bad();
        const auto r = source[i].toObject();
        if (!knownFields(r, {"kind", "value", "action", "disabled", "ports", "network"})) return bad();
        for (const auto &key : {"kind", "value", "action"}) if (!r.value(key).isString()) return bad();
        if (r.contains("disabled") && !r.value("disabled").isBool()) return bad();
        for (const auto &key : {"ports", "network"}) if (r.contains(key) && !r.value(key).isString()) return bad();
        const QString kind = r.value("kind").toString();
        if (kind != "domain" && kind != "suffix" && kind != "cidr") return bad();
        QString destination = r.value("value").toString();
        if (kind == "suffix" && !destination.startsWith("*.")) destination.prepend("*.");
        const auto rule = destinationRule(destination, r.value("action").toString(), !r.value("disabled").toBool(),
                                          r.value("ports").toString(), r.value("network").toString());
        if (rule.isEmpty() || (kind == "cidr") != (rule.value("kind").toString() == "cidr")) return bad();
        if (version == 1 && (rule.value("action") == "block" || !rule.value("ports").toString().isEmpty()
                             || !rule.value("network").toString().isEmpty())) return bad();
        if (!rule.value("disabled").toBool()) {
            const auto key = ruleKey(rule);
            if (seen.contains(key)) return bad();
            seen.insert(key);
        }
        rules.append(rule);
    }
    const QJsonObject candidate{{"version", 2}, {"default", policy}, {"rules", rules}};
    if (QJsonDocument(candidate).toJson(QJsonDocument::Indented).size() > 1024 * 1024)
        return fail("Routing configuration exceeds 1 MiB");
    output = candidate;
    error.clear();
    return true;
}

// Static policy inspection only: no DNS lookup or network operation. An
// optional known IP can be checked alongside a hostname, as in the engine.
inline QVariantMap inspectRule(const QJsonObject &input, const QString &destination,
                               const QString &ipText, const QString &portText, const QString &network)
{
    QJsonObject config;
    QString error;
    const auto fail = [](const QString &message) { return QVariantMap{{"error", message}}; };
    if (!normalizeConfig(input, config, error)) return fail(error);
    if (network != "tcp" && network != "udp") return fail("Select TCP or UDP");
    bool ok;
    const int port = portText.toInt(&ok);
    if (!ok || port < 1 || port > 65535) return fail("Port must be between 1 and 65535");
    QString domain;
    QHostAddress ip;
    if (!ipText.trimmed().isEmpty() && (!ip.setAddress(ipText.trimmed()) || !ip.scopeId().isEmpty())) return fail("Invalid destination IP");
    if (!destination.trimmed().isEmpty()) {
        const auto rule = destinationRule(destination, "direct", true);
        if (rule.isEmpty() || rule.value("kind") == "suffix") return fail("Enter an exact hostname or IP");
        if (rule.value("kind") == "cidr") {
            QHostAddress literal(destination.trimmed());
            if (literal.isNull() || (!ip.isNull() && ip != literal)) return fail("Enter one destination IP, without CIDR");
            ip = literal;
        } else domain = rule.value("value").toString();
    }
    if (domain.isEmpty() && ip.isNull()) return fail("Enter a hostname or IP");
    if (port == 53) return {{"action", "dns"}, {"rule", 0}, {"reason", "managed_dns"}};
    const auto rules = config.value("rules").toArray();
    QList<int> order;
    for (int i = 0; i < rules.size(); ++i) order.append(i);
    const auto rank = [](const QString &kind) { return kind == "domain" ? 0 : kind == "suffix" ? 1 : 2; };
    std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
        const auto x = rules[a].toObject(), y = rules[b].toObject();
        const auto k = x.value("kind").toString(), l = y.value("kind").toString();
        if (k != l) return rank(k) < rank(l);
        if (k == "suffix") return x.value("value").toString().count('.') > y.value("value").toString().count('.');
        if (k == "cidr") return QHostAddress::parseSubnet(x.value("value").toString()).second > QHostAddress::parseSubnet(y.value("value").toString()).second;
        return false;
    });
    for (int index : order) {
        const auto r = rules[index].toObject();
        if (r.value("disabled").toBool()) continue;
        const QString net = r.value("network").toString();
        if (!net.isEmpty() && net != network) continue;
        const QString ports = r.value("ports").toString();
        if (!ports.isEmpty()) {
            bool found = false;
            for (const auto &part : ports.split(',')) {
                const auto ends = part.split('-');
                if (port >= ends.first().toInt() && port <= ends.last().toInt()) found = true;
            }
            if (!found) continue;
        }
        const QString kind = r.value("kind").toString(), value = r.value("value").toString();
        const bool match = (kind == "domain" && !domain.isEmpty() && domain == value)
            || (kind == "suffix" && !domain.isEmpty() && (domain == value || domain.endsWith("." + value)))
            || (kind == "cidr" && !ip.isNull() && ip.isInSubnet(QHostAddress::parseSubnet(value)));
        if (match) return {{"action", r.value("action").toString()}, {"rule", index + 1}, {"reason", "rule"}};
    }
    return {{"action", config.value("default").toString()}, {"rule", 0}, {"reason", "default"}};
}

// Preserve hostname identity. Cached legacy DNS answers must never be emitted
// as IP rules for a hostname; canonical validation/precedence lives in Go.
inline QJsonObject fromLegacySites(bool enabled, RouteMode mode, const QVariantMap &sites)
{
    const bool inverse = enabled && mode == RouteMode::VpnOnlyForwardSites;
    QJsonArray rules;
    if (enabled && mode != RouteMode::VpnAllSites) {
        for (auto it = sites.cbegin(); it != sites.cend(); ++it) {
            const QString value = it.key().trimmed();
            const QHostAddress literal(value);
            const auto subnet = QHostAddress::parseSubnet(value);
            const QString kind = !literal.isNull() || subnet.second >= 0 ? QStringLiteral("cidr")
                    : value.startsWith("*.") ? QStringLiteral("suffix") : QStringLiteral("domain");
            rules.append(QJsonObject{{"kind", kind}, {"value", value},
                                     {"action", inverse ? "vpn" : "direct"}});
        }
    }
    return {{"version", 1}, {"default", inverse ? "direct" : "vpn"}, {"rules", rules}};
}
}
