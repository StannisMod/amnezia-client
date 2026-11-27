#pragma once

#include <QHostAddress>
#include <QStringList>
#include <QVector>
#include <algorithm>
#include <utility>

namespace amnezia::routing {

// Produce disjoint capture routes while retaining the OS routes for exceptions.
// Split /0 because desktop systems already own their native default route.
inline bool proxyIpv6Routes(const QStringList &included, const QStringList &excluded, QStringList &result)
{
    struct Prefix { Q_IPV6ADDR bytes; int length; };
    constexpr int limit = 4096;
    const auto contains = [](const Prefix &parent, const Prefix &child) {
        if (parent.length > child.length) return false;
        for (int bit = 0; bit < parent.length; ++bit)
            if ((parent.bytes[bit / 8] ^ child.bytes[bit / 8]) & (0x80 >> (bit % 8))) return false;
        return true;
    };
    const auto parse = [](const QStringList &input, QVector<Prefix> &output) {
        if (input.size() > limit) return false;
        for (const auto &value : input) {
            const auto subnet = QHostAddress::parseSubnet(value);
            if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol || subnet.second < 0
                || !subnet.first.scopeId().isEmpty()) return false;
            auto bytes = subnet.first.toIPv6Address();
            for (int bit = subnet.second; bit < 128; ++bit) bytes[bit / 8] &= ~(0x80 >> (bit % 8));
            output.append({bytes, subnet.second});
        }
        return true;
    };
    QVector<Prefix> routes, exceptions;
    if (!parse(included, routes) || !parse(excluded, exceptions)) return false;
    std::sort(routes.begin(), routes.end(), [](const Prefix &a, const Prefix &b) { return a.length < b.length; });
    QVector<Prefix> unique;
    for (const auto &route : routes) {
        if (std::none_of(unique.cbegin(), unique.cend(), [&](const Prefix &parent) { return contains(parent, route); }))
            unique.append(route);
    }
    routes = std::move(unique);
    for (const auto &exception : exceptions) {
        QVector<Prefix> remaining;
        for (auto route : routes) {
            if (contains(exception, route)) continue;
            if (!contains(route, exception)) remaining.append(route);
            else {
                while (route.length < exception.length) {
                    const int bit = route.length++;
                    const auto mask = 0x80 >> (bit % 8);
                    auto sibling = route;
                    if (exception.bytes[bit / 8] & mask) route.bytes[bit / 8] |= mask;
                    else sibling.bytes[bit / 8] |= mask;
                    remaining.append(sibling);
                    if (remaining.size() > limit) return false;
                }
            }
            if (remaining.size() > limit) return false;
        }
        routes = std::move(remaining);
    }
    QStringList output;
    for (const auto &route : routes) {
        if (route.length == 0) output << "::/1" << "8000::/1";
        else output.append(QHostAddress(route.bytes).toString() + '/' + QString::number(route.length));
        if (output.size() > limit) return false;
    }
    result = std::move(output);
    return true;
}
}
