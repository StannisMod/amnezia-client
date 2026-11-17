#pragma once
#include "macopenvpnipv6table.h"

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#include <QElapsedTimer>
#include <QDebug>
#include <QNetworkInterface>
#include <QScopeGuard>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <cstddef>
#include <limits>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

namespace amnezia::macOpenVpnIpv6 {
// Darwin SDK structures are used only on Darwin. No mirrored routing ABI and
// no route(8) subprocess/status interpretation are involved in this adapter.
class Native {
public:
    Native() {
        const auto entries = snapshot();
        if (!entries) return;
        for (const auto &entry : *entries) {
            if (entry.prefix || !entry.scope.isEmpty() || !entry.usable()) continue;
            if (!m_originalDefault.isEmpty() && m_originalDefault != entry.path.device) {
                m_originalDefault.clear(); return;
            }
            m_originalDefault = entry.path.device;
        }
    }
    Api api() {
        Api result;
        result.select = [this](const QString &tunnel, const QString &host, bool vpn) { return select(tunnel, host, vpn); };
        result.sources = [this](const QString &host) { return sources(host); };
        result.read = [this](const QString &host, const QString &scope) { return read(host, scope); };
        result.create = [this](const Route &route) {
            const auto before = read(route.host, route.scope);
            if (!before) return false;
            if (before->exact && (route.scope.isEmpty() || !before->exact->transient
                || before->exact->managed || before->exact->path != route.path)) return false;
            // XNU RTM_ADD replaces a protocol-generated clone under the route
            // table lock. A static foreign row still fails with EEXIST.
            return mutate(RTM_ADD, route);
        };
        result.changeOwned = [this](const Route &before, const Route &after) {
            if (!before.managed || !after.managed || before.host != after.host || before.scope != after.scope) return false;
            const auto found = read(before.host, before.scope);
            if (!found || !found->exact) return false;
            if (*found->exact == after) return true;
            if (!(*found->exact == before)) return false;
            if (before.scope.isEmpty()) {
                return replaceUnscoped(before, after,
                    [this, &before] { return read(before.host, {}); },
                    [this](const Route &route) { return mutate(RTM_DELETE, route); },
                    [this](const Route &route) { return mutate(RTM_ADD, route); });
            }
            return mutate(RTM_CHANGE, after);
        };
        result.removeOwned = [this](const Route &route) {
            const auto found = read(route.host, route.scope);
            if (!found) return false;
            if (!found->exact || !(*found->exact == route) || !route.managed) return true;
            return mutate(RTM_DELETE, route);
        };
        return result;
    }
private:
    static qsizetype rounded(qsizetype length) { return length ? (length + 3) & ~qsizetype(3) : 4; }
    static std::optional<QHostAddress> address(const QByteArray &bytes, const QString &device,
                                              bool localDestination = false) {
        if (bytes.size() < qsizetype(sizeof(sockaddr_in6))) return {};
        sockaddr_in6 value{};
        std::memcpy(&value, bytes.constData(), sizeof(value));
        if (value.sin6_family != AF_INET6) return {};
        Q_IPV6ADDR ip{};
        std::memcpy(ip.c, &value.sin6_addr, 16);
        QHostAddress result(ip);
        if (result.isLinkLocal()) {
            // Route messages can contain KAME's embedded link-local zone.
            const auto embedded = (unsigned(ip[2]) << 8) | ip[3];
            const auto index = QNetworkInterface::interfaceIndexFromName(device);
            const auto zone = linkLocalZone(embedded, value.sin6_scope_id, unsigned(index),
                localDestination, [](unsigned candidate) {
                    return !QNetworkInterface::interfaceNameFromIndex(candidate).isEmpty();
                });
            if (!zone) return {};
            ip[2] = ip[3] = 0;
            result = QHostAddress(ip);
            result.setScopeId(QNetworkInterface::interfaceNameFromIndex(*zone));
        }
        return result;
    }
    static std::optional<QList<Entry>> snapshot() {
        int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_DUMP, 0};
        QByteArray data;
        bool loaded = false;
        for (int attempt = 0; attempt < 3; ++attempt) {
            size_t length = 0;
            if (::sysctl(mib, 6, nullptr, &length, nullptr, 0) != 0 || length > 4 * 1024 * 1024) return {};
            data.resize(qsizetype(length));
            if (::sysctl(mib, 6, data.data(), &length, nullptr, 0) == 0) {
                if (length > size_t(data.size())) return {};
                data.resize(qsizetype(length)); loaded = true; break;
            }
            if (errno != ENOMEM) return {};
        }
        if (!loaded) return {};
        QList<Entry> entries;
        const auto invalid = [](const char *stage, qsizetype offset) -> std::optional<QList<Entry>> {
            qWarning() << "Darwin IPv6 routing snapshot rejected" << stage << offset;
            return {};
        };
        for (qsizetype offset = 0; offset < data.size();) {
            if (data.size() - offset < qsizetype(sizeof(rt_msghdr))) return invalid("short-header", offset);
            rt_msghdr header{};
            std::memcpy(&header, data.constData() + offset, sizeof(header));
            if (header.rtm_version != RTM_VERSION || header.rtm_errno
                || header.rtm_msglen < sizeof(header) || header.rtm_msglen > data.size() - offset) return invalid("header", offset);
            QMap<int, QByteArray> addresses;
            qsizetype cursor = offset + sizeof(header), end = offset + header.rtm_msglen;
            for (int bit = 0; bit < RTAX_MAX; ++bit) {
                if (!(header.rtm_addrs & (1 << bit))) continue;
                if (end - cursor < 2) return invalid("short-address", cursor);
                const auto length = static_cast<unsigned char>(data[cursor]);
                const auto step = rounded(length);
                if (step > end - cursor) return invalid("address-length", cursor);
                addresses.insert(1 << bit, QByteArray(data.constData() + cursor, length));
                cursor += step;
            }
            offset = end;
            const auto device = QNetworkInterface::interfaceNameFromIndex(header.rtm_index);
            auto destination = address(addresses.value(RTA_DST), device,
                                       (header.rtm_flags & RTF_LOCAL) != 0);
            if (!destination) {
                qWarning() << "Darwin IPv6 destination decode failed"
                           << "device" << device << "flags" << Qt::hex << header.rtm_flags
                           << "sockaddr" << addresses.value(RTA_DST).toHex();
                return invalid("destination", offset);
            }
            destination->setScopeId({});
            Entry entry;
            entry.destination = *destination;
            entry.up = (header.rtm_flags & RTF_UP) != 0;
            entry.blocked = (header.rtm_flags & (RTF_REJECT | RTF_BLACKHOLE)) != 0;
            entry.managed = (header.rtm_flags & (RTF_STATIC | RTF_PROTO1 | RTF_PROTO2 | RTF_HOST))
                == (RTF_STATIC | RTF_PROTO1 | RTF_PROTO2 | RTF_HOST);
            entry.transient = (header.rtm_flags & (RTF_HOST | RTF_WASCLONED | RTF_IFSCOPE))
                == (RTF_HOST | RTF_WASCLONED | RTF_IFSCOPE)
                && !(header.rtm_flags & (RTF_STATIC | RTF_REJECT | RTF_BLACKHOLE | RTF_LOCAL));
            entry.path.device = device;
            if (header.rtm_flags & RTF_IFSCOPE) entry.scope = device;
            if (header.rtm_flags & RTF_HOST) entry.prefix = 128;
            else {
                const auto mask = addresses.value(RTA_NETMASK);
                bool zero = false;
                for (int i = 0; i < 128; ++i) {
                    const int byte = int(offsetof(sockaddr_in6, sin6_addr)) + i / 8;
                    const bool one = byte < mask.size() && (static_cast<unsigned char>(mask[byte]) & (0x80 >> (i % 8)));
                    if (one && zero) return invalid("noncontiguous-mask", offset);
                    if (one) ++entry.prefix; else zero = true;
                }
            }
            if (header.rtm_flags & RTF_GATEWAY) {
                const auto gateway = address(addresses.value(RTA_GATEWAY), device);
                if (!gateway) {
                    const auto bytes = addresses.value(RTA_GATEWAY);
                    qWarning() << "Darwin IPv6 snapshot gateway family/length"
                               << (bytes.size() >= 2 ? int(static_cast<unsigned char>(bytes[1])) : -1)
                               << bytes.size() << header.rtm_index;
                    return invalid("gateway", offset);
                }
                entry.path.gateway = *gateway;
            }
            entries.append(entry);
        }
        return entries;
    }
    static bool hasSource(const QNetworkInterface &iface) {
        if (!iface.flags().testFlag(QNetworkInterface::IsUp) || iface.flags().testFlag(QNetworkInterface::IsLoopBack)) return false;
        for (const auto &entry : iface.addressEntries()) {
            auto ip = entry.ip(); ip.setScopeId({});
            if (validHost(ip)) return true;
        }
        return false;
    }
    std::optional<QList<Path>> sources(const QString &host) {
        const auto entries = snapshot();
        if (!entries) return {};
        QList<Path> result;
        for (const auto &iface : QNetworkInterface::allInterfaces()) {
            if (!hasSource(iface)) continue;
            const auto found = sourcePath(*entries, QHostAddress(host), iface.name());
            if (found.ambiguous) return {};
            if (found.path) result.append(*found.path);
        }
        return result;
    }
    std::optional<Path> select(const QString &tunnel, const QString &host, bool vpn) {
        const auto entries = snapshot();
        if (!entries) return {};
        if (vpn) {
            const auto iface = QNetworkInterface::interfaceFromName(tunnel);
            if (!hasSource(iface) || !iface.flags().testFlag(QNetworkInterface::IsPointToPoint)) return {};
            const auto found = sourcePath(*entries, QHostAddress(host), tunnel);
            if (found.ambiguous) return {};
            return found.path ? found.path : std::optional<Path>{{tunnel, {}}};
        }
        const auto device = nativeDevice(*entries, tunnel, m_originalDefault,
            [](const QString &name) { return hasSource(QNetworkInterface::interfaceFromName(name)); });
        if (!device) return {};
        const auto found = sourcePath(*entries, QHostAddress(host), *device);
        return found.ambiguous ? std::optional<Path>{} : found.path;
    }

    std::optional<Observed> read(const QString &host, const QString &scope) {
        const auto entries = snapshot();
        if (!entries) return {};
        Observed result;
        for (const auto &entry : *entries) {
            if (entry.prefix != 128 || entry.destination != QHostAddress(host) || entry.scope != scope) continue;
            if (result.exact) return {}; // An ambiguous ownership lookup is not absence.
            result.exact = entry.row();
        }
        return result;
    }
    static bool append(QByteArray &message, const void *data, qsizetype length) {
        if (length < 2 || length > 255 || message.size() + rounded(length) > 2048) return false;
        message.append(static_cast<const char *>(data), length);
        message.append(QByteArray(rounded(length) - length, '\0'));
        return true;
    }
    static std::optional<QByteArray> linkAddress(const QString &device, int index) {
        ifaddrs *interfaces = nullptr;
        if (::getifaddrs(&interfaces) != 0) return {};
        const auto cleanup = qScopeGuard([&] { ::freeifaddrs(interfaces); });
        const auto name = device.toUtf8();
        for (const auto *item = interfaces; item; item = item->ifa_next) {
            if (!item->ifa_addr || item->ifa_addr->sa_family != AF_LINK || name != item->ifa_name) continue;
            sockaddr_dl link{};
            const auto length = item->ifa_addr->sa_len;
            const auto fixed = offsetof(sockaddr_dl, sdl_data);
            if (length < fixed || length < fixed + name.size() || fixed + name.size() > 255) return {};
            std::memcpy(&link, item->ifa_addr, fixed);
            if (link.sdl_index != index || link.sdl_nlen != name.size()) return {};
            // Identify the actual interface, not its own Ethernet MAC as an
            // invented destination-neighbor address.
            link.sdl_len = fixed + name.size(); link.sdl_alen = link.sdl_slen = 0;
            QByteArray result(link.sdl_len, '\0');
            std::memcpy(result.data(), &link, fixed);
            std::memcpy(result.data() + fixed, name.constData(), name.size());
            return result;
        }
        return {};
    }
    static bool exchange(int type, const Route &route) {
        const auto index = QNetworkInterface::interfaceIndexFromName(route.path.device);
        if (!index || index > (std::numeric_limits<quint16>::max)() || (!route.scope.isEmpty() && route.scope != route.path.device)) return false;
        const int fd = ::socket(PF_ROUTE, SOCK_RAW, 0);
        if (fd < 0) return false;
        const auto cleanup = qScopeGuard([&] { ::close(fd); });
        if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || ::fcntl(fd, F_SETFL, O_NONBLOCK) != 0) return false;
        rt_msghdr header{};
        header.rtm_version = RTM_VERSION; header.rtm_type = type;
        header.rtm_pid = ::getpid();
        static std::atomic<unsigned> sequence{0x4f560000U};
        header.rtm_seq = int((++sequence) & 0x7fffffffU);
        header.rtm_index = route.scope.isEmpty() ? 0 : index;
        header.rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC | RTF_PROTO1 | RTF_PROTO2;
        if (!route.scope.isEmpty()) header.rtm_flags |= RTF_IFSCOPE;
        header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_IFP;
        sockaddr_in6 destination{};
        destination.sin6_len = sizeof(destination); destination.sin6_family = AF_INET6;
        const auto address = QHostAddress(route.host).toIPv6Address();
        std::memcpy(&destination.sin6_addr, address.c, 16);
        QByteArray message(sizeof(header), '\0');
        if (!append(message, &destination, sizeof(destination))) return false;
        const auto link = linkAddress(route.path.device, index);
        if (!link) return false;
        if (route.path.gateway.isNull()) {
            if (!append(message, link->constData(), link->size())) return false;
        } else {
            sockaddr_in6 gateway{};
            gateway.sin6_len = sizeof(gateway); gateway.sin6_family = AF_INET6;
            const auto ip = route.path.gateway.toIPv6Address();
            std::memcpy(&gateway.sin6_addr, ip.c, 16);
            if (route.path.gateway.isLinkLocal()) gateway.sin6_scope_id = index;
            header.rtm_flags |= RTF_GATEWAY;
            if (!append(message, &gateway, sizeof(gateway))) return false;
        }
        if (!append(message, link->constData(), link->size())) return false;
        header.rtm_msglen = message.size();
        std::memcpy(message.data(), &header, sizeof(header));
        if (::write(fd, message.constData(), message.size()) != message.size()) return false;
        QElapsedTimer deadline; deadline.start();
        while (deadline.elapsed() < 2000) {
            const auto remaining = 2000 - deadline.elapsed();
            if (remaining <= 0) return false;
            pollfd ready{fd, POLLIN, 0};
            const int status = ::poll(&ready, 1, int(remaining));
            if (status < 0 && errno == EINTR) continue;
            if (status <= 0 || !(ready.revents & POLLIN)) return false;
            alignas(rt_msghdr) char bytes[8192];
            const auto received = ::recv(fd, bytes, sizeof(bytes), 0);
            if (received < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (received <= 0) return false;
            // Other route/address/interface notifications can be shorter
            // than rt_msghdr. They are not replies to this operation.
            if (received < qsizetype(sizeof(rt_msghdr))) continue;
            rt_msghdr reply{}; std::memcpy(&reply, bytes, sizeof(reply));
            if (reply.rtm_type != RTM_ADD && reply.rtm_type != RTM_CHANGE
                && reply.rtm_type != RTM_DELETE && reply.rtm_type != RTM_GET) continue;
            if (reply.rtm_pid != header.rtm_pid || reply.rtm_seq != header.rtm_seq) continue;
            if (reply.rtm_version != RTM_VERSION || reply.rtm_msglen < sizeof(reply) || reply.rtm_msglen > received) return false;
            if (reply.rtm_errno)
                qWarning() << "Darwin IPv6 route mutation rejected" << type << reply.rtm_errno;
            return reply.rtm_type == type && reply.rtm_errno == 0;
        }
        return false;
    }
    bool mutate(int type, const Route &route) {
        if (!route.managed || route.transient || !validHost(QHostAddress(route.host)) || !validPath(route.path)) return false;
        if (!exchange(type, route)) {
            qWarning() << "Darwin IPv6 route exchange failed" << type;
            return false;
        }
        const auto after = read(route.host, route.scope);
        if (!after) {
            qWarning() << "Darwin IPv6 route verification snapshot unavailable" << type;
            return false;
        }
        return type == RTM_DELETE ? (!after->exact || !(*after->exact == route))
            : after->exact && *after->exact == route;
    }
    QString m_originalDefault;
};
} // namespace amnezia::macOpenVpnIpv6
#endif
