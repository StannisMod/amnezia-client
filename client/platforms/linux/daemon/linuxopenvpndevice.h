#pragma once

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QProcess>
#include <QUuid>
#include <cerrno>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

// Reserve an unpredictable, absent device name before starting our OpenVPN.
// Never infer ownership from tun* names, address ranges or a global link diff.
// tun0 prefix also retains the existing Linux kill-switch interface policy.
class LinuxOpenVpnDevice {
public:
    LinuxOpenVpnDevice()
    {
        do {
            m_name = "tun0" + QUuid::createUuid().toString(QUuid::Id128).left(11);
        } while (QNetworkInterface::interfaceFromName(m_name).isValid());
    }
    ~LinuxOpenVpnDevice() { cleanup(); }
    LinuxOpenVpnDevice(const LinuxOpenVpnDevice &) = delete;
    LinuxOpenVpnDevice &operator=(const LinuxOpenVpnDevice &) = delete;

    QStringList arguments() const { return {"--dev", m_name, "--dev-type", "tun"}; }

    bool cleanup()
    {
        const auto iface = QNetworkInterface::interfaceFromName(m_name);
        if (!iface.isValid()) return true; // Userspace TUN / graceful DCO exit.
        QProcess inspect;
        inspect.start("ip", {"-d", "-j", "link", "show", "dev", m_name});
        if (!inspect.waitForStarted(1000) || !inspect.waitForFinished(1000)) {
            inspect.kill(); inspect.waitForFinished(1000); return false;
        }
        const auto links = QJsonDocument::fromJson(inspect.readAllStandardOutput()).array();
        if (inspect.exitCode() != 0 || links.size() != 1) return false;
        const auto link = links[0].toObject();
        const auto kind = link.value("linkinfo").toObject().value("info_kind").toString();
        // An unexpected/replaced kind is never ours to delete. Ordinary TUN
        // closes with its file descriptor; only persistent DCO needs this step.
        if (link.value("ifname").toString() != m_name || link.value("ifindex").toInt() != iface.index()
            || (kind != "ovpn" && kind != "ovpn-dco")) return false;

        // Delete by the inspected index, not a name that could be reassigned
        // between inspection and deletion. The kernel removes its own routes.
        const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) return false;
        struct Request { nlmsghdr header; ifinfomsg interface; } request{};
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
        request.header.nlmsg_type = RTM_DELLINK;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        request.header.nlmsg_seq = 1;
        request.interface.ifi_family = AF_UNSPEC;
        request.interface.ifi_index = iface.index();
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        bool success = false;
        if (sendto(fd, &request, request.header.nlmsg_len, 0,
                   reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) == request.header.nlmsg_len) {
            pollfd ready{fd, POLLIN, 0};
            if (poll(&ready, 1, 1000) > 0) {
                alignas(nlmsghdr) char buffer[4096];
                int remaining = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
                for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); NLMSG_OK(header, remaining);
                     header = NLMSG_NEXT(header, remaining)) {
                    if (header->nlmsg_seq == 1 && header->nlmsg_type == NLMSG_ERROR
                        && header->nlmsg_len >= NLMSG_LENGTH(sizeof(nlmsgerr))) {
                        const auto error = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(header))->error;
                        success = error == 0 || error == -ENODEV;
                    }
                }
            }
        }
        ::close(fd);
        return success;
    }
private:
    QString m_name;
};
