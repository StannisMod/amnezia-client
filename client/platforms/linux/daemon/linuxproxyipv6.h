#pragma once

#include "linuxroutingtable.h"
#include <QHostAddress>
#include <memory>

// The proxy owns only a new policy table and one address on its own TUN.
// Throw routes preserve the administrator's original routing policy.
class LinuxProxyIpv6 {
public:
    ~LinuxProxyIpv6() { if (m_addressAdded) run({"-6", "addr", "del", address(), "dev", "tun2"}); }

    bool configure(const QStringList &included, const QStringList &excluded)
    {
        if (m_table || m_addressAdded) return false;
        QStringList routes, exceptions;
        if (!parse(included, routes) || !parse(excluded, exceptions)) return false;
        if (!run({"-6", "addr", "add", address(), "dev", "tun2", "nodad"})) return false;
        m_addressAdded = true;
        m_table = std::make_unique<LinuxRoutingTable>();
        if (!m_table->ensureFamily("-6")) return false;
        const auto table = QString::number(m_table->table());
        for (const auto &prefix : routes)
            if (!run({"-6", "route", "add", prefix, "dev", "tun2", "table", table})) return false;
        for (const auto &prefix : exceptions)
            if (!run({"-6", "route", "replace", "throw", prefix, "table", table})) return false;
        return true;
    }

private:
    static QString address() { return "fdfe:dcba:9876::2/126"; }
    static bool parse(const QStringList &input, QStringList &output)
    {
        if (input.size() > 4096) return false;
        for (const auto &value : input) {
            const auto subnet = QHostAddress::parseSubnet(value);
            if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol || subnet.second < 0
                || !subnet.first.scopeId().isEmpty()) return false;
            output.append(subnet.first.toString() + '/' + QString::number(subnet.second));
        }
        output.removeDuplicates();
        return true;
    }
    static bool run(const QStringList &arguments)
    {
        QProcess process;
        process.start("ip", arguments);
        if (!process.waitForStarted(5000) || !process.waitForFinished(5000)) {
            process.kill(); process.waitForFinished(1000); return false;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) return true;
        qWarning() << "Proxy IPv6 command failed" << arguments << process.readAllStandardError();
        return false;
    }
    bool m_addressAdded = false;
    std::unique_ptr<LinuxRoutingTable> m_table;
};
