#pragma once

#include "core/utils/proxyIpv6Routes.h"
#include <QDir>
#include <QProcess>
#include <functional>

class WindowsProxyIpv6 {
public:
    // Command syntax: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface
    using Runner = std::function<bool(const QStringList &)>;
    explicit WindowsProxyIpv6(quint32 index, Runner runner = run) : m_index(index), m_run(std::move(runner)) {}
    WindowsProxyIpv6(const WindowsProxyIpv6 &) = delete;
    WindowsProxyIpv6 &operator=(const WindowsProxyIpv6 &) = delete;
    ~WindowsProxyIpv6() { clear(); }

    bool configure(const QStringList &included, const QStringList &excluded)
    {
        if (!m_index || m_addressAdded || !m_routes.isEmpty()) return false;
        QStringList routes;
        if (!amnezia::routing::proxyIpv6Routes(included, excluded, routes)) return false;
        if (!m_run({"interface", "ipv6", "add", "address", interfaceArgument(),
                    "address=" + address() + "/126", "store=active", "skipassource=false"})) return false;
        m_addressAdded = true;
        for (const auto &route : routes) {
            if (!m_run(routeArguments("add", route))) { clear(); return false; }
            m_routes.append(route);
        }
        return true;
    }
    bool clear()
    {
        bool success = true;
        for (int i = m_routes.size() - 1; i >= 0; --i) {
            if (m_run(routeArguments("delete", m_routes[i]))) m_routes.removeAt(i);
            else success = false;
        }
        if (m_addressAdded && m_routes.isEmpty()) {
            if (m_run({"interface", "ipv6", "delete", "address", interfaceArgument(), "address=" + address(), "store=active"}))
                m_addressAdded = false;
            else success = false;
        }
        return success;
    }
private:
    QString interfaceArgument() const { return "interface=" + QString::number(m_index); }
    static QString address() { return "fdfe:dcba:9876::2"; }
    QStringList routeArguments(const QString &operation, const QString &prefix) const
    {
        QStringList args{"interface", "ipv6", operation, "route", "prefix=" + prefix,
                         interfaceArgument(), "nexthop=::", "store=active"};
        if (operation == "add") args << "metric=1" << "publish=no";
        return args;
    }
    static bool run(const QStringList &arguments)
    {
        QProcess process;
        const auto netsh = QDir(qEnvironmentVariable("SystemRoot", "C:/Windows")).filePath("System32/netsh.exe");
        process.start(netsh, arguments);
        if (!process.waitForStarted(5000) || !process.waitForFinished(5000)) {
            process.kill(); process.waitForFinished(1000); return false;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) return true;
        qWarning() << "Proxy IPv6 command failed" << arguments << process.readAllStandardError();
        return false;
    }
    quint32 m_index;
    Runner m_run;
    QStringList m_routes;
    bool m_addressAdded = false;
};
