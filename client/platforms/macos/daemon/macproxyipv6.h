#pragma once

#include "core/utils/proxyIpv6Routes.h"
#include <QProcess>
#include <functional>

class MacProxyIpv6 {
public:
    using Runner = std::function<bool(const QString &, const QStringList &)>;
    explicit MacProxyIpv6(Runner runner = run) : m_run(std::move(runner)) {}
    MacProxyIpv6(const MacProxyIpv6 &) = delete;
    MacProxyIpv6 &operator=(const MacProxyIpv6 &) = delete;
    ~MacProxyIpv6() { clear(); }

    bool configure(const QStringList &included, const QStringList &excluded)
    {
        if (m_addressAdded || !m_routes.isEmpty()) return false;
        QStringList routes;
        if (!amnezia::routing::proxyIpv6Routes(included, excluded, routes)) return false;
        if (!m_run("/sbin/ifconfig", {"utun22", "inet6", address(), "prefixlen", "126", "alias"})) return false;
        m_addressAdded = true;
        for (const auto &route : routes) {
            if (!m_run("/sbin/route", routeArguments("add", route))) {
                clear();
                return false;
            }
            m_routes.append(route);
        }
        return true;
    }

    bool clear()
    {
        bool success = true;
        for (int i = m_routes.size() - 1; i >= 0; --i) {
            if (m_run("/sbin/route", routeArguments("delete", m_routes[i]))) m_routes.removeAt(i);
            else success = false;
        }
        if (m_addressAdded && m_routes.isEmpty()) {
            if (m_run("/sbin/ifconfig", {"utun22", "inet6", address(), "-alias"})) m_addressAdded = false;
            else success = false;
        }
        return success;
    }

private:
    static QString address() { return "fdfe:dcba:9876::2"; }
    static QStringList routeArguments(const QString &operation, const QString &prefix)
    { return {"-n", operation, "-inet6", "-net", prefix, "-interface", "utun22"}; }
    static bool run(const QString &program, const QStringList &arguments)
    {
        QProcess process;
        process.start(program, arguments);
        if (!process.waitForStarted(5000) || !process.waitForFinished(5000)) {
            process.kill(); process.waitForFinished(1000); return false;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0) return true;
        qWarning() << "Proxy IPv6 command failed" << program << arguments << process.readAllStandardError();
        return false;
    }
    Runner m_run;
    QStringList m_routes;
    bool m_addressAdded = false;
};
