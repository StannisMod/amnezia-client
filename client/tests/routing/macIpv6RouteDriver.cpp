#include <QCoreApplication>
#include <QTextStream>
#include <QRegularExpression>
#include <QProcess>
#include "../../platforms/macos/daemon/macopenvpnipv6native.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (qEnvironmentVariable("AMNEZIA_NATIVE_IPV6_LAB") != "owned-runner"
        || qEnvironmentVariable("GITHUB_ACTIONS") != "true") return 64;
    const auto args = app.arguments();
    if (args.size() != 6 && args.size() != 7) return 64;
    const auto operation = args[1], host = args[2], scope = args[3], device = args[4];
    // Only synthetic private IPv6 hosts and owned utun paths are accepted.
    const QHostAddress address(host);
    const auto owned = [](const QString &name) {
        return QRegularExpression(QStringLiteral("^utun[0-9]+$")).match(name).hasMatch();
    };
    if (!address.isInSubnet(QHostAddress("fc00::"), 7) || !owned(device)
        || (!scope.isEmpty() && scope != device) || args[5] != "managed") return 64;
    using namespace amnezia::macOpenVpnIpv6;
    Native native;
    const auto api = native.api();
    const Route after{host, scope, Path{device, {}}, true};
    bool result = false;
    if (operation == "create") result = api.create(after);
    else if (operation == "remove") result = api.removeOwned(after);
    else if (operation == "change" && args.size() == 7 && owned(args[6])) {
        const Route before{host, scope, Path{args[6], {}}, true};
        result = api.changeOwned(before, after);
    } else return 64;
    if (!result) {
        const auto observed = api.read(host, scope);
        qWarning() << "Native probe read available" << bool(observed)
                   << "exact row" << (observed && bool(observed->exact));
        QProcess table;
        table.start("/usr/sbin/netstat", {"-rn", "-f", "inet6"});
        if (table.waitForFinished(10000)) {
            for (const auto &line : table.readAllStandardOutput().split('\n'))
                if (line.contains(host.toUtf8())) qWarning().noquote() << line;
        }
    }
    QTextStream(stdout) << (result ? "OK\n" : "FAIL\n");
    return result ? 0 : 1;
}
