#include <QCoreApplication>
#include <QTextStream>
#include "platforms/linux/daemon/linuxopenvpnipv6routes.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (qEnvironmentVariable("AMNEZIA_IPV6_LAB") != "isolated-namespace") return 64;
    LinuxOpenVpnIpv6Routes routes;
    QTextStream input(stdin), output(stdout);
    output << "READY\n" << Qt::flush;
    while (!input.atEnd()) {
        const auto document = QJsonDocument::fromJson(input.readLine().toUtf8()).object();
        QStringList hosts;
        for (const auto &host : document.value("hosts").toArray()) hosts << host.toString();
        output << (routes.add(document.value("local_ipv4").toString(), hosts,
                              document.value("through_vpn").toBool()) ? "OK\n" : "FAIL\n") << Qt::flush;
    }
}
