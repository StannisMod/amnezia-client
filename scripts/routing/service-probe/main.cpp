#include <QCoreApplication>
#include <QRemoteObjectNode>
#include <QProcess>
#include <QJsonArray>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QFile>
#include "rep_ipc_interface_replica.h"

// Disposable CI client of the real installed service's existing QtRO API.
// It sends no user profile or credentials and adds no production IPC methods.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) return 2;
    const QString mode(argv[1]);
    if (mode != "on" && mode != "off" && mode != "proxy-ipv6" && mode != "proxy-ipv6-data") return 2;
    if (mode.startsWith("proxy-ipv6") && qEnvironmentVariable("AMNEZIA_PROXY_ROUTE_TEST") != "isolated-docker") return 2;
    QRemoteObjectNode node;
#ifdef Q_OS_WIN
    node.connectToNode(QUrl("local:local:AmneziaVpnIpcInterface"));
#else
    node.connectToNode(QUrl("local:/tmp/local:AmneziaVpnIpcInterface"));
#endif
    QScopedPointer<IpcInterfaceReplica> replica(node.acquire<IpcInterfaceReplica>());
    if (!replica->waitForSource(8000)) return 3;
#ifdef Q_OS_LINUX
    if (mode.startsWith("proxy-ipv6")) {
        const bool dataTest = mode == "proxy-ipv6-data";
        auto ok = [](auto call) { return call.waitForFinished(12000) && call.returnValue(); };
        auto ip = [](const QStringList &args) {
            QProcess p; p.start("ip", args);
            if (!p.waitForFinished(5000) || p.exitCode() != 0) return QByteArray();
            return p.readAllStandardOutput();
        };
        auto ip6tables = [](const QStringList &args) {
            QProcess p; p.start("ip6tables", args);
            return p.waitForFinished(5000) && p.exitCode() == 0;
        };
        const auto originalRules = ip({"-6", "rule", "show"});
        if (!ok(replica->createTun("tun2", "198.18.0.1"))) return 10;
        const QStringList excluded = dataTest ? QStringList{qEnvironmentVariable("AMNEZIA_PROXY_SERVER_SUBNET")} : QStringList{"2001:db8:2::/64"};
        if (!ok(replica->configureProxyIpv6({"::/0"}, excluded))) return 11;
        if (!ip({"-6", "route", "get", "fd42::2"}).contains("dev tun2")) return 12;
        const auto directDevice = qEnvironmentVariable("AMNEZIA_PROXY_DIRECT_DEVICE", "lan0").toUtf8();
        if (!dataTest && !ip({"-6", "route", "get", "2001:db8:2::42"}).contains("dev " + directDevice)) return 13;
        const QJsonObject config{{"splitTunnelType",0},{"splitTunnelSites",QJsonArray()},
            {"dns1","2606:4700:4700::1111"},{"vpnServer","2001:db8:1::42"},{"proxyIpv6",true}};
        if (!ok(replica->enableKillSwitch(config,0))) return 14;
        if (!ip6tables({"-C","amnvpn.a.200.allowVPN","-j","amnvpn.200.allowVPN"})) return 15;
        if (!ip6tables({"-C","amnvpn.110.allowNets","-d","2001:db8:1::42/128","-j","ACCEPT"})) return 16;
        if (!ip6tables({"-C","amnvpn.320.allowDNS","-o","tun2+","-d","2606:4700:4700::1111/128","-p","udp","--dport","53","-j","ACCEPT"})) return 17;
        if (ip6tables({"-C","amnvpn.a.250.blockIPv6","-j","amnvpn.250.blockIPv6"})) return 18;
        if (!ip6tables({"-C","amnvpn.a.100.blockAll","-j","amnvpn.100.blockAll"})) return 19;
        if (dataTest) {
            if (!ip({"-6","route","get","2001:db8:99::1"}).contains("dev tun2")) return 22;
            QFile configuration(qEnvironmentVariable("AMNEZIA_PROXY_CLIENT_CONFIG"));
            if (!configuration.open(QIODevice::ReadOnly)) return 29;
            auto xray = replica->xrayStartOwned(QString::fromUtf8(configuration.readAll()));
            if (!xray.waitForFinished(12000) || xray.returnValue() == 0) return 30;
            QProcess tun;
            tun.start(qEnvironmentVariable("AMNEZIA_TUN2SOCKS"), {"-device","tun://tun2","-proxy","socks5://127.0.0.1:39081"});
            if (!tun.waitForStarted(5000)) return 23;
            QByteArray startup;
            for (int i=0; i<30 && !startup.contains("[STACK]"); ++i) {
                tun.waitForReadyRead(100); startup += tun.readAllStandardError(); startup += tun.readAllStandardOutput();
            }
            if (!startup.contains("[STACK]")) { qWarning()<<startup; return 24; }
            QTcpSocket tcp;
            tcp.connectToHost(QHostAddress("2001:db8:99::1"),18081);
            if (!tcp.waitForConnected(5000)) {qWarning()<<tcp.errorString()<<tun.readAllStandardError();return 25;}
            tcp.write("linux-tun-proof\n"); tcp.waitForBytesWritten(5000);
            QByteArray reply;
            while (!reply.endsWith('\n') && tcp.waitForReadyRead(5000)) reply += tcp.readAll();
            if (!reply.endsWith(":linux-tun-proof\n")) {qWarning()<<reply<<tcp.errorString()<<tun.readAllStandardError();return 26;}
            QUdpSocket udp;
            if (udp.writeDatagram("linux-tun-udp",QHostAddress("2001:db8:99::1"),18082)<0 || !udp.waitForReadyRead(5000)) return 27;
            QByteArray packet(256,0); const auto size=udp.readDatagram(packet.data(),packet.size());
            if (packet.left(size)!="linux-tun-udp") return 28;
            tcp.disconnectFromHost(); tun.terminate(); if (!tun.waitForFinished(2000)) {tun.kill();tun.waitForFinished(1000);}
            if (!ok(replica->xrayStopOwned(xray.returnValue()))) return 31;
            qInfo("LINUX_PROXY_IPV6_TUN_TCP_UDP_PASS");
        }
        if (!ok(replica->disableKillSwitch()) || !ok(replica->deleteTun("tun2"))) return 20;
        if (ip({"-6","rule","show"}) != originalRules) return 21;
        qInfo("LINUX_PROXY_IPV6_IPC_PASS");
        return 0;
    }
#endif
    auto call = replica->refreshKillSwitch(QString(argv[1]) == "on");
    if (!call.waitForFinished(12000) || !call.returnValue()) return 4;
    return 0;
}
