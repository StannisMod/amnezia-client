#include <QCoreApplication>
#include <QLocalSocket>
#include <QRemoteObjectNode>
#include <QNetworkInterface>
#include <QProcess>
#include <QTimer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QtEndian>
#include <QElapsedTimer>
#include <QThread>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDirIterator>
#include <QFile>
#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"
#include "linuxdnsrecovery.h"
#include "xrayStopSequence.h"

void require(bool value, const char *message) { if (!value) qFatal("%s", message); }
template<class Call> auto reply(Call call)
{
    require(call.waitForFinished(5000), "QtRO reply deadline");
    return call.returnValue();
}
QSharedPointer<IpcInterfaceReplica> remote;
struct IpcClient {
    template<class Success, class Failure> static bool withInterface(Success yes, Failure no)
    {
        return remote && remote->isReplicaValid() ? yes(remote) : no();
    }
};
namespace Vpn { enum class ConnectionState { Disconnected }; }
// Minimal caller context around the verbatim production stop body. Operations
// below are real QtRO calls to the production service, not mock replies.
class XrayProtocol : public QObject {
public:
    QString m_dnsOwner = "xray-real-stop-fixture";
    bool m_dnsAttempted = true, m_tunPrepared = true, m_routingApplied = true;
    bool m_destroying = false, m_stopRetryScheduled = false, guarded = false, disconnected = false;
    quint64 m_tunGeneration = 1;
    qint64 m_xrayToken = 0;
    QSharedPointer<IpcProcessInterfaceReplica> m_tun2socksProcess;
    QMetaObject::Connection m_dnsFailureConnection;
    XrayStopSequence m_stopSequence;
    bool guardStop() { const bool previous = guarded; guarded = true; return previous; }
    void resetStopGuard() { guarded = false; }
    void setConnectionState(Vpn::ConnectionState) { disconnected = true; }
    void stop();
};
const QString tunName = "tun2";
#include "production-stop.inc"

QByteArray protection()
{
    QByteArray result;
    for (const auto &arguments : {QStringList{"-6", "route", "show", "table", "all"},
                                  QStringList{"-6", "rule", "show"}}) {
        QProcess process;
        process.start("ip", arguments);
        require(process.waitForFinished(5000) && process.exitCode() == 0,
                "read real IPv6 capture protection");
        result += process.readAllStandardOutput();
    }
    return result;
}
bool socksAlive()
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, 10808);
    if (!socket.waitForConnected(1000)) return false;
    socket.write(QByteArray::fromHex("050100"));
    if (!socket.waitForReadyRead(1000)) return false;
    return socket.read(2) == QByteArray::fromHex("0500");
}
void dnsQueries(const QJsonObject &published)
{
    for (const auto &value : published["dns"].toArray()) {
        const QHostAddress endpoint(value.toString());
        for (bool tcp : {false, true}) for (int type : {28, 1}) {
            auto query = QByteArray::fromHex("0123010000010000000000000570726f6265076578616d706c6500001c0001");
            query[query.size() - 3] = char(type);
            QByteArray answer;
            if (tcp) {
                QTcpSocket socket;
                socket.connectToHost(endpoint, 53);
                require(socket.waitForConnected(1000), "DNS TCP connect");
                QByteArray framed(2, 0);
                qToBigEndian<quint16>(query.size(), framed.data());
                socket.write(framed + query);
                while (answer.size() < 2)
                    require(socket.waitForReadyRead(1000) && (answer += socket.readAll()).size(),
                            "DNS TCP length");
                const auto length = qFromBigEndian<quint16>(answer.constData());
                while (answer.size() < length + 2)
                    require(socket.waitForReadyRead(1000) && (answer += socket.readAll()).size(),
                            "DNS TCP body");
                answer.remove(0, 2);
            } else {
                QUdpSocket socket;
                require(socket.writeDatagram(query, endpoint, 53) == query.size(), "DNS UDP write");
                require(socket.waitForReadyRead(1000), "DNS UDP answer");
                answer.resize(socket.pendingDatagramSize());
                require(socket.readDatagram(answer.data(), answer.size()) == answer.size(), "DNS UDP body");
            }
            require(answer.size() >= 12 && qFromBigEndian<quint16>(answer.constData()) == 0x123
                    && (uchar(answer[3]) & 15) == (type == 28 ? 0 : 2)
                    && qFromBigEndian<quint16>(answer.constData() + 6) == 0,
                    "actual DNS NODATA/SERVFAIL");
        }
    }
}
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    require(qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SERVICE_TEST") == "isolated-namespace",
            "requires isolated namespace");
    QRemoteObjectNode node;
    QLocalSocket transport;
    transport.connectToServer("/tmp/local:AmneziaVpnIpcInterface");
    require(transport.waitForConnected(5000), "service socket");
    node.addClientSideConnection(&transport);
    remote.reset(node.acquire<IpcInterfaceReplica>());
    require(remote->waitForSource(5000), "main replica");
    XrayProtocol caller;
    caller.m_xrayToken = reply(remote->xrayStartOwned(
        R"({"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":"freedom","settings":{}}]})"));
    require(caller.m_xrayToken != 0 && socksAlive(), "actual Xray runtime started");
    const auto baselineProtection = protection();
    require(reply(remote->createTun("tun2", "198.18.0.1")), "service-owned TUN");
    const int index = QNetworkInterface::interfaceFromName("tun2").index();
    require(index > 0, "actual TUN exists");
    const auto backend = LinuxDnsRecovery::systemBackend();
    const auto before = backend.read(index);
    require(!before.isEmpty(), "read initial real resolved state");
    const int descriptor = reply(remote->createPrivilegedProcess());
    require(descriptor > 0, "worker descriptor");
    QRemoteObjectNode workerNode;
    QLocalSocket workerTransport;
    workerTransport.connectToServer(QString("/tmp/local:AmneziaVpnIpcInterface_%1").arg(descriptor));
    require(workerTransport.waitForConnected(5000), "worker socket");
    workerNode.addClientSideConnection(&workerTransport);
    caller.m_tun2socksProcess.reset(workerNode.acquire<IpcProcessInterfaceReplica>());
    auto worker = caller.m_tun2socksProcess;
    require(worker->waitForSource(5000), "worker replica");
    worker->setProgram(3);
    worker->setArguments({"-device", "tun://tun2", "-proxy", "socks5://127.0.0.1:10808"});
    worker->start();
    require(reply(worker->waitForStarted(3000)) || !reply(worker->processStopped()),
            "real tun2socks started");
    require(!reply(worker->processStopped()), "real worker remains running");
    QElapsedTimer readiness;
    readiness.start();
    QByteArray startup;
    while (!startup.contains("[STACK]") && readiness.elapsed() < 5000) {
        startup += reply(worker->readAllStandardOutput());
        startup += reply(worker->readAllStandardError());
        if (!startup.contains("[STACK]")) QThread::msleep(20);
    }
    require(startup.contains("[STACK]"), "real tun2socks STACK readiness before DNS publication");
    // Linux Xray uses service-owned native capture, not the Windows/macOS
    // setNativeIpv6Blocked RPC. Match the actual setupRouting OFF path.
    require(reply(remote->configureProxyIpv6({"::/0"}, {})), "real IPv6 capture protection enabled");
    const auto protectedRules = protection();
    require(reply(remote->updateResolversWithPolicy("tun2", {QHostAddress("2001:db8::53")},
                                                   false, caller.m_dnsOwner)), "guarded DNS published");
    const auto published = backend.read(index);
    require(!published["dns"].toArray().isEmpty(), "actual alias publication");
    dnsQueries(published);
    if (app.arguments().size() == 3 && app.arguments()[1] == "--publish-only") {
        QFile record(app.arguments()[2]);
        require(record.open(QIODevice::WriteOnly), "publish-only state record");
        record.write(QJsonDocument(QJsonObject{{"index", index}, {"before", before},
            {"published", published}, {"baseline_capture", QString::fromUtf8(baselineProtection)},
            {"protected_capture", QString::fromUtf8(protectedRules)}}).toJson());
        qInfo("PASS: active Xray/worker/TUN/native capture retained by systemd service after replica exit");
        return 0;
    }
    const QJsonArray external{QString("192.0.2.77")};
    require(backend.write(index, "dns", external), "external DNS edit");
    const auto owner = caller.m_dnsOwner;
    const auto token = caller.m_xrayToken;
    caller.stop();
    require(caller.m_dnsOwner == owner && caller.m_dnsAttempted, "owner retained after refused restore");
    require(caller.m_xrayToken == token && socksAlive(), "engine retained");
    require(caller.m_tun2socksProcess && !reply(worker->processStopped()), "worker retained");
    require(QNetworkInterface::interfaceFromName("tun2").index() == index, "TUN retained");
    require(backend.read(index)["dns"].toArray() == external, "external DNS not overwritten");
    require(protection() == protectedRules && !caller.disconnected, "protection retained");
    dnsQueries(published);
    qInfo("PASS: real refused DNS restore retains owner/TUN/worker/Xray/protection");
    require(backend.write(index, "dns", published["dns"]), "fixture resolves external edit");
    caller.stop();
    require(caller.m_stopSequence.complete() && caller.disconnected, "confirmed cleanup completion");
    require(caller.m_dnsOwner.isEmpty() && !caller.m_dnsAttempted && !caller.m_xrayToken,
            "owner released only after cleanup");
    require(!caller.m_tun2socksProcess && reply(worker->processStopped()), "worker joined");
    require(!QNetworkInterface::interfaceFromName("tun2").isValid(), "TUN removed");
    require(!socksAlive(), "actual Xray engine stopped");
    require(protection() == baselineProtection, "native IPv6 routes/rules retired");
    QDirIterator journals(qEnvironmentVariable("XDG_CONFIG_HOME"), {"owned-*.json"},
                         QDir::Files, QDirIterator::Subdirectories);
    require(!journals.hasNext(), "durable DNS journal retired");
    qInfo("PASS: real QtRO retry confirms worker join/TUN deletion/Xray stop/journal retirement");
    return 0;
}
