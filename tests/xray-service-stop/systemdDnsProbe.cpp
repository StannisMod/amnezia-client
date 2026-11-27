#include <QCoreApplication>
#include <QLocalSocket>
#include <QRemoteObjectNode>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QNetworkInterface>
#include <QUdpSocket>
#include <QtEndian>
#include <QProcess>
#include <QTcpSocket>
#include <QDirIterator>
#include "rep_ipc_interface_replica.h"
#include "linuxdnsrecovery.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() != 3) return 2;
    const auto backend = LinuxDnsRecovery::systemBackend();
    if (args[1] == "snapshot-openvpn") {
        for (const auto &root : {QString("/root/.config"), QString("/.config")}) {
        QDirIterator journals(root, {"owned-*.json"}, QDir::Files, QDirIterator::Subdirectories);
        while (journals.hasNext()) {
            const auto path = journals.next();
            QFile journal(path);
            if (!journal.open(QIODevice::ReadOnly)) return 23;
            const auto stored = QJsonDocument::fromJson(journal.readAll()).object();
            const auto recovery = stored["dns_recovery"].toObject();
            qInfo() << "Snapshot candidate" << path << "protocol"
                    << recovery["protocol_metadata"].toObject().value("protocol");
            if (recovery["protocol_metadata"].toObject()["protocol"] != QJsonValue("openvpn")) continue;
            const int index = stored["interface_index"].toInt();
            QJsonObject before;
            for (const auto &link : recovery["links"].toArray())
                if (link.toObject()["index"].toInt() == index) before = link.toObject()["before"].toObject();
            if (before.isEmpty()) return 24;
            QFile record(args[2]);
            if (!record.open(QIODevice::WriteOnly)) return 25;
            record.write(QJsonDocument(QJsonObject{{"index", index}, {"before", before},
                {"published", backend.read(index)}}).toJson());
            return 0;
        }
        }
        return 26;
    }
    if (args[1] == "inspect" || args[1] == "external" || args[1] == "resolve"
            || args[1] == "blocked" || args[1] == "conflict" || args[1] == "retired") {
        QFile file(args[2]);
        if (!file.open(QIODevice::ReadOnly)) return 3;
        const auto record = QJsonDocument::fromJson(file.readAll()).object();
        const int index = record["index"].toInt();
        if (args[1] == "retired") {
            if (QNetworkInterface::interfaceFromIndex(index).isValid()) return 18;
            for (const auto &iface : QNetworkInterface::allInterfaces())
                for (const auto &address : iface.addressEntries())
                    if (record["published"].toObject()["dns"].toArray().contains(address.ip().toString()))
                        return 19;
            QTcpSocket engine;
            engine.connectToHost(QHostAddress::LocalHost, 10808);
            if (engine.waitForConnected(500)) return 20;
            QByteArray capture;
            for (const auto &arguments : {QStringList{"-6", "route", "show", "table", "all"},
                                          QStringList{"-6", "rule", "show"}}) {
                QProcess command;
                command.start("ip", arguments);
                if (!command.waitForFinished(5000) || command.exitCode()) return 21;
                capture += command.readAllStandardOutput();
            }
            if (capture != record["baseline_capture"].toString().toUtf8()) return 22;
            qInfo("PASS: active native TUN/engine/capture retired after confirmed systemd stop");
            return 0;
        }
        if (args[1] == "external")
            return backend.write(index, "dns", QJsonArray{QString("192.0.2.77")}) ? 0 : 13;
        if (args[1] == "resolve")
            return backend.write(index, "dns", record["published"].toObject()["dns"]) ? 0 : 14;
        const auto current = backend.read(record["index"].toInt());
        const auto before = record["before"].toObject();
        qInfo().noquote() << QJsonDocument(current).toJson(QJsonDocument::Compact);
        if (args[1] == "blocked" || args[1] == "conflict") {
            if (current["dns"].toArray() != QJsonArray{QString("192.0.2.77")}) return 15;
            if (args[1] == "conflict") {
                qInfo("PASS: failed startup recovery preserves externally edited DNS");
                return 0;
            }
            const auto endpoints = record["published"].toObject()["dns"].toArray();
            for (const auto &endpoint : endpoints) {
                QUdpSocket socket;
                const auto query = QByteArray::fromHex("0123010000010000000000000570726f6265076578616d706c6500001c0001");
                if (socket.writeDatagram(query, QHostAddress(endpoint.toString()), 53) != query.size()
                        || !socket.waitForReadyRead(1000)) return 16;
                QByteArray answer(4096, 0);
                const auto size = socket.readDatagram(answer.data(), answer.size());
                if (size < 12 || (uchar(answer[3]) & 15)
                        || qFromBigEndian<quint16>(answer.constData() + 6)) return 17;
            }
            qInfo("PASS: pending systemd stop preserves external DNS and live guarded AAAA NODATA");
            return 0;
        }
        for (const auto &key : {"dns", "domains", "default_route"})
            if (current[key] != before[key]) return 4;
        for (const auto &iface : QNetworkInterface::allInterfaces())
            for (const auto &address : iface.addressEntries())
                if (record["published"].toObject()["dns"].toArray().contains(address.ip().toString()))
                    return 5;
        qInfo("PASS: real systemd DNS snapshot restored and aliases retired");
        return 0;
    }
    const int index = QNetworkInterface::interfaceFromName("dns-systemd").index();
    if (index <= 0) return 6;
    const auto before = backend.read(index);
    if (before.isEmpty()) return 7;
    QRemoteObjectNode node;
    QLocalSocket socket;
    socket.connectToServer("/tmp/local:AmneziaVpnIpcInterface");
    if (!socket.waitForConnected(5000)) return 8;
    node.addClientSideConnection(&socket);
    auto iface = node.acquire<IpcInterfaceReplica>();
    if (!iface->waitForSource(5000)) return 9;
    if (args[1] == "ready") return 0;
    auto result = iface->updateResolversWithPolicy("dns-systemd", {QHostAddress("2001:db8::53")},
                                                  false, "systemd-dns-fixture");
    if (!result.waitForFinished(5000) || !result.returnValue()) return 10;
    const auto published = backend.read(index);
    if (published["dns"].toArray().isEmpty()) return 11;
    QFile file(args[2]);
    if (!file.open(QIODevice::WriteOnly)) return 12;
    file.write(QJsonDocument(QJsonObject{{"index", index}, {"before", before}, {"published", published}}).toJson());
    qInfo("PASS: actual systemd-owned service published guarded DNS");
    return 0;
}
