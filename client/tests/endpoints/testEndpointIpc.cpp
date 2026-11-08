#include <QTest>
#include <QLocalServer>
#include <QLocalSocket>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "mozilla/localsocketcontroller.h"

class TestEndpointIpc : public QObject
{
    Q_OBJECT
private slots:
    void runtimeBindingRejectsOldRepliesAndGuardsCleanup() {
        QTemporaryDir directory;
        QLocalServer server;
        const auto path=directory.filePath("runtime.sock");
        QVERIFY(server.listen(path));
        LocalSocketController controller(path);
        QSignalSpy initialized(&controller,&ControllerImpl::initialized);
        QSignalSpy runtime(&controller,&ControllerImpl::routingRuntimeStatus);
        QSignalSpy ack(&controller,&ControllerImpl::deactivated);
        controller.initialize(nullptr,nullptr);
        QTRY_VERIFY(server.hasPendingConnections());
        QScopedPointer<QLocalSocket> service(server.nextPendingConnection());
        QTRY_VERIFY(service->canReadLine());
        const auto initial=QJsonDocument::fromJson(service->readLine()).object();
        auto send=[&](const QJsonObject &row){service->write(QJsonDocument(row).toJson(QJsonDocument::Compact)+"\n");service->flush();};
        send({{"type","status"},{"status_id",initial.value("status_id")},{"connected",false}});
        QTRY_COMPARE(initialized.count(),1);
        controller.activate({{"protocol","awg"},{"sing_box_routing",QJsonObject{}}});
        QTRY_VERIFY(service->canReadLine());
        QCOMPARE(QJsonDocument::fromJson(service->readLine()).object().value("type").toString(),"activate");
        auto status=[&](const QJsonValue &serial,const QString &id){return QJsonObject{
            {"type","status"},{"ownership_protocol",1},{"status_id",serial},{"runtime_id",id},{"runtime_alive",true},{"preserves_connections",true},
            {"connected",true},{"date",QDateTime::currentDateTime().toString()},
            {"serverIpv4Gateway","172.19.0.2"},{"deviceIpv4Address","172.19.0.1"},{"txBytes",1},{"rxBytes",1}};};
        send(status(initial.value("status_id"),"retired-owner"));
        controller.checkStatus();
        QTRY_VERIFY(service->canReadLine());
        auto request=QJsonDocument::fromJson(service->readLine()).object();
        send(status(request.value("status_id"),"owner-a"));
        QTRY_COMPARE(controller.routingRuntimeId(),QString("owner-a"));
        QCOMPARE(runtime.count(),1);
        controller.hintRoutingNetwork("foreign-owner");
        QTRY_VERIFY(service->canReadLine());
        request=QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(request.value("type").toString(),"status");
        controller.hintRoutingNetwork("owner-a");
        QTRY_VERIFY(service->canReadLine());
        const auto hint=QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(hint.value("type").toString(),"routing_network_changed");
        QCOMPARE(hint.value("runtime_id").toString(),"owner-a");
        QTRY_VERIFY(service->canReadLine());
        request=QJsonDocument::fromJson(service->readLine()).object();
        send(status(request.value("status_id"),"replacement-owner"));
        QTRY_COMPARE(runtime.count(),2);
        QCOMPARE(controller.routingRuntimeId(),QString("owner-a"));
        controller.deactivateWithAck();
        QTRY_VERIFY(service->canReadLine());
        const auto cleanup=QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(cleanup.value("runtime_id").toString(),"owner-a");
        send({{"type","deactivated"},{"runtime_id","replacement-owner"},{"cleanup_id",cleanup.value("cleanup_id")}});
        send({{"type","deactivated"},{"runtime_id","owner-a"},{"cleanup_id",cleanup.value("cleanup_id")}});
        QTRY_COMPARE(ack.count(),1);
        QVERIFY(controller.routingRuntimeId().isEmpty());
        controller.deactivateWithAck();
        QTRY_VERIFY(service->canReadLine());
        const auto next=QJsonDocument::fromJson(service->readLine()).object();
        QVERIFY(next.value("cleanup_id")!=cleanup.value("cleanup_id"));
        send({{"type","deactivated"},{"cleanup_id",cleanup.value("cleanup_id")}});
        send({{"type","deactivated"},{"cleanup_id",next.value("cleanup_id")}});
        QTRY_COMPARE(ack.count(),2);
    }
    void ipcReconnectRetainsTheSameRuntime() {
        QTemporaryDir directory;QLocalServer server;
        const auto path=directory.filePath("reconnect.sock");QVERIFY(server.listen(path));
        LocalSocketController controller(path);
        QSignalSpy initialized(&controller,&ControllerImpl::initialized);
        controller.initialize(nullptr,nullptr);
        QTRY_VERIFY(server.hasPendingConnections());
        QScopedPointer<QLocalSocket> service(server.nextPendingConnection());
        QTRY_VERIFY(service->canReadLine());service->readLine();
        service->write("{\"type\":\"status\",\"connected\":false}\n");service->flush();
        QTRY_COMPARE(initialized.count(),1);
        controller.activate({{"protocol","awg"},{"sing_box_routing",QJsonObject{}}});
        QTRY_VERIFY(service->canReadLine());service->readLine();
        controller.checkStatus();
        QTRY_VERIFY(service->canReadLine());
        auto request=QJsonDocument::fromJson(service->readLine()).object();
        auto response=[&]{return QJsonObject{{"type","status"},{"status_id",request.value("status_id")},
            {"ownership_protocol",1},{"runtime_id","surviving-owner"},{"runtime_alive",true},{"preserves_connections",true},
            {"connected",true},{"date",QDateTime::currentDateTime().toString()},
            {"serverIpv4Gateway","172.19.0.2"},{"deviceIpv4Address","172.19.0.1"},{"rxBytes",1},{"txBytes",1}};};
        service->write(QJsonDocument(response()).toJson(QJsonDocument::Compact)+"\n");service->flush();
        QTRY_COMPARE(controller.routingRuntimeId(),QString("surviving-owner"));
        service->disconnectFromServer();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(),7000);
        service.reset(server.nextPendingConnection());
        QTRY_VERIFY(service->canReadLine());
        request=QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(request.value("type").toString(),"status");
        service->write(QJsonDocument(response()).toJson(QJsonDocument::Compact)+"\n");service->flush();
        QTRY_COMPARE(initialized.count(),2);
        QCOMPARE(controller.routingRuntimeId(),QString("surviving-owner"));
        QVERIFY(!service->canReadLine()); // No activate/deactivate during IPC repair.
    }
    void endpointReplyMustMatchTheCurrentLookup() {
        QTemporaryDir directory;
        QLocalServer server;
        const auto path = directory.filePath("dns-test.sock");
        QVERIFY(server.listen(path));
        LocalSocketController controller(path);
        QSignalSpy initialized(&controller, &ControllerImpl::initialized);
        controller.initialize(nullptr, nullptr);
        QTRY_VERIFY(server.hasPendingConnections());
        QScopedPointer<QLocalSocket> service(server.nextPendingConnection());
        QTRY_VERIFY(service->canReadLine()); service->readLine();
        service->write("{\"type\":\"status\",\"connected\":false}\n"); service->flush();
        QTRY_COMPARE(initialized.count(), 1);
        int obsolete = 0, current = 0;
        controller.resolveEndpoint("vpn.example.org", [&](auto) { ++obsolete; });
        QTRY_VERIFY(service->canReadLine()); service->readLine(); // cancellation
        QTRY_VERIFY(service->canReadLine());
        const auto first = QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(first.value("type").toString(), "resolve_endpoint");
        controller.cancelEndpointLookup();
        controller.resolveEndpoint("vpn.example.org", [&](const QList<QHostAddress> &addresses) {
            QCOMPARE(addresses, QList<QHostAddress>{QHostAddress("192.0.2.2")}); ++current;
        });
        QTRY_VERIFY(service->canReadLine()); service->readLine();
        QTRY_VERIFY(service->canReadLine()); service->readLine();
        QTRY_VERIFY(service->canReadLine());
        const auto second = QJsonDocument::fromJson(service->readLine()).object();
        QVERIFY(first.value("lookup_id") != second.value("lookup_id"));
        QVERIFY(first.value("alternate") != second.value("alternate"));
        for (const auto &request : {first, second}) {
            const QJsonObject response{{"type", "endpoint_resolved"}, {"lookup_id", request.value("lookup_id")},
                                      {"addresses", QJsonArray{request == first ? "192.0.2.1" : "192.0.2.2"}}};
            service->write(QJsonDocument(response).toJson(QJsonDocument::Compact) + "\n");
        }
        service->flush();
        QTRY_COMPARE(current, 1);
        QCOMPARE(obsolete, 0);
    }
    void cleanupWaitsForExplicitServiceAck()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QLocalServer server;
        const QString path = directory.filePath("endpoint-test.sock");
        QVERIFY(server.listen(path));
        LocalSocketController controller(path);
        QSignalSpy ack(&controller, &ControllerImpl::deactivated);
        QSignalSpy disconnected(&controller, &ControllerImpl::disconnected);
        QSignalSpy handshake(&controller, &ControllerImpl::handshakeUpdated);
        controller.initialize(nullptr, nullptr);
        // Before the service is initialized the request must be queued, rather
        // than silently dropped or reported as a completed local disconnect.
        controller.deactivateWithAck();
        QTRY_VERIFY(server.hasPendingConnections());
        QScopedPointer<QLocalSocket> service(server.nextPendingConnection());
        QTRY_VERIFY(service->canReadLine());
        const auto initial = QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(initial.value("type").toString(), "status");
        QCOMPARE(ack.count(), 0);

        // A previous tunnel exists but never handshook: the empty date must not
        // prevent cleanup of that tunnel before the next DNS resolution.
        service->write("{\"type\":\"status\",\"connected\":true,\"date\":\"\"}\n");
        service->flush();
        QTRY_VERIFY(service->canReadLine());
        const auto request = QJsonDocument::fromJson(service->readLine()).object();
        QCOMPARE(request.value("type").toString(), "deactivate");
        QVERIFY(request.value("request_ack").toBool());
        QCOMPARE(ack.count(), 0);

        service->write("{\"type\":\"disconnected\"}\n");
        service->flush();
        QTRY_COMPARE(disconnected.count(), 1);
        QCOMPARE(ack.count(), 0); // Disconnected alone is never a cleanup ack.
        service->write("{\"type\":\"deactivated\"}\n");
        service->flush();
        QTRY_COMPARE(ack.count(), 1);

        service->write("{\"type\":\"status\",\"serverIpv4Gateway\":\"192.0.2.1\",\"deviceIpv4Address\":\"10.8.0.2\",\"txBytes\":10,\"rxBytes\":20,\"lastHandshakeMs\":1700000000123}\n");
        service->flush();
        QTRY_COMPARE(handshake.count(), 1);
        QCOMPARE(handshake.first().at(0).toLongLong(), 1700000000123LL);
        QCOMPARE(handshake.first().at(1).toULongLong(), 10ULL);
        QCOMPARE(handshake.first().at(2).toULongLong(), 20ULL);
    }
};
QTEST_GUILESS_MAIN(TestEndpointIpc)
#include "testEndpointIpc.moc"
