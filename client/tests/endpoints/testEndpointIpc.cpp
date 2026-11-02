#include <QTest>
#include <QLocalServer>
#include <QLocalSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "mozilla/localsocketcontroller.h"

class TestEndpointIpc : public QObject
{
    Q_OBJECT
private slots:
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
