#include <QPointer>
#include <QSignalSpy>
#include <QTest>
#include "vpnConnection.h"

// Deferred stop models the service's real teardown acknowledgement. No VPN
// credentials, platform daemon or network access is needed for ownership tests.
class DeferredProtocol final : public VpnProtocol {
public:
    DeferredProtocol(bool *destroyed, bool synchronous = false)
        : VpnProtocol(QJsonObject{}), destroyed(destroyed), synchronous(synchronous) { setConnectionState(Vpn::Connected); }
    ~DeferredProtocol() override { *destroyed = true; }
    ErrorCode start() override { return ErrorCode::NoError; }
    void stop() override {
        setConnectionState(Vpn::Disconnecting);
        if (synchronous) acknowledge();
    }
    void acknowledge() { setConnectionState(Vpn::Disconnected); }
    void failCleanup() {
        setLastError(ErrorCode::VpnEndpointCleanupFailed);
        emit protocolError(ErrorCode::VpnEndpointCleanupFailed);
    }
private:
    bool *destroyed;
    bool synchronous;
};

class TestableConnection final : public VpnConnection {
public:
    TestableConnection() : VpnConnection(nullptr, nullptr) {}
    void install(const QSharedPointer<VpnProtocol> &protocol) {
        m_vpnProtocol = protocol;
        connect(protocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    }
};

class TestProtocolDisconnect : public QObject {
    Q_OBJECT
private slots:
    void retainedUntilAcknowledgementOrFailure_data() {
        QTest::addColumn<bool>("error");
        QTest::newRow("acknowledgement") << false;
        QTest::newRow("cleanup failure") << true;
    }
    void retainedUntilAcknowledgementOrFailure() {
        QFETCH(bool, error);
        bool destroyed = false;
        TestableConnection connection;
        QPointer<DeferredProtocol> protocol = new DeferredProtocol(&destroyed);
        connection.install(QSharedPointer<VpnProtocol>(protocol.data()));
        connection.disconnectFromVpn();
        QVERIFY(!destroyed);
        QVERIFY(connection.vpnProtocol());
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        QCoreApplication::processEvents();
        QVERIFY(!destroyed); // Merely returning to the event loop is not an ack.
        if (error) protocol->failCleanup();
        else protocol->acknowledge();
        QVERIFY(!destroyed); // Never delete a sender in its notification stack.
        QCOMPARE(connection.connectionState(), error ? Vpn::Error : Vpn::Disconnected);
        QTRY_VERIFY(destroyed);
        QVERIFY(connection.vpnProtocol().isNull());
    }
    void synchronousStopAlsoReleasesOutsideItsOwnStack() {
        bool destroyed = false;
        TestableConnection connection;
        connection.install(QSharedPointer<VpnProtocol>(new DeferredProtocol(&destroyed, true)));
        connection.disconnectFromVpn();
        QVERIFY(!destroyed);
        QCOMPARE(connection.connectionState(), Vpn::Disconnected);
        QTRY_VERIFY(destroyed);
        QVERIFY(connection.vpnProtocol().isNull());
    }
    void staleCompletionCannotClearAnotherProtocol() {
        bool oldDestroyed = false, newDestroyed = false;
        TestableConnection connection;
        auto old = QSharedPointer<DeferredProtocol>::create(&oldDestroyed);
        connection.install(old);
        connection.disconnectFromVpn();
        old->acknowledge(); // Completion is queued.
        auto replacement = QSharedPointer<DeferredProtocol>::create(&newDestroyed);
        connection.install(replacement);
        QCoreApplication::processEvents();
        QCOMPARE(connection.vpnProtocol().data(), replacement.data());
        QVERIFY(!newDestroyed);
    }
};
QTEST_MAIN(TestProtocolDisconnect)
#include "testProtocolDisconnect.moc"
