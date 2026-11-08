#include <QTest>
#include <QSignalSpy>
#include "core/protocols/wireGuardProtocol.h"

class RecordingController final : public ControllerImpl {
public:
    int activations = 0, deactivations = 0, hints = 0;
    QString id = "owner-a";
    void initialize(const Device *, const Keys *) override {}
    void activate(const QJsonObject &) override {
        ++activations;
        if (activations>1) id=QString("owner-%1").arg(activations);
        emit connected("peer");
    }
    void deactivate() override { ++deactivations; emit disconnected(); }
    void deactivateWithAck() override { ++deactivations; emit deactivated(); }
    void checkStatus() override { emit routingRuntimeStatus(id, true, true); }
    QString routingRuntimeId() const override { return id; }
    bool routingRecoverySupported() const override { return true; }
    void hintRoutingNetwork(const QString &expected) override { QCOMPARE(expected,id); ++hints; }
    void getBackendLogs(std::function<void(const QString &)> &&) override {}
    void cleanupBackendLogs() override {}
};
class TestPreservingProtocol : public QObject {
    Q_OBJECT
    static QJsonObject profile() {
        return {{"protocol","awg"},{"sing_box_routing",QJsonObject{{"version",1},{"default","vpn"}}},
                {"awg_config_data",QJsonObject{{"hostName","192.0.2.1"}}}};
    }
private slots:
    void establishedEventsKeepTheConfirmedOwner() {
        auto *control = new RecordingController;
        WireguardProtocol protocol(profile(),nullptr,control);
        QObject::connect(&protocol,&VpnProtocol::connectionStateChanged,&protocol,[&](auto state){
            if(state==Vpn::Connected) protocol.reconnect();
        });
        QCOMPARE(protocol.start(),amnezia::ErrorCode::NoError);
        QVERIFY(protocol.preservesConnectionState());
        QCOMPARE(control->activations,1);
        const auto cleanups = control->deactivations;
        for (int n=0;n<100;++n) protocol.reconnect();
        emit control->disconnected(); // Lost GUI IPC, not a dead child.
        emit control->handshakeUpdated(1,100000,0);
        QCOMPARE(control->activations,1);
        QCOMPARE(control->deactivations,cleanups);
        QCOMPARE(control->hints,101);
        QVERIFY(protocol.preservesConnectionState());
        protocol.stop();
        protocol.stop();
        QCOMPARE(control->deactivations,cleanups+1);
        QVERIFY(!protocol.preservesConnectionState());
        emit control->connected("late");
        QVERIFY(!protocol.preservesConnectionState());
    }
    void replacementOwnerCannotBeReconnectedOver() {
        auto *control = new RecordingController;
        WireguardProtocol protocol(profile(),nullptr,control);
        QSignalSpy errors(&protocol,&VpnProtocol::protocolError);
        protocol.start();
        const auto cleanups=control->deactivations;
        emit control->routingRuntimeStatus("different-owner",true,true);
        QCOMPARE(errors.count(),1);
        QCOMPARE(control->deactivations,cleanups);
        QCOMPARE(control->activations,1);
        QVERIFY(protocol.runtimeWasReplaced());
        protocol.stop();
        QCOMPARE(control->deactivations,cleanups);
    }
    void matchingDeadChildPermitsBoundedFullRecovery() {
        auto *control = new RecordingController;
        WireguardProtocol protocol(profile(),nullptr,control);
        protocol.start();
        const auto cleanups=control->deactivations;
        emit control->routingRuntimeStatus(control->id,false,true);
        QCOMPARE(control->deactivations,cleanups+1);
        QCOMPARE(control->activations,2);
        QVERIFY(protocol.preservesConnectionState());
    }
};
QTEST_GUILESS_MAIN(TestPreservingProtocol)
#include "testPreservingProtocol.moc"
