#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QTimer>
#include "core/utils/vpnEndpointSession.h"
#include "mozilla/localsocketcontroller.h"

// Exercise the production session policy and actual service IPC. Only timing
// is shortened for a disposable fixture; profile keys are never regenerated.
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    if (argc != 3) return 2;
    QFile file(QString::fromLocal8Bit(argv[1]));
    if (!file.open(QIODevice::ReadOnly)) return 2;
    const auto profile = QJsonDocument::fromJson(file.readAll()).object();
    if (!profile.contains("sing_box_routing")) return 2;
    LocalSocketController controller;
    amnezia::VpnEndpointSession session;
    QElapsedTimer clock; clock.start();
    const auto report = [](const QJsonObject &row) {
        QTextStream(stdout) << QJsonDocument(row).toJson(QJsonDocument::Compact) << Qt::endl;
    };
    session.timing.staleMs = 1500;
    session.timing.handshakeMs = 8000;
    session.timing.retryMs = 100;
    session.resolver = [&](const QString &host, auto complete) { controller.resolveEndpoint(host, std::move(complete)); };
    session.cancelResolver = [&] { controller.cancelEndpointLookup(); };
    session.activate = [&](const QString &address) {
        report({{"event", "activate"}, {"address", address}});
        controller.activate(amnezia::vpnEndpoint::activationConfig(profile, address));
    };
    session.deactivate = [&] { controller.deactivateWithAck(); };
    session.failed = [&](auto failure) { report({{"event", "failed"}, {"reason", int(failure)}}); app.exit(1); };
    session.changed = [&](auto phase) {
        using Phase = amnezia::VpnEndpointSession::Phase;
        report({{"event", "phase"}, {"phase", int(phase)}, {"address", session.address()}});
        if (phase == Phase::Connected) report({{"event", "connected"}, {"address", session.address()}});
        if (phase == Phase::Idle) app.quit();
    };
    QObject::connect(&controller, &ControllerImpl::deactivated, &app, [&] { session.deactivated(); });
    QObject::connect(&controller, &ControllerImpl::connected, &app, [&] { session.connected(); });
    QObject::connect(&controller, &ControllerImpl::disconnected, &app, [&] { session.recover(); });
    QObject::connect(&controller, &ControllerImpl::handshakeUpdated, &app,
        [&](qint64 handshake, quint64 tx, quint64 rx) { session.observePeer(handshake, tx, rx, clock.elapsed()); });
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, &app, [&] {
        if (QFile::exists(QString::fromLocal8Bit(argv[2]))) session.stop();
        else controller.checkStatus();
    });
    poll.start(200);
    controller.initialize(nullptr, nullptr);
    session.start("endpoint.test", true);
    QTimer::singleShot(90000, &app, [&] { session.stop(); app.exit(3); });
    return app.exec();
}
