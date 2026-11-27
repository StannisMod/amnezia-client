#include <QCoreApplication>
#include <QFile>
#include <QLocalSocket>
#include <QRemoteObjectDynamicReplica>
#include <QRemoteObjectNode>
#include <QRemoteObjectPendingCall>
#include <QTimer>
#include "rep_ipc_process_interface_replica.h"
#include "../../client/core/utils/openVpnIpv6.h"
#include <QTextStream>

// Separate OS process: the driver kills this replica, not the native owner.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() == 2 && args[1] == "--blocking-directives") {
        QTextStream(stdout) << amnezia::openVpnIpv6::blockingDirectives(
            {}, amnezia::RouteMode::VpnAllSites, {}, {"2001:db8::53"});
        return 0;
    }
    if (args.size() != 4) return 2;
    QTimer::singleShot(45000, &app, [] { qFatal("QtRO acceptance deadline"); });
    QRemoteObjectNode node;
    QLocalSocket socket;
    socket.connectToServer("/tmp/local:AmneziaVpnIpcInterface");
    if (!socket.waitForConnected(5000)) return 3;
    node.addClientSideConnection(&socket);
    auto main = node.acquireDynamic("IpcInterface");
    if (!main->waitForSource(5000)) return 4;
    int descriptor = args[3].toInt();
    if (args[1] == "start") {
        QRemoteObjectPendingCall call;
        if (!QMetaObject::invokeMethod(main, "createPrivilegedProcess",
                                      Q_RETURN_ARG(QRemoteObjectPendingCall, call))) return 5;
        call.waitForFinished(5000);
        if (call.error() != QRemoteObjectPendingCall::NoError) return 6;
        descriptor = call.returnValue().toInt();
        if (descriptor <= 0) return 7;
    }
    QLocalSocket processSocket;
    QRemoteObjectNode processNode;
    processSocket.connectToServer(QString("/tmp/local:AmneziaVpnIpcInterface_%1").arg(descriptor));
    if (!processSocket.waitForConnected(5000)) return 8;
    processNode.addClientSideConnection(&processSocket);
    auto process = processNode.acquire<IpcProcessInterfaceReplica>();
    if (!process->waitForSource(5000)) return 9;
    QObject::connect(process, &IpcProcessInterfaceReplica::managedOpenVpnLine, &app,
        [](const QString &line) { qInfo().noquote() << "NATIVE" << line; });
    QObject::connect(process, &IpcProcessInterfaceReplica::managedOpenVpnFailed, &app,
        [] { qFatal("service DNS hand-off failed"); });
    QObject::connect(process, &IpcProcessInterfaceReplica::finished, &app,
                     [&app](int code, QProcess::ExitStatus status) {
        qInfo() << "CONFIRMED_FINISHED" << code << status;
        app.exit(code == 0 && status == QProcess::NormalExit ? 0 : 12);
    });
    if (args[1] == "start") {
        process->setProgram(1);
        process->setArguments({"--config", args[2]});
        auto configured = process->configureManagedOpenVpn();
        configured.waitForFinished(5000);
        if (!configured.returnValue()) return 10;
        QFile descriptorFile(args[3]);
        if (!descriptorFile.open(QIODevice::WriteOnly)) return 11;
        descriptorFile.write(QByteArray::number(descriptor));
        descriptorFile.close();
        process->start();
    } else {
        process->terminate();
    }
    return app.exec();
}
