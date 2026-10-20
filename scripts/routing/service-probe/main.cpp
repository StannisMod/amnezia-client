#include <QCoreApplication>
#include <QRemoteObjectNode>
#include "rep_ipc_interface_replica.h"

// Disposable CI client of the real installed service's existing QtRO API.
// It sends no user profile or credentials and adds no production IPC methods.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2 || (QString(argv[1]) != "on" && QString(argv[1]) != "off")) return 2;
    QRemoteObjectNode node;
#ifdef Q_OS_WIN
    node.connectToNode(QUrl("local:local:AmneziaVpnIpcInterface"));
#else
    node.connectToNode(QUrl("local:/tmp/local:AmneziaVpnIpcInterface"));
#endif
    QScopedPointer<IpcInterfaceReplica> replica(node.acquire<IpcInterfaceReplica>());
    if (!replica->waitForSource(8000)) return 3;
    auto call = replica->refreshKillSwitch(QString(argv[1]) == "on");
    if (!call.waitForFinished(12000) || !call.returnValue()) return 4;
    return 0;
}
