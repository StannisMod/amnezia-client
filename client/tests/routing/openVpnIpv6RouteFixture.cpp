#include <QCoreApplication>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#ifdef Q_OS_WIN
#include "platforms/windows/daemon/windowsopenvpnipv6api.h"
#include "platforms/windows/daemon/windowsopenvpnipv6routes.h"
#else
#include "platforms/linux/daemon/linuxopenvpnipv6routes.h"
#endif
#ifdef AMNEZIA_ROUTE_FIXTURE_IPC
#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"
#include "ipc.h"
#endif

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
#ifdef Q_OS_WIN
    // The Windows driver is used only by the disposable-VM orchestrator and
    // must exercise the installed service, never a substitute route owner.
    if (qEnvironmentVariable("AMNEZIA_IPV6_LAB") != "owned-windows-vm"
        || !app.arguments().contains("--ipc-process")) return 64;
    WindowsOpenVpnIpv6Routes routes(amnezia::windowsOpenVpnIpv6::nativeApi());
#else
    if (qEnvironmentVariable("AMNEZIA_IPV6_LAB") != "isolated-namespace") return 64;
    LinuxOpenVpnIpv6Routes routes;
#endif
#ifndef AMNEZIA_ROUTE_FIXTURE_IPC
    if (app.arguments().contains("--ipc-process")) return 68;
#else
    QRemoteObjectNode node, processNode;
    QScopedPointer<IpcInterfaceReplica> service;
    QScopedPointer<IpcProcessInterfaceReplica> process;
    if (app.arguments().contains("--ipc-process")) {
        node.connectToNode(QUrl("local:" + amnezia::getIpcServiceUrl()));
        service.reset(node.acquire<IpcInterfaceReplica>());
        if (!service->waitForSource(8000)) return 65;
#ifdef Q_OS_WIN
        // Match OpenVpnProtocol's normal startup: the MSI stages the TAP
        // driver, while the privileged service installs/creates its adapter.
        auto adapters = service->getTapList();
        if (!adapters.waitForFinished(8000)) return 69;
        if (adapters.returnValue().isEmpty()) {
            auto installed = service->checkAndInstallDriver();
            if (!installed.waitForFinished(60000) || !installed.returnValue()) return 69;
        }
#endif
        auto create = service->createPrivilegedProcess();
        if (!create.waitForFinished(8000) || create.returnValue() <= 0) return 66;
        processNode.connectToNode(QUrl("local:" + amnezia::getIpcProcessUrl(create.returnValue())));
        process.reset(processNode.acquire<IpcProcessInterfaceReplica>());
        if (!process->waitForSource(8000)) return 67;
    }
#endif
    QTextStream input(stdin), output(stdout);
    output << "READY\n" << Qt::flush;
    while (!input.atEnd()) {
        const auto document = QJsonDocument::fromJson(input.readLine().toUtf8()).object();
#ifdef AMNEZIA_ROUTE_FIXTURE_IPC
        if (process && document.value("operation") == "start") {
            process->setProgram(amnezia::PermittedProcess::OpenVPN);
            process->setArguments({"--config", document.value("config").toString()});
            process->start();
            auto started = process->waitForStarted(5000);
            output << (started.waitForFinished(8000) && started.returnValue() ? "OK\n" : "FAIL\n") << Qt::flush;
            continue;
        }
        const auto operation = document.value("operation").toString();
        if (process && (operation == "stop" || operation == "kill" || operation == "close")) {
            if (operation == "kill") process->kill();
            else if (operation == "close") process->close();
            else process->terminate();
            auto stopped = process->waitForFinished(5000);
            output << (stopped.waitForFinished(7000) ? "OK\n" : "FAIL\n") << Qt::flush;
            continue;
        }
#endif
        QStringList hosts;
        for (const auto &host : document.value("hosts").toArray()) hosts << host.toString();
        bool success;
#ifdef AMNEZIA_ROUTE_FIXTURE_IPC
        if (process) {
            auto reply = process->addOpenVpnIpv6Hosts(document.value("local_ipv4").toString(), hosts,
                                                     document.value("through_vpn").toBool());
            success = reply.waitForFinished(10000) && reply.returnValue();
        } else
#endif
        success = routes.add(document.value("local_ipv4").toString(), hosts,
                                    document.value("through_vpn").toBool());
        output << (success ? "OK\n" : "FAIL\n") << Qt::flush;
    }
}
