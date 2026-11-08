#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QTimer>
#include "core/protocols/wireGuardProtocol.h"
#include "mozilla/localsocketcontroller.h"

// A disposable test driver of the production protocol and controller, with the
// real installed service. It contains no replacement recovery state machine.
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if (argc!=3) return 2;
    QFile input(QString::fromLocal8Bit(argv[1]));
    if (!input.open(QIODevice::ReadOnly)) return 2;
    const auto profile=QJsonDocument::fromJson(input.readAll()).object();
    if (!profile.contains("sing_box_routing")) return 2;
    const QString controlPath=QString::fromLocal8Bit(argv[2]);
    auto *controller=new LocalSocketController;
    WireguardProtocol protocol(profile,nullptr,controller);
    bool stopping=false;
    const auto report=[](const QJsonObject &row){QTextStream(stdout)<<QJsonDocument(row).toJson(QJsonDocument::Compact)<<Qt::endl;};
    QObject::connect(&protocol,&VpnProtocol::connectionStateChanged,&app,[&](Vpn::ConnectionState state){
        report({{"event","state"},{"state",int(state)}});
        if (stopping&&state==Vpn::Disconnected) app.quit();
    });
    QObject::connect(&protocol,&VpnProtocol::protocolError,&app,[&](auto error){report({{"event","failed"},{"reason",int(error)}});app.exit(1);});
    QTimer timer;
    QObject::connect(&timer,&QTimer::timeout,&app,[&]{
        QFile command(controlPath);
        if (command.open(QIODevice::ReadOnly)) {
            const auto action=command.readAll().trimmed();command.close();QFile::remove(controlPath);
            if (action=="stop") {stopping=true;protocol.stop();}
            else if (action=="network") {for(int n=0;n<20;++n) protocol.reconnect();}
            else if (action=="drop_ipc") {
                if (auto *socket=controller->findChild<QLocalSocket *>()) socket->abort();
                report({{"event","ipc_dropped"}});
            }
        }
        report({{"event","status"},{"state",int(protocol.connectionState())},{"preserved",protocol.preservesConnectionState()}});
    });
    timer.start(250);
    const auto error=protocol.start();
    if (error!=amnezia::ErrorCode::NoError) return 3;
    QTimer::singleShot(180000,&app,[&]{report({{"event","failed"},{"reason","deadline"}});protocol.stop();app.exit(4);});
    return app.exec();
}
