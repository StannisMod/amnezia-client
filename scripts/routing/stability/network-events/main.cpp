#include <QCoreApplication>
#include <QDateTime>
#include <QDBusConnection>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSocketNotifier>
#include <QThread>
#include <cstdio>
#include <unistd.h>
#include "linuxnetworkwatcherworker.h"

static void record(QString event, int state = -1) {
 QJsonObject row{{"at", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)}, {"event",event}};
 if(state>=0) row["state"]=state;
 auto bytes=QJsonDocument(row).toJson(QJsonDocument::Compact);
 fwrite(bytes.constData(),1,bytes.size(),stdout);fputc('\n',stdout);fflush(stdout);
}
class RawEvents final: public QObject {
 Q_OBJECT
 public slots:
 void stateChanged(uint state) {record("dbus-StateChanged",static_cast<int>(state));}
};
int main(int argc,char **argv){
 QCoreApplication app(argc,argv);
 RawEvents raw;
 QDBusConnection::systemBus().connect("org.freedesktop.NetworkManager","/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager","StateChanged",&raw,SLOT(stateChanged(uint)));
 LinuxNetworkWatcherWorker worker(QThread::currentThread());
 QObject::connect(&worker,&LinuxNetworkWatcherWorker::networkChanged,[]{record("production-networkChanged");});
 QObject::connect(&worker,&LinuxNetworkWatcherWorker::wakeup,[]{record("production-wakeup");});
 worker.initialize();
 QSocketNotifier input(STDIN_FILENO,QSocketNotifier::Read);
 QObject::connect(&input,&QSocketNotifier::activated,[&]{
  char buffer[128];auto count=read(STDIN_FILENO,buffer,sizeof(buffer));if(count<=0){app.quit();return;}
  for(auto line:QByteArray(buffer,static_cast<int>(count)).split('\n')){
   if(line=="duplicate"){
    record("inject-unchanged-state-70-twice");
    for(int i=0;i<2;++i)QMetaObject::invokeMethod(&worker,"NMStateChanged",Qt::DirectConnection,Q_ARG(quint32,70));
   }
  }
 });
 record("ready");return app.exec();
}
#include "main.moc"
