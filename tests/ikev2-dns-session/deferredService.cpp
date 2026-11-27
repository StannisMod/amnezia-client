#include "qtservice.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTimer>

#ifndef AMNEZIA_DEFERRED_SERVICE_NAME
#define AMNEZIA_DEFERRED_SERVICE_NAME "AmneziaDnsStopBarrierFixture"
#endif

// Test-only external join boundary. This exercises the real QtService/SCM
// framework; it is not a substitute for native RAS or DNS backend acceptance.
class DeferredService final : public QtService<QCoreApplication>
{
public:
    DeferredService(int argc, char **argv)
        : QtService<QCoreApplication>(argc, argv, AMNEZIA_DEFERRED_SERVICE_NAME)
    {
        setServiceFlags(NeedsStopOnShutdown | DeferredStop);
    }
    void start() override
    {
        write("started");
        auto *timer = new QTimer(qApp);
        QObject::connect(timer, &QTimer::timeout, qApp, [this] {
            if (m_stopping && QFile::exists(QCoreApplication::applicationDirPath() + "/fixture-release")) {
                write("joined");
                qApp->quit();
            }
        });
        timer->start(100);
    }
    void stop() override
    {
        m_stopping = true;
        write("stop-pending");
    }
private:
    void write(const QString &phase)
    {
        QSaveFile file(QCoreApplication::applicationDirPath() + "/fixture-state.json");
        const auto bytes = QJsonDocument(QJsonObject{
            {"phase", phase}, {"pid", QCoreApplication::applicationPid()}}).toJson();
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
            qFatal("Failed to persist fixture state");
    }
    bool m_stopping = false;
};

int main(int argc, char **argv)
{
    DeferredService service(argc, argv);
    return service.exec();
}
