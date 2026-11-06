#include <QCoreApplication>
#include <QJsonDocument>
#include <QTextStream>
#include "../../core/utils/splitDnsConfig.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const auto rule = [](const QString &kind, const QString &name, const QString &action) {
        return QJsonObject{{"kind", kind}, {"value", name}, {"action", action}};
    };
    QJsonObject routing{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray{
        rule("domain", "public.corp.example", "vpn"), rule("suffix", "direct.test", "direct"),
        rule("suffix", "corp.example", "direct")}}};
    const auto session = [](const QJsonObject &route) {
        return QJsonObject{{"routing", route}, {"dns", amnezia::dns::forSiteRoutes(route, "10.77.0.2")}};
    };
    const auto initial = session(routing);
    auto rules = routing.value("rules").toArray();
    rules.prepend(rule("domain", "cached.corp.example", "vpn"));
    routing.insert("rules", rules);
    QTextStream(stdout) << QJsonDocument(QJsonObject{{"initial", initial}, {"reconnected", session(routing)}}).toJson();
    return 0;
}
