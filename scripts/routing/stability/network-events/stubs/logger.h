#pragma once
#include <QDebug>
// Only the log sink is substituted; the watcher and its D-Bus subscription are
// compiled from production unchanged. No Wi-Fi is present in this fixture.
class Logger {
public:
 explicit Logger(const QString &) {}
 QDebug debug(){return qDebug();}
 QDebug warning(){return qWarning();}
 QDebug error(){return qCritical();}
 QString sensitive(const QString &){return QStringLiteral("[redacted]");}
};
