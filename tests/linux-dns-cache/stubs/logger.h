#pragma once
#include <QDebug>
class Logger {
public:
    explicit Logger(const QString &) {}
    QDebug debug() { return qDebug(); }
    QDebug warning() { return qWarning(); }
    QDebug error() { return qCritical(); }
    QString sensitive(const QString &) { return QStringLiteral("<sensitive>"); }
};
