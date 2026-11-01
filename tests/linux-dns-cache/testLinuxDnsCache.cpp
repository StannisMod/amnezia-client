#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

#include "../../service/server/linuxdnscache.h"

class LinuxDnsCacheTests : public QObject {
    Q_OBJECT
private slots:
    void flush_data()
    {
        QTest::addColumn<QByteArray>("manager");
        QTest::addColumn<QByteArray>("behavior");
        QTest::addColumn<bool>("installCommand");
        QTest::addColumn<bool>("expected");
        QTest::newRow("resolved") << QByteArray("resolved") << QByteArray("ok") << true << true;
        QTest::newRow("resolved-preferred-over-nscd") << QByteArray("both") << QByteArray("ok") << true << true;
        QTest::newRow("nscd") << QByteArray("nscd") << QByteArray("ok") << true << true;
        QTest::newRow("no-manager") << QByteArray("none") << QByteArray("ok") << true << false;
        QTest::newRow("missing-resolvectl") << QByteArray("resolved") << QByteArray("ok") << false << false;
        QTest::newRow("missing-nscd") << QByteArray("nscd") << QByteArray("ok") << false << false;
        QTest::newRow("nonzero-exit-no-restart-fallback") << QByteArray("both") << QByteArray("fail") << true << false;
        QTest::newRow("crash") << QByteArray("resolved") << QByteArray("crash") << true << false;
        QTest::newRow("timeout-no-restart-fallback") << QByteArray("both") << QByteArray("timeout") << true << false;
    }

    void flush()
    {
        QFETCH(QByteArray, manager);
        QFETCH(QByteArray, behavior);
        QFETCH(bool, installCommand);
        QFETCH(bool, expected);
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QByteArray oldPath = qgetenv("PATH");
        const bool hadPath = qEnvironmentVariableIsSet("PATH");
        auto restorePath = qScopeGuard([&] {
            if (hadPath) qputenv("PATH", oldPath); else qunsetenv("PATH");
        });
        const QString logPath = dir.filePath("commands.log");
        auto script = [&](const QString &name, const QByteArray &body) {
            QFile file(dir.filePath(name));
            if (!file.open(QIODevice::WriteOnly)) return false;
            file.write("#!/bin/sh\n");
            file.write("echo '" + name.toUtf8() + "' \"$@\" >> '" + logPath.toUtf8() + "'\n");
            file.write(body);
            file.close();
            return file.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
        };
        QByteArray status = "exit 3\n";
        if (manager == "both") status = "exit 0\n";
        if (manager == "resolved") status = "[ \"$3\" = systemd-resolved.service ]\n";
        if (manager == "nscd") status = "[ \"$3\" = nscd.service ]\n";
        QVERIFY(script("systemctl", status));
        if (installCommand) {
            QByteArray body = "exit 0\n";
            if (behavior == "fail") body = "echo failure >&2\nexit 1\n";
            if (behavior == "crash") body = "kill -KILL $$\n";
            if (behavior == "timeout") body = "exec /bin/sleep 10\n";
            QVERIFY(script("resolvectl", body));
            QVERIFY(script("nscd", body));
        }
        qputenv("PATH", dir.path().toUtf8());
        QElapsedTimer timer;
        timer.start();
        QCOMPARE(LinuxDnsCache::flush(500), expected);
        QVERIFY2(timer.elapsed() < 4000, "DNS cache operation exceeded its bounded timeout");
        QFile log(logPath);
        QVERIFY(log.open(QIODevice::ReadOnly));
        const QByteArray commands = log.readAll();
        QVERIFY(!commands.contains("restart"));
        QVERIFY(!commands.contains(" stop"));
        if (manager == "resolved" || manager == "both") {
            QVERIFY(!commands.contains("nscd"));
            if (installCommand) QVERIFY(commands.contains("resolvectl flush-caches\n"));
        } else if (manager == "nscd" && installCommand) {
            QVERIFY(commands.contains("nscd -i hosts\n"));
        }
    }
};

QTEST_GUILESS_MAIN(LinuxDnsCacheTests)
#include "testLinuxDnsCache.moc"
