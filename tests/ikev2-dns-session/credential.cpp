#include <winsock2.h>
#include <windows.h>
#include <QtTest>
#include <QScopeGuard>
#include <QTemporaryFile>
#include "../../client/core/protocols/ikev2CredentialFile.h"

class CredentialFileTest : public QObject
{
    Q_OBJECT
private slots:
    void closedQTemporaryFileRetainsTheConflictingNativeHandle()
    {
        QTemporaryFile file;
        QVERIFY(file.open());
        QCOMPARE(file.write("fixture-data"), qint64(12));
        const auto path = file.fileName();
        file.close();
        const auto reader = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),
            GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto error = GetLastError();
        auto cleanup = qScopeGuard([&] { if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader); });
        QVERIFY(reader == INVALID_HANDLE_VALUE);
        QCOMPARE(error, DWORD(ERROR_SHARING_VIOLATION));
    }
    void productionCredentialIsReadableAndRetiresWithItsOwner()
    {
        QString path;
        {
            Ikev2CredentialFile file("fixture-data");
            QVERIFY(file.isValid());
            path = file.path();
            const auto reader = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),
                GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            QVERIFY(reader != INVALID_HANDLE_VALUE);
            auto cleanup = qScopeGuard([&] { CloseHandle(reader); });
            char bytes[12]{};
            DWORD size = 0;
            QVERIFY(ReadFile(reader, bytes, sizeof(bytes), &size, nullptr));
            QCOMPARE(size, DWORD(12));
            QCOMPARE(QByteArray(bytes, 12), QByteArray("fixture-data"));
        }
        QVERIFY(!QFileInfo::exists(path));
        QVERIFY(!QFileInfo::exists(QFileInfo(path).absolutePath()));
    }
};
QTEST_GUILESS_MAIN(CredentialFileTest)
#include "credential.moc"
