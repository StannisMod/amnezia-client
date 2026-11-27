#ifndef IKEV2CREDENTIALFILE_H
#define IKEV2CREDENTIALFILE_H

#include <QFile>
#include <QTemporaryDir>
#ifdef Q_OS_WIN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <QScopeGuard>
#include <vector>
#endif

// QTemporaryFile::close() deliberately retains its native write handle.
// Certificate utilities may open with read-only sharing on Windows. Retain
// ownership of the private directory, but release the file handle before IPC.
class Ikev2CredentialFile
{
public:
    explicit Ikev2CredentialFile(const QByteArray &data)
    {
        if (!m_directory.isValid() || data.isEmpty() || !protectDirectory()) return;
        QFile file(path());
        if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly)
                || file.write(data) != data.size() || !file.flush()) return;
#ifndef Q_OS_WIN
        if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) return;
#endif
        file.close();
        m_valid = file.error() == QFileDevice::NoError;
    }
    bool isValid() const { return m_valid; }
    QString path() const { return m_directory.filePath("client.p12"); }
private:
    bool protectDirectory()
    {
#ifdef Q_OS_WIN
        // The GUI owns the credential, while the existing LocalSystem
        // certificate utility must be able to read it. No other user gets it.
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        auto close = qScopeGuard([&] { CloseHandle(token); });
        DWORD bytes = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
        if (!bytes || bytes > 65536) return false;
        std::vector<BYTE> data(bytes);
        if (!GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes)) return false;
        LPWSTR owner = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &owner))
            return false;
        auto freeOwner = qScopeGuard([&] { LocalFree(owner); });
        const auto text = QString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%1)")
            .arg(QString::fromWCharArray(owner));
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                reinterpret_cast<LPCWSTR>(text.utf16()), SDDL_REVISION_1, &descriptor, nullptr)) return false;
        auto freeDescriptor = qScopeGuard([&] { LocalFree(descriptor); });
        PACL dacl = nullptr;
        BOOL present = FALSE, defaulted = FALSE;
        if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present) return false;
        const auto directory = m_directory.path();
        return SetNamedSecurityInfoW(const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(directory.utf16())),
            SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
#else
        return true; // QTemporaryDir is owner-only on Unix.
#endif
    }
    QTemporaryDir m_directory;
    bool m_valid = false;
};

#endif
