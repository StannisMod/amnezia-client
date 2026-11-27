#include <winsock2.h>
#include <windows.h>
#include <wbemidl.h>
#include <QCoreApplication>
#include <QDebug>
#include <QScopeGuard>
#include <utility>

// Native policy-provider discovery, not a VPN/runtime acceptance substitute.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) return 1;
    auto uninitialize = qScopeGuard([] { CoUninitialize(); });
    IWbemLocator *locator = nullptr;
    auto result = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void **>(&locator));
    if (FAILED(result)) return 2;
    auto releaseLocator = qScopeGuard([&] { locator->Release(); });
    for (const auto &entry : {std::pair{L"ROOT\\StandardCimv2", L"MSFT_DNSClientDohServerAddress"},
                             std::pair{L"ROOT\\Microsoft\\Windows\\DNS", L"PS_DnsClientNrptPolicy"}}) {
        BSTR name = SysAllocString(entry.first);
        auto freeName = qScopeGuard([&] { SysFreeString(name); });
        IWbemServices *service = nullptr;
        result = locator->ConnectServer(name, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
            nullptr, nullptr, &service);
        if (FAILED(result)) {
            qCritical() << "ConnectServer" << QString::fromWCharArray(entry.first) << Qt::hex << quint32(result);
            return 3;
        }
        auto releaseService = qScopeGuard([&] { service->Release(); });
        result = CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        if (FAILED(result)) return 4;
        BSTR path = SysAllocString(entry.second);
        auto freePath = qScopeGuard([&] { SysFreeString(path); });
        IWbemClassObject *type = nullptr;
        result = service->GetObject(path, 0, nullptr, &type, nullptr);
        if (FAILED(result)) {
            qCritical() << "GetObject" << QString::fromWCharArray(entry.second) << Qt::hex << quint32(result);
            return 5;
        }
        auto releaseType = qScopeGuard([&] { type->Release(); });
        if (QString::fromWCharArray(entry.second).startsWith("MSFT_")) {
            BSTR text = nullptr;
            result = type->GetObjectText(0, &text);
            if (FAILED(result)) return 6;
            qInfo().noquote() << QString::fromWCharArray(text);
            SysFreeString(text);
            continue;
        }
        BSTR method = SysAllocString(L"Get");
        auto freeMethod = qScopeGuard([&] { SysFreeString(method); });
        IWbemClassObject *inputType = nullptr;
        result = type->GetMethod(method, 0, &inputType, nullptr);
        if (FAILED(result) || !inputType) return 7;
        auto releaseInputType = qScopeGuard([&] { inputType->Release(); });
        IWbemClassObject *input = nullptr;
        result = inputType->SpawnInstance(0, &input);
        if (FAILED(result)) return 8;
        auto releaseInput = qScopeGuard([&] { input->Release(); });
        VARIANT effective{};
        effective.vt = VT_BOOL;
        effective.boolVal = VARIANT_TRUE;
        result = input->Put(L"Effective", 0, &effective, 0);
        if (FAILED(result)) return 9;
        IWbemClassObject *output = nullptr;
        result = service->ExecMethod(path, method, 0, nullptr, input, &output, nullptr);
        if (FAILED(result) || !output) {
            qCritical() << "ExecMethod" << Qt::hex << quint32(result);
            return 10;
        }
        auto releaseOutput = qScopeGuard([&] { output->Release(); });
        BSTR text = nullptr;
        result = output->GetObjectText(0, &text);
        if (FAILED(result)) return 11;
        qInfo().noquote() << QString::fromWCharArray(text);
        SysFreeString(text);
        for (const auto property : {L"ReturnValue", L"CmdletOutput"}) {
            VARIANT value{};
            result = output->Get(property, 0, &value, nullptr, nullptr);
            qInfo() << QString::fromWCharArray(property) << "HRESULT" << Qt::hex << quint32(result)
                    << "VARTYPE" << value.vt;
            VariantClear(&value);
        }
    }
    return 0;
}
