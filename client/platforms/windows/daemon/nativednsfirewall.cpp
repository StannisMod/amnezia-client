#include "nativednsfirewall.h"
#include <fwpmu.h>

namespace NativeDnsFirewall {
namespace {
bool ensureBaseline()
{
    HANDLE engine = nullptr;
    if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine) != ERROR_SUCCESS)
        return false;
    FWPM_SUBLAYER0 *existing = nullptr;
    auto result = FwpmSubLayerGetByKey0(engine, &baselineSublayer, &existing);
    if (result == FWP_E_SUBLAYER_NOT_FOUND) {
        FWPM_SUBLAYER0 layer{};
        layer.subLayerKey = baselineSublayer;
        layer.weight = 0xffff;
        layer.displayData.name = const_cast<PWSTR>(L"Amnezia-SplitTunnel-Sublayer");
        layer.displayData.description = const_cast<PWSTR>(L"Filters that enforce a good baseline");
        result = FwpmSubLayerAdd0(engine, &layer, nullptr);
        if (result == FWP_E_ALREADY_EXISTS)
            result = FwpmSubLayerGetByKey0(engine, &baselineSublayer, &existing);
    }
    const bool valid = result == ERROR_SUCCESS &&
        (!existing || (existing->weight == 0xffff && !existing->providerKey));
    if (existing) FwpmFreeMemory0(reinterpret_cast<void **>(&existing));
    FwpmEngineClose0(engine);
    return valid;
}
}
HANDLE openLease(const QList<QHostAddress> &endpoints)
{
    if (endpoints.isEmpty() || endpoints.size() > 16 || !ensureBaseline()) return nullptr;
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    HANDLE lease = nullptr;
    if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &lease) != ERROR_SUCCESS)
        return nullptr;
    auto fail = [&]() -> HANDLE {
        FwpmTransactionAbort0(lease);
        FwpmEngineClose0(lease);
        return nullptr;
    };
    if (FwpmTransactionBegin0(lease, 0) != ERROR_SUCCESS) return fail();
    for (const auto &endpoint : endpoints) {
        if (endpoint.protocol() != QAbstractSocket::IPv4Protocol ||
                !endpoint.isInSubnet(QHostAddress("198.19.255.0"), 24)) return fail();
        for (const auto protocol : {IPPROTO_UDP, IPPROTO_TCP}) {
            for (const bool receive : {false, true}) {
                FWP_V4_ADDR_AND_MASK address{endpoint.toIPv4Address(), 0xffffffffu};
                FWPM_FILTER_CONDITION0 conditions[4]{};
                conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conditions[0].matchType = FWP_MATCH_EQUAL;
                conditions[0].conditionValue.type = FWP_UINT8;
                conditions[0].conditionValue.uint8 = protocol;
                conditions[1].fieldKey = receive ? FWPM_CONDITION_IP_LOCAL_ADDRESS : FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[1].matchType = FWP_MATCH_EQUAL;
                conditions[1].conditionValue.type = FWP_V4_ADDR_MASK;
                conditions[1].conditionValue.v4AddrMask = &address;
                conditions[2].fieldKey = receive ? FWPM_CONDITION_IP_LOCAL_PORT : FWPM_CONDITION_IP_REMOTE_PORT;
                conditions[2].matchType = FWP_MATCH_EQUAL;
                conditions[2].conditionValue.type = FWP_UINT16;
                conditions[2].conditionValue.uint16 = 53;
                conditions[3].fieldKey = FWPM_CONDITION_FLAGS;
                conditions[3].matchType = FWP_MATCH_FLAGS_ALL_SET;
                conditions[3].conditionValue.type = FWP_UINT32;
                conditions[3].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                FWPM_FILTER0 filter{};
                filter.displayData.name = const_cast<PWSTR>(L"Amnezia native DNS local IPv4");
                filter.layerKey = receive ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = baselineSublayer;
                filter.action.type = FWP_ACTION_PERMIT;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 13;
                filter.numFilterConditions = 4;
                filter.filterCondition = conditions;
                UINT64 id = 0;
                if (FwpmFilterAdd0(lease, &filter, nullptr, &id) != ERROR_SUCCESS) return fail();
            }
        }
    }
    if (FwpmTransactionCommit0(lease) != ERROR_SUCCESS) return fail();
    return lease;
}
HANDLE openSetupFence()
{
    if (!ensureBaseline()) return nullptr;
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    HANDLE lease = nullptr;
    if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &lease) != ERROR_SUCCESS)
        return nullptr;
    const auto fail = [&]() -> HANDLE {
        FwpmTransactionAbort0(lease);
        FwpmEngineClose0(lease);
        return nullptr;
    };
    if (FwpmTransactionBegin0(lease, 0) != ERROR_SUCCESS) return fail();
    for (const auto protocol : {IPPROTO_UDP, IPPROTO_TCP}) {
        FWPM_FILTER_CONDITION0 conditions[2]{};
        conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.type = FWP_UINT8;
        conditions[0].conditionValue.uint8 = protocol;
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].matchType = FWP_MATCH_EQUAL;
        conditions[1].conditionValue.type = FWP_UINT16;
        conditions[1].conditionValue.uint16 = 53;
        FWPM_FILTER0 filter{};
        filter.displayData.name = const_cast<PWSTR>(L"Amnezia native DNS pre-dial fence");
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = baselineSublayer;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 14;
        filter.numFilterConditions = 2;
        filter.filterCondition = conditions;
        UINT64 id = 0;
        if (FwpmFilterAdd0(lease, &filter, nullptr, &id) != ERROR_SUCCESS) return fail();
    }
    if (FwpmTransactionCommit0(lease) != ERROR_SUCCESS) return fail();
    return lease;
}
}
