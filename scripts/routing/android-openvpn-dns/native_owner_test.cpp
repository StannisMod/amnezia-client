#include "native_dns_owner.hpp"
#include <cassert>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <signal.h>
#include <sys/socket.h>
#include <thread>

namespace {
void put16(uint8_t *p, unsigned value) { p[0] = value >> 8; p[1] = value; }
std::vector<uint8_t> packet(unsigned id, unsigned type, unsigned alias = 1)
{
    const uint8_t name[] = {7,'m','a','n','a','g','e','d',7,'e','x','a','m','p','l','e',0};
    std::vector<uint8_t> p(20 + 8 + 12 + sizeof(name) + 4);
    p[0] = 0x45; put16(p.data() + 2, p.size());
    p[8] = 64; p[9] = 17;
    p[12] = 10; p[13] = 77; p[15] = 2;
    p[16] = 198; p[17] = 19; p[18] = 255; p[19] = alias;
    put16(p.data() + 20, 40000); put16(p.data() + 22, 53);
    put16(p.data() + 24, p.size() - 20);
    auto *q = p.data() + 28;
    put16(q, id); q[2] = 1; q[3] = 0x20; put16(q + 4, 1);
    std::memcpy(q + 12, name, sizeof(name));
    put16(q + 12 + sizeof(name), type); put16(q + 14 + sizeof(name), 1);
    unsigned sum = 0;
    for (unsigned i = 0; i < 20; i += 2) sum += (p[i] << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    put16(p.data() + 10, (~sum) & 65535);
    return p;
}
std::vector<uint8_t> receive(int fd, unsigned id, unsigned rcode, bool answer)
{
    pollfd ready{fd, POLLIN, 0};
    assert(poll(&ready, 1, 2000) == 1);
    std::vector<uint8_t> data(65535);
    const auto size = ::read(fd, data.data(), data.size());
    assert(size >= 40);
    data.resize(size);
    const unsigned header = (data[0] & 15) * 4;
    assert(data[0] >> 4 == 4 && data[9] == 17 && header >= 20);
    const auto *dns = data.data() + header + 8;
    assert(((dns[0] << 8) | dns[1]) == id && (dns[2] & 0x80));
    assert((dns[3] & 15) == rcode);
    assert(dns[6] == 0 && dns[7] == (answer ? 1 : 0));
    if (answer) {
        const uint8_t expected[] = {198, 51, 100, 2};
        assert(std::memcmp(data.data() + size - 4, expected, 4) == 0);
        assert(dns[3] & 0x20); // Native non-AAAA authentication flag is retained.
    } else assert(!(dns[3] & 0x20)); // Synthetic NODATA/SERVFAIL is not authenticated.
    return data;
}
struct Capture {
    int fd[2];
    Capture()
    {
        assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == 0);
        for (auto value : fd) {
            const auto flags = fcntl(value, F_GETFL);
            assert(flags >= 0 && fcntl(value, F_SETFL, flags | O_NONBLOCK) == 0);
        }
    }
    ~Capture() { for (auto value : fd) if (value >= 0) ::close(value); }
};
}

#include "native_tcp_test.hpp"
#include "native_scoped_test.hpp"
#include "native_options_test.hpp"
#include "native_tunnel_test.hpp"

int main()
{
    signal(SIGPIPE, SIG_IGN); // Socketpair fixture only; production writes a TUN.
    testNativeDNSMetadataNeverFlattens();
    std::atomic<unsigned> dispatches{0}, cancels{0}, failures{0}, retired{0};
    std::atomic<int> mode{0};
    std::atomic<int64_t> lastHandle{0};
    std::atomic<uint64_t> lastToken{0};
    std::mutex mutex;
    std::condition_variable changed;
    bool allowCancel = false, cancelStarted = false;
    amnezia::NativeDNSState *current = nullptr;
    amnezia::NativeDNSCallbacks callbacks{
        [&](int64_t handle, uint64_t token, int network, const std::string &encoded, int timeout) {
            assert((network == 0 || network == 1) && timeout > 0 && timeout <= 5000);
            dispatches++;
            lastHandle = handle; lastToken = token;
            if (mode == 1) return current->reject(handle, token);
            if (mode == 2) {
                std::lock_guard<std::mutex> lock(mutex);
                changed.notify_all();
                return true;
            }
            auto answer = openvpn::Base64().decode(encoded);
            assert(answer.size() >= 12);
            const unsigned id = (static_cast<uint8_t>(answer[0]) << 8) | static_cast<uint8_t>(answer[1]);
            assert(network == (id == 0x2346 ? 1 : 0));
            answer[2] |= 0x80; answer[3] = 0xa0; answer[7] = 1;
            const uint8_t rr[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 2};
            answer.append(reinterpret_cast<const char *>(rr), sizeof(rr));
            return current->complete(handle, token, openvpn::Base64().encode(answer));
        },
        [&](int64_t handle, uint64_t token) {
            assert(handle == lastHandle && token == lastToken);
            std::unique_lock<std::mutex> lock(mutex);
            cancels++;
            cancelStarted = true;
            changed.notify_all();
            changed.wait(lock, [&] { return allowCancel; });
        },
        [&](int64_t) {
            std::lock_guard<std::mutex> lock(mutex);
            failures++; changed.notify_all();
        },
        [&](int64_t) {
            assert(current->owned()); // Callback is not yet full policy/engine retirement.
            retired++;
        }
    };
    amnezia::NativeDNSState state(callbacks);
    current = &state;
    Capture capture;
    uint8_t ipv6[40] = {0x60};
    state.begin();
    assert(!state.owned() && state.attach(capture.fd[0], false));
    assert(state.feed(ipv6, sizeof(ipv6)) == 0); // ON behavior unchanged.
    assert(state.policy(true));
    assert(!state.policy(false)); // No live policy mutation / hidden TCP disconnect.
    state.begin();
    assert(state.prepare("fd77::53") < 0 && state.owned());
    const auto first = state.prepare("198.19.255.1");
    assert(first > 0 && state.owned());
    assert(state.prepare("198.19.255.1") < 0); // No duplicate endpoint flattening.
    assert(state.prepare("198.19.255.2") > first);
    assert(!state.attach(capture.fd[0], true) && state.owned());
    auto wire = packet(0x1234, 28);
    assert(state.feed(wire.data(), wire.size()) == -1); // Not admitted before attachment.
    assert(state.attach(capture.fd[0], false) && state.owned());
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1234, 0, false);
    assert(dispatches == 0);
    wire = packet(0x1235, 28, 2);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1235, 0, false);
    assert(dispatches == 0);
    wire = packet(0x1236, 1);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1236, 0, true);
    assert(dispatches == 1);
    state.quiesce();
    wire = packet(0x1250, 28);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1250, 0, false);
    wire = packet(0x1251, 1);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1251, 2, false);
    assert(dispatches == 1);
    assert(state.attach(capture.fd[0], false));
    testNativeTCP(state, capture.fd[1], dispatches);
    wire = packet(0x1237, 1, 3); // Not an owned DNS address.
    const auto original = wire;
    assert(state.feed(wire.data(), wire.size()) == 0 && wire == original);
    assert(state.feed(ipv6, sizeof(ipv6)) == 1); // OFF blocks IPv6, no privileged exception.
    assert(state.attach(capture.fd[0], false)); // Retained-TUN reattach, same generation.
    mode = 1;
    wire = packet(0x1238, 1);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1238, 2, false);
    mode = 2;
    const auto pendingExpected = dispatches.load() + 1;
    wire = packet(0x1239, 1);
    assert(state.feed(wire.data(), wire.size()) == 1);
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock, std::chrono::seconds(2), [&] { return dispatches == pendingExpected; }));
    }
    std::atomic<unsigned> stopped{0};
    std::thread stop1([&] { state.stop(); stopped++; });
    std::thread stop2([&] { state.stop(); stopped++; });
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock, std::chrono::seconds(2), [&] { return cancelStarted; }));
        assert(state.owned() && stopped == 0);
        assert(!state.releasePolicy()); // Pending host callback is not engine/DNS retirement.
        assert(state.feed(ipv6, sizeof(ipv6)) == -1);
        assert(!state.complete(lastHandle, lastToken, "invalid"));
        allowCancel = true;
        changed.notify_all();
    }
    stop1.join(); stop2.join();
    assert(stopped == 2 && state.owned() && cancels == 1 && failures == 0);
    auto detachedBootstrap = amnezia::NativeDNSBootstrap::acquire();
    assert(!state.releasePolicy() && state.owned());
    detachedBootstrap.reset();
    assert(state.releasePolicy() && !state.owned());
    assert(retired == 2);
    assert(AmneziaOpenVPNDNSIPv6Off() == 1); // Fence persists until next connection.
    assert(fcntl(capture.fd[0], F_GETFD) >= 0); // Never closes the native owner's descriptor.
    const auto retiredHandle = lastHandle.load();
    const auto retiredToken = lastToken.load();
    mode = 0;
    assert(state.policy(true));
    state.begin();
    assert(state.prepare("198.19.255.1") > retiredHandle);
    assert(state.attach(capture.fd[0], false));
    assert(!state.reject(retiredHandle, retiredToken));
    wire = packet(0x1240, 28);
    assert(state.feed(wire.data(), wire.size()) == 1);
    receive(capture.fd[1], 0x1240, 0, false);
    state.begin();
    assert(state.attach(capture.fd[0], false) && state.owned());
    assert(state.feed(ipv6, sizeof(ipv6)) == 1); // DNS absence cannot silently switch policy ON.
    state.stop();
    assert(state.releasePolicy() && !state.owned());
    assert(state.policy(false)); // Explicit next connection, after confirmed join.
    assert(AmneziaOpenVPNDNSIPv6Off() == 0);
    state.begin();
    assert(state.attach(capture.fd[0], false));
    assert(state.feed(ipv6, sizeof(ipv6)) == 0);
    state.stop();
    assert(state.releasePolicy());
    assert(state.policy(true));
    state.begin();
    assert(state.prepare("198.19.255.1") > 0);
    assert(state.attach(capture.fd[0], false));
    ::close(capture.fd[1]); capture.fd[1] = -1;
    wire = packet(0x1241, 28);
    assert(state.feed(wire.data(), wire.size()) == 1);
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock, std::chrono::seconds(2), [&] { return failures == 1; }));
    }
    assert(state.owned() && state.feed(wire.data(), wire.size()) == -1);
    state.stop();
    assert(state.owned() && failures == 1);
    assert(state.releasePolicy() && !state.owned());
    assert(retired == 4);
    char *provenance = AmneziaOpenVPNDNSProvenance();
    assert(provenance && std::strstr(provenance, "v1.6.4") &&
           std::strstr(provenance, "v0.22.0") && std::strstr(provenance, "v0.19.0"));
    free(provenance);
    testScopedNoFallback();
    testScopedForwarding();
    testScopedBlockedBindRetirement();
    testSelectedEncryptedScopesNeverDowngrade();
    testSelectedEncryptedForwarding();
    testNativeTunnelCABIWithoutOSNetworkBinding();
    std::cout << "PASS: real Cloak-runtime C ABI + native DNS owner NODATA/A/scope, "
                 "retained writer, failure, stale handles and concurrent joined stop\n";
}
