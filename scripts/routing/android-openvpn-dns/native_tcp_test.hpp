// Test-only raw TCP peer for the real C ABI. No production packet stack here.
#ifndef AMNEZIA_OPENVPN_DNS_NATIVE_TCP_TEST_HPP
#define AMNEZIA_OPENVPN_DNS_NATIVE_TCP_TEST_HPP
namespace {
unsigned tcpChecksum(const uint8_t *bytes, size_t size, unsigned sum = 0)
{
    for (size_t i = 0; i < size; i += 2)
        sum += (unsigned(bytes[i]) << 8) | (i + 1 < size ? bytes[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}
void put32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = value >> 24; bytes[1] = value >> 16;
    bytes[2] = value >> 8; bytes[3] = value;
}
uint32_t get32(const uint8_t *bytes)
{
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
           (uint32_t(bytes[2]) << 8) | bytes[3];
}
class TCPPeer {
    amnezia::NativeDNSState &state_;
    int output_;
    uint32_t client_ = 0x10203040;
    uint32_t server_ = 0;

    void send(uint8_t flags, const std::vector<uint8_t> &payload = {})
    {
        std::vector<uint8_t> p(40 + payload.size());
        p[0] = 0x45; put16(p.data() + 2, p.size());
        p[8] = 64; p[9] = 6;
        p[12] = 10; p[13] = 77; p[15] = 2;
        p[16] = 198; p[17] = 19; p[18] = 255; p[19] = 1;
        auto *tcp = p.data() + 20;
        put16(tcp, 40001); put16(tcp + 2, 53);
        put32(tcp + 4, client_); put32(tcp + 8, server_);
        tcp[12] = 0x50; tcp[13] = flags; put16(tcp + 14, 65535);
        std::copy(payload.begin(), payload.end(), p.begin() + 40);
        unsigned pseudo = 6 + p.size() - 20;
        for (unsigned i = 12; i < 20; i += 2) pseudo += (unsigned(p[i]) << 8) | p[i + 1];
        put16(tcp + 16, tcpChecksum(tcp, p.size() - 20, pseudo));
        put16(p.data() + 10, tcpChecksum(p.data(), 20));
        const auto original = p;
        assert(state_.feed(p.data(), p.size()) == 1 && p == original);
    }
    std::vector<uint8_t> read()
    {
        pollfd ready{output_, POLLIN, 0};
        assert(poll(&ready, 1, 2000) == 1);
        std::vector<uint8_t> p(65535);
        const auto size = ::read(output_, p.data(), p.size());
        assert(size >= 40);
        p.resize(size);
        const unsigned ip = (p[0] & 15) * 4;
        assert(p[0] >> 4 == 4 && p[9] == 6 && ip >= 20 && size >= ip + 20);
        assert(p[12] == 198 && p[13] == 19 && p[14] == 255 && p[15] == 1);
        const auto *tcp = p.data() + ip;
        assert(tcp[0] == 0 && tcp[1] == 53 && ((tcp[2] << 8) | tcp[3]) == 40001);
        assert(!(tcp[13] & 4)); // Never accept a reset as a DNS response.
        return p;
    }
  public:
    TCPPeer(amnezia::NativeDNSState &state, int output) : state_(state), output_(output)
    {
        send(2);
        const auto p = read();
        const auto *tcp = p.data() + (p[0] & 15) * 4;
        assert((tcp[13] & 0x12) == 0x12 && get32(tcp + 8) == client_ + 1);
        server_ = get32(tcp + 4) + 1;
        ++client_;
        send(0x10);
    }
    std::vector<uint8_t> query(unsigned id, unsigned type, unsigned expectedRcode = 0)
    {
        const auto udp = packet(id, type);
        std::vector<uint8_t> frame(2);
        put16(frame.data(), udp.size() - 28);
        frame.insert(frame.end(), udp.begin() + 28, udp.end());
        // Deliberately split the two-byte DNS length prefix across native
        // TCP packets, then send a second query on this same stream.
        send(0x18, std::vector<uint8_t>{frame[0]}); ++client_;
        send(0x18, std::vector<uint8_t>(frame.begin() + 1, frame.end()));
        client_ += frame.size() - 1;
        std::vector<uint8_t> response;
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < until) {
            const auto p = read();
            const unsigned ip = (p[0] & 15) * 4;
            const auto *tcp = p.data() + ip;
            const unsigned head = (tcp[12] >> 4) * 4;
            assert(head >= 20 && p.size() >= ip + head);
            const auto payload = p.size() - ip - head;
            if (!payload) continue; // Separate native TCP acknowledgement.
            const auto sequence = get32(tcp + 4);
            if (sequence == server_) {
                response.insert(response.end(), p.begin() + ip + head, p.end());
                server_ += payload;
            } else {
                assert(static_cast<int32_t>(sequence - server_) < 0); // Retransmission only.
            }
            send(0x10);
            if (response.size() < 2) continue;
            const unsigned size = (response[0] << 8) | response[1];
            assert(size >= 12 && size <= 65535 && response.size() <= size + 2);
            if (response.size() == size + 2) {
                std::vector<uint8_t> dns(response.begin() + 2, response.end());
                assert(((dns[0] << 8) | dns[1]) == id && (dns[2] & 0x80) && (dns[3] & 15) == expectedRcode);
                return dns;
            }
        }
        assert(false && "native TCP DNS frame did not complete");
        return {};
    }
    void close()
    {
        send(0x14); // Exact-sequence client reset; no long-lived fixture endpoint.
        // Drain only this completed TCP tuple before the subsequent UDP cases.
        pollfd ready{output_, POLLIN, 0};
        while (poll(&ready, 1, 50) == 1) {
            const auto p = read();
            assert(p[9] == 6);
        }
    }
};

void testNativeTCP(amnezia::NativeDNSState &state, int output, std::atomic<unsigned> &dispatches)
{
    const auto before = dispatches.load();
    TCPPeer peer(state, output);
    const auto nodata = peer.query(0x2345, 28);
    assert(nodata[6] == 0 && nodata[7] == 0 && !(nodata[3] & 0x20));
    assert(dispatches == before);
    const auto answer = peer.query(0x2346, 1);
    assert(answer[6] == 0 && answer[7] == 1 && (answer[3] & 0x20));
    const uint8_t expected[] = {198, 51, 100, 2};
    assert(std::memcmp(answer.data() + answer.size() - 4, expected, 4) == 0);
    assert(dispatches == before + 1);
    peer.close();
}
}
#endif
