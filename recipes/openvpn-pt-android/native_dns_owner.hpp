#ifndef AMNEZIA_OPENVPN_NATIVE_DNS_OWNER_HPP
#define AMNEZIA_OPENVPN_NATIVE_DNS_OWNER_HPP

#include "native_dns.h"
#include "native_dns_bootstrap.hpp"
#include "native_dns_engine.hpp"
#include <openvpn/common/base64.hpp>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace amnezia {

struct NativeDNSCallbacks {
    std::function<bool(int64_t, uint64_t, int, const std::string &, int)> dispatch;
    std::function<void(int64_t, uint64_t)> cancel;
    std::function<void(int64_t)> failed;
    std::function<void(int64_t)> retired;
    std::function<bool(int64_t, int)> bind;
};

// DNS-only output uses a duplicate of the actual native capture descriptor.
// It never reads that descriptor or creates another interface/packet reader.
// The duplicate keeps the original generation alive through native reconnect
// and is released only AFTER the Go frontend and its host callbacks join.
class NativeDNSOwner {
    using Retained = std::shared_ptr<NativeDNSOwner>;
    NativeDNSCallbacks callbacks_;
    const std::string address_;
    std::atomic<int64_t> handle_{0};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> quiescing_{false};
    std::atomic<bool> failed_{false};
    std::once_flag stopped_;
    std::mutex writer_;
    int output_ = -1;
    NativeDNSEngine::Ptr engine_;
    bool tunnel_ = false;

    explicit NativeDNSOwner(std::string address, NativeDNSCallbacks callbacks)
        : callbacks_(std::move(callbacks)), address_(std::move(address)) {}

    static NativeDNSOwner &get(void *host) { return **static_cast<Retained *>(host); }
    static void release(void *host)
    {
        auto retained = static_cast<Retained *>(host);
        auto &s = **retained;
        if (s.handle() > 0 && s.callbacks_.retired) {
            try { s.callbacks_.retired(s.handle()); } catch (...) {}
        }
        delete retained;
    }
    static int32_t write(void *host, const uint8_t *packet, int32_t size)
    { return get(host).writePacket(packet, size) ? 1 : 0; }
    static int32_t dispatch(void *host, int64_t handle, uint64_t token, int32_t network,
                            const uint8_t *wire, int32_t size, int32_t timeout)
    {
        auto &s = get(host);
        if (s.stopping_.load() || s.quiescing_.load() || s.failed_.load() || size < 12 || size > 65535) return 0;
        try {
            return s.callbacks_.dispatch(handle, token, network,
                openvpn::Base64().encode(wire, size), timeout) ? 1 : 0;
        } catch (...) { return 0; }
    }
    static void cancel(void *host, int64_t handle, uint64_t token)
    {
        // Cancellation must still reach native I/O during intentional stop.
        try { get(host).callbacks_.cancel(handle, token); } catch (...) {}
    }
    static void failure(void *host, int64_t handle)
    {
        auto &s = get(host);
        if (!s.stopping_.load() && !s.failed_.exchange(true)) {
            try { s.callbacks_.failed(handle); } catch (...) {}
        }
    }
    static int32_t bind(void *host, int64_t handle, int32_t fd)
    {
        auto &s = get(host);
        if (s.stopping_.load() || s.quiescing_.load() || s.failed_.load() || !s.callbacks_.bind) return 0;
        try { return s.callbacks_.bind(handle, fd) ? 1 : 0; } catch (...) { return 0; }
    }
    static int32_t tunnelWrite(void *host, const uint8_t *packet, int32_t size)
    {
        auto &s = get(host);
        NativeDNSEngine::Ptr engine;
        {
            std::lock_guard<std::mutex> lock(s.writer_);
            if (s.stopping_.load() || s.quiescing_.load()) return 1; // Cancelled DNS output is consumed, never retried.
            if (s.failed_.load()) return 0;
            engine = s.engine_;
        }
        return engine && (engine->enqueue(packet, size) || engine->retiring()) ? 1 : 0;
    }
    bool writePacket(const uint8_t *packet, int32_t size)
    {
        if (stopping_.load() || failed_.load() || size <= 0 || size > 65535) return false;
        std::lock_guard<std::mutex> lock(writer_);
        if (output_ < 0 || stopping_.load()) return false;
        // Do not change native descriptor flags, and never risk a blocking
        // write from a callback. Native TunIO starts nonblocking reads before
        // any packet can be fed into this endpoint.
        const int flags = fcntl(output_, F_GETFL);
        if (flags < 0 || !(flags & O_NONBLOCK)) return false;
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        while (!stopping_.load()) {
            const auto result = ::write(output_, packet, static_cast<size_t>(size));
            if (result == size) return true;
            if (result >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return false;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                until - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) return false;
            pollfd ready{output_, POLLOUT, 0};
            const int rc = poll(&ready, 1, static_cast<int>(remaining));
            if (rc == 0 || (rc < 0 && errno != EINTR) ||
                (rc > 0 && (ready.revents & (POLLERR | POLLHUP | POLLNVAL)))) return false;
        }
        return false;
    }

  public:
    static Retained prepare(const std::string &address, int64_t policy, NativeDNSCallbacks callbacks,
                            const std::string *upstream = nullptr, const std::string *transport = nullptr,
                            const std::string *serverName = nullptr, const std::string *httpsURL = nullptr,
                            const std::string *source = nullptr, int mtu = 0)
    {
        auto s = Retained(new NativeDNSOwner(address, std::move(callbacks)));
        // The ABI owns this retained reference on success AND on failure.
        auto retained = new Retained(s);
        s->tunnel_ = source != nullptr;
        auto handle = source && upstream && transport
            ? AmneziaOpenVPNDNSStartTunnel(const_cast<char *>(address.c_str()),
                const_cast<char *>(source->c_str()), const_cast<char *>(upstream->c_str()),
                const_cast<char *>(transport->c_str()),
                const_cast<char *>(serverName ? serverName->c_str() : ""),
                const_cast<char *>(httpsURL ? httpsURL->c_str() : ""),
                mtu, policy, retained, write, tunnelWrite, failure, release)
            : upstream && transport
            ? AmneziaOpenVPNDNSStartSelected(const_cast<char *>(address.c_str()),
                const_cast<char *>(upstream->c_str()), const_cast<char *>(transport->c_str()),
                const_cast<char *>(serverName ? serverName->c_str() : ""),
                const_cast<char *>(httpsURL ? httpsURL->c_str() : ""),
                policy, retained, write, bind, failure, release)
            : upstream
            ? AmneziaOpenVPNDNSStartScoped(const_cast<char *>(address.c_str()),
                const_cast<char *>(upstream->c_str()), policy, retained, write, bind, failure, release)
            : AmneziaOpenVPNDNSStart(const_cast<char *>(address.c_str()), policy, retained,
                write, dispatch, cancel, failure, release);
        s->handle_.store(handle);
        if (handle <= 0 || s->failed_.load()) {
            s->stop();
            return {};
        }
        return s;
    }
    ~NativeDNSOwner() { stop(); }
    int64_t handle() const { return handle_.load(); }
    const std::string &address() const { return address_; }
    bool attach(int descriptor, NativeDNSEngine::Ptr engine = {})
    {
        std::lock_guard<std::mutex> lock(writer_);
        if (stopping_.load() || failed_.load() || descriptor < 0 || (tunnel_ && !engine)) return false;
        const int duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
        if (duplicate < 0) return false;
        if (output_ >= 0) ::close(output_);
        output_ = duplicate;
        engine_ = std::move(engine);
        if (AmneziaOpenVPNDNSResume(handle()) != 1) return false;
        quiescing_.store(false);
        return true;
    }
    int feed(uint8_t *packet, int size)
    {
        if (stopping_.load() || failed_.load()) return -1;
        return AmneziaOpenVPNDNSFeed(handle(), packet, size);
    }
    int feedTunnel(uint8_t *packet, int size)
    {
        if (!tunnel_ || stopping_.load() || failed_.load()) return 0;
        return AmneziaOpenVPNDNSFeedTunnel(handle(), packet, size);
    }
    bool complete(uint64_t token, const std::string &encoded)
    {
        if (stopping_.load() || failed_.load() || encoded.size() > 87384) return false;
        try {
            auto wire = openvpn::Base64().decode(encoded);
            if (wire.size() < 12 || wire.size() > 65535) return false;
            return AmneziaOpenVPNDNSComplete(handle(), token,
                reinterpret_cast<uint8_t *>(&wire[0]), static_cast<int32_t>(wire.size())) == 1;
        } catch (...) { return false; }
    }
    bool reject(uint64_t token) { return AmneziaOpenVPNDNSReject(handle(), token) == 1; }
    void quiesce()
    {
        quiescing_.store(true);
        NativeDNSEngine::Ptr engine;
        {
            std::lock_guard<std::mutex> lock(writer_);
            engine = engine_;
        }
        if (engine) engine->quiesce();
        if (handle() > 0) AmneziaOpenVPNDNSQuiesce(handle());
    }
    void stop()
    {
        std::call_once(stopped_, [this] {
            stopping_.store(true);
            quiesce();
            if (handle() > 0) AmneziaOpenVPNDNSStop(handle());
            NativeDNSEngine::Ptr engine;
            {
                std::lock_guard<std::mutex> lock(writer_);
                engine = engine_;
            }
            if (engine) engine->close();
            std::lock_guard<std::mutex> lock(writer_);
            if (output_ >= 0) { ::close(output_); output_ = -1; }
        });
    }
};

class NativeDNSState {
    using Owners = std::map<int64_t, std::shared_ptr<NativeDNSOwner>>;
    NativeDNSCallbacks callbacks_;
    mutable std::mutex state_;
    std::mutex transition_;
    Owners active_, prepared_;
    std::shared_ptr<const Owners> snapshot_ = std::make_shared<const Owners>();
    bool staged_ = false;
    bool retiring_ = false;
    std::atomic<int64_t> policy_{0};
    std::atomic<bool> off_{false};

    static void quiesce(Owners &owners)
    { for (auto &entry : owners) entry.second->quiesce(); }
    static void close(Owners &owners)
    {
        quiesce(owners);
        for (auto &entry : owners) entry.second->stop();
    }

  public:
    explicit NativeDNSState(NativeDNSCallbacks callbacks) : callbacks_(std::move(callbacks)) {}
    ~NativeDNSState() { stop(); }
    bool policy(bool off)
    {
        std::lock_guard<std::mutex> transition(transition_);
        if (policy_.load() > 0) return off_.load() == off;
        return NativeDNSBootstrap::whileIdle([&] {
            const auto generation = AmneziaOpenVPNDNSPolicy(off ? 1 : 0);
            if (generation <= 0) return false;
            off_.store(off);
            policy_.store(generation);
            return true;
        });
    }
    // Caller must first join the native connect/transport worker, then stop DNS.
    // Neither a native stop request nor DNS absence alone proves engine join.
    bool releasePolicy()
    {
        std::unique_lock<std::mutex> transition(transition_, std::try_to_lock);
        if (!transition.owns_lock()) return false;
        {
            std::lock_guard<std::mutex> lock(state_);
            if (retiring_ || !active_.empty() || !prepared_.empty()) return false;
        }
        const auto generation = policy_.load();
        if (generation <= 0) return true;
        return NativeDNSBootstrap::whileIdle([&] {
            if (AmneziaOpenVPNDNSReleasePolicy(generation) != 1) return false;
            policy_.store(0);
            return true;
        });
    }
    bool ipv6Off() const { return off_.load(); }
    void begin()
    {
        std::lock_guard<std::mutex> transition(transition_);
        Owners prior;
        {
            std::lock_guard<std::mutex> lock(state_);
            prior.swap(prepared_);
            retiring_ = !prior.empty();
        }
        close(prior);
        std::lock_guard<std::mutex> lock(state_);
        retiring_ = false;
        staged_ = true;
    }
    int64_t prepare(const std::string &address, const std::string *upstream = nullptr,
                    const std::string *transport = nullptr, const std::string *serverName = nullptr,
                    const std::string *httpsURL = nullptr, const std::string *source = nullptr, int mtu = 0)
    {
        std::lock_guard<std::mutex> transition(transition_);
        {
            std::lock_guard<std::mutex> lock(state_);
            if (!staged_ || retiring_ || prepared_.size() >= 16 ||
                policy_.load() <= 0 || !off_.load()) return -1;
            for (const auto &entry : prepared_)
                if (entry.second->address() == address) return -1;
        }
        auto owner = NativeDNSOwner::prepare(address, policy_.load(), callbacks_, upstream, transport, serverName, httpsURL, source, mtu);
        if (!owner) return -1;
        std::lock_guard<std::mutex> lock(state_);
        prepared_.emplace(owner->handle(), owner);
        return owner->handle();
    }
    int64_t prepareScoped(const std::string &address, const std::string &upstream)
    { return prepare(address, &upstream); }
    int64_t prepareSelected(const std::string &address, const std::string &upstream,
                            const std::string &transport, const std::string &serverName,
                            const std::string &httpsURL)
    { return prepare(address, &upstream, &transport, &serverName, &httpsURL); }
    int64_t prepareTunnel(const std::string &address, const std::string &source, int mtu, const std::string &upstream,
                         const std::string &transport, const std::string &serverName, const std::string &httpsURL)
    { return prepare(address, &upstream, &transport, &serverName, &httpsURL, &source, mtu); }
    bool attach(int descriptor, bool prefixed, NativeDNSEngine::Ptr engine = {})
    {
        std::lock_guard<std::mutex> transition(transition_);
        Owners selected, prior;
        bool staged;
        {
            std::lock_guard<std::mutex> lock(state_);
            if (retiring_) return false;
            staged = staged_;
            selected = staged ? prepared_ : active_;
        }
        if (!selected.empty() && prefixed) return false; // Android native IP framing only.
        for (auto &entry : selected)
            if (!entry.second->attach(descriptor, engine)) return false;
        if (staged) {
            {
                std::lock_guard<std::mutex> lock(state_);
                prior.swap(active_);
                active_.swap(prepared_);
                snapshot_ = std::make_shared<const Owners>(active_);
                retiring_ = !prior.empty();
                staged_ = false;
            }
            close(prior);
            std::lock_guard<std::mutex> lock(state_);
            retiring_ = false;
        }
        return true;
    }
    int feed(uint8_t *packet, int size)
    {
        std::shared_ptr<const Owners> owners;
        {
            std::lock_guard<std::mutex> lock(state_);
            if (retiring_ || (active_.empty() && !prepared_.empty())) return -1;
            owners = snapshot_;
        }
        if (off_.load() && size > 0 && (packet[0] >> 4) == 6) return 1;
        for (const auto &entry : *owners) {
            const auto handled = entry.second->feed(packet, size);
            if (handled != 0) return handled;
        }
        return 0;
    }
    int feedTunnel(uint8_t *packet, int size)
    {
        std::shared_ptr<const Owners> owners;
        {
            std::lock_guard<std::mutex> lock(state_);
            owners = snapshot_;
        }
        for (const auto &entry : *owners) {
            const auto handled = entry.second->feedTunnel(packet, size);
            if (handled != 0) return handled;
        }
        return 0;
    }
    bool owned() const
    {
        std::lock_guard<std::mutex> lock(state_);
        return policy_.load() > 0 || retiring_ || !active_.empty() || !prepared_.empty();
    }
    bool active() const
    {
        return off_.load();
    }
    void quiesce()
    {
        Owners active, prepared;
        {
            std::lock_guard<std::mutex> lock(state_);
            active = active_;
            prepared = prepared_;
        }
        quiesce(active);
        quiesce(prepared);
    }
    bool complete(int64_t handle, uint64_t token, const std::string &answer)
    {
        std::shared_ptr<NativeDNSOwner> owner;
        {
            std::lock_guard<std::mutex> lock(state_);
            auto entry = active_.find(handle);
            if (entry == active_.end()) return false;
            owner = entry->second;
        }
        return owner->complete(token, answer);
    }
    bool reject(int64_t handle, uint64_t token)
    {
        std::shared_ptr<NativeDNSOwner> owner;
        {
            std::lock_guard<std::mutex> lock(state_);
            auto entry = active_.find(handle);
            if (entry == active_.end()) return false;
            owner = entry->second;
        }
        return owner->reject(token);
    }
    void stop()
    {
        std::lock_guard<std::mutex> transition(transition_);
        Owners active, prepared;
        {
            std::lock_guard<std::mutex> lock(state_);
            active.swap(active_);
            snapshot_ = std::make_shared<const Owners>();
            prepared.swap(prepared_);
            retiring_ = !active.empty() || !prepared.empty();
            staged_ = false;
        }
        quiesce(active);
        quiesce(prepared);
        close(active);
        close(prepared);
        std::lock_guard<std::mutex> lock(state_);
        retiring_ = false;
    }
};
} // namespace amnezia
#endif
