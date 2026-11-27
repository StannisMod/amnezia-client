#ifndef AMNEZIA_OPENVPN_NATIVE_DNS_ENGINE_HPP
#define AMNEZIA_OPENVPN_NATIVE_DNS_ENGINE_HPP

#include <cstdint>
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace amnezia {
// Posts ONLY DNS-owned IPv4 packets onto the existing engine thread. Queued
// closures retain this gate and an ID, never a Client pointer or packet bytes.
// close() joins an executing callback and synchronously cancels pending payloads;
// late closures become no-ops. The native worker must still join before policy
// release, as for all existing transport callbacks.
class NativeDNSEngine : public std::enable_shared_from_this<NativeDNSEngine> {
  public:
    using Ptr = std::shared_ptr<NativeDNSEngine>;
    using Post = std::function<void(std::function<void()>)>;
    using Send = std::function<void(const uint8_t *, int)>;
  private:
    std::mutex pending_mutex_;
    std::recursive_mutex executing_;
    std::atomic<bool> quiesced_{false};
    Post post_;
    Send send_;
    uint64_t next_ = 0;
    std::map<uint64_t, std::vector<uint8_t>> pending_;

    void run(uint64_t id)
    {
        std::vector<uint8_t> packet;
        Send send;
        {
            std::lock_guard<std::mutex> lock(pending_mutex_);
            const auto found = pending_.find(id);
            if (found == pending_.end()) return;
            packet = std::move(found->second);
            pending_.erase(found);
            send = send_;
        }
        std::lock_guard<std::recursive_mutex> executing(executing_);
        // Copy before invocation: an engine error may synchronously close the
        // gate from this same engine thread.
        if (!quiesced_.load() && send) send(packet.data(), static_cast<int>(packet.size()));
    }
    NativeDNSEngine(Post post, Send send) : post_(std::move(post)), send_(std::move(send)) {}
  public:
    static Ptr create(Post post, Send send)
    { return Ptr(new NativeDNSEngine(std::move(post), std::move(send))); }
    ~NativeDNSEngine() { close(); }
    bool retiring() const { return quiesced_.load(); }
    bool enqueue(const uint8_t *packet, int size)
    {
        if (!packet || size < 20 || size > 65535 || (packet[0] >> 4) != 4) return false;
        std::lock_guard<std::mutex> lock(pending_mutex_);
        if (quiesced_.load() || !post_ || !send_ || pending_.size() >= 128 || next_ == UINT64_MAX) return false;
        const auto id = ++next_;
        pending_.emplace(id, std::vector<uint8_t>(packet, packet + size));
        try {
            auto retained = shared_from_this();
            auto post = post_;
            // Post must enqueue asynchronously, as openvpn_io::post does.
            // Keep posting joined with quiesce, but never hold this mutex
            // while executing native engine code.
            post([retained, id] { retained->run(id); });
            return true;
        } catch (...) {
            pending_.erase(id);
            return false;
        }
    }
    void quiesce()
    {
        quiesced_.store(true);
        std::lock_guard<std::mutex> lock(pending_mutex_);
        post_ = {};
        send_ = {};
        pending_.clear();
    }
    void close()
    {
        quiesce(); // Cancel every scope before waiting for an executing send.
        std::lock_guard<std::recursive_mutex> executing(executing_);
    }
};
}
#endif
