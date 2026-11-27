#ifndef AMNEZIA_OPENVPN_NATIVE_DNS_BOOTSTRAP_HPP
#define AMNEZIA_OPENVPN_NATIVE_DNS_BOOTSTRAP_HPP
#include <memory>
#include <mutex>
#include <cstddef>

namespace amnezia {
// The pinned native resolver deliberately detaches getaddrinfo workers because
// that API cannot be cancelled. Detachment is NOT retirement: retain the policy
// owner until those workers actually finish, without timeout kills.
class NativeDNSBootstrap {
    struct State { std::mutex mutex; size_t active = 0; };
    // Process-lifetime registry: a detached OS resolver must never race a
    // static mutex destructor during an externally initiated process exit.
    static State &state() { static State *value = new State; return *value; }
    struct Lease {
        Lease() { std::lock_guard<std::mutex> lock(state().mutex); ++state().active; }
        ~Lease() { std::lock_guard<std::mutex> lock(state().mutex); --state().active; }
        Lease(const Lease &) = delete;
        Lease &operator=(const Lease &) = delete;
    };
  public:
    static auto acquire() { return std::make_shared<Lease>(); }
    template<class Function> static bool whileIdle(Function function)
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        return state().active == 0 && function();
    }
};
}
#endif
