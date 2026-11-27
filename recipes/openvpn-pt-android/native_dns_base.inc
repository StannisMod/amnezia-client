#ifdef OPENVPN_PLATFORM_ANDROID
    TunBuilderBase()
        : amnezia_native_dns_(amnezia_dns_callbacks())
    {}

  private:
    amnezia::NativeDNSCallbacks amnezia_dns_callbacks()
    {
        return {
            [this](int64_t handle, uint64_t token, int network, const std::string &wire, int timeout) {
                return tun_builder_dns_dispatch(handle, static_cast<long long>(token), network, wire, timeout);
            },
            [this](int64_t handle, uint64_t token) {
                tun_builder_dns_cancel(handle, static_cast<long long>(token));
            },
            [this](int64_t handle) { tun_builder_dns_failed(handle); },
            [this](int64_t handle) { tun_builder_dns_retired(handle); },
            [this](int64_t handle, int fd) { return tun_builder_dns_bind(handle, fd); }
        };
    }
  public:

    // DNS bytes cross SWIG as base64, never a lossy UTF-8 conversion or log.
    virtual bool tun_builder_dns_dispatch(long long handle, long long token, int network,
                                          const std::string &wire, int timeout) { return false; }
    virtual void tun_builder_dns_cancel(long long handle, long long token) {}
    virtual void tun_builder_dns_failed(long long handle) {}
    virtual void tun_builder_dns_retired(long long handle) {}
    virtual bool tun_builder_dns_bind(long long handle, int fd) { return false; }
    virtual bool tun_builder_dns_tunnel_allowed() { return false; }
    // Final native modern DNS port, not an inferred/default replacement.
    virtual bool tun_builder_dns_server(const std::string &address, int port, bool ipv6)
    { return false; }
    virtual bool tun_builder_dns_transport(const std::string &address, int port, bool ipv6,
        const std::string &transport, const std::string &serverName) { return false; }

    long long amnezia_dns_prepare(const std::string &address)
    { return amnezia_native_dns_.prepare(address); }
    long long amnezia_dns_prepare_scoped(const std::string &address, const std::string &upstream)
    { return amnezia_native_dns_.prepareScoped(address, upstream); }
    long long amnezia_dns_prepare_selected(const std::string &address, const std::string &upstream,
        const std::string &transport, const std::string &serverName, const std::string &httpsURL)
    { return amnezia_native_dns_.prepareSelected(address, upstream, transport, serverName, httpsURL); }
    long long amnezia_dns_prepare_tunnel(const std::string &address, const std::string &source, int mtu,
        const std::string &upstream, const std::string &transport,
        const std::string &serverName, const std::string &httpsURL)
    { return amnezia_native_dns_.prepareTunnel(address, source, mtu, upstream, transport, serverName, httpsURL); }
    bool amnezia_dns_complete(long long handle, long long token, const std::string &answer)
    { return amnezia_native_dns_.complete(handle, static_cast<uint64_t>(token), answer); }
    bool amnezia_dns_reject(long long handle, long long token)
    { return amnezia_native_dns_.reject(handle, static_cast<uint64_t>(token)); }
    bool amnezia_dns_owned() const { return amnezia_native_dns_.owned(); }
    void amnezia_dns_stop() { amnezia_native_dns_.stop(); }
    bool amnezia_dns_policy(bool off) { return amnezia_native_dns_.policy(off); }
    bool amnezia_dns_release_policy() { return amnezia_native_dns_.releasePolicy(); }
    bool amnezia_ipv6_off() const { return amnezia_native_dns_.ipv6Off(); }

    // Called only by the existing native TunBuilderClient, never a second
    // Android reader/stack. SWIG does not expose descriptor/packet entrypoints.
    void amnezia_dns_begin() { amnezia_native_dns_.begin(); }
    bool amnezia_dns_attach(int descriptor, bool prefixed, amnezia::NativeDNSEngine::Ptr engine = {})
    { return amnezia_native_dns_.attach(descriptor, prefixed, std::move(engine)); }
    int amnezia_dns_feed(unsigned char *bytes, int size)
    { return amnezia_native_dns_.feed(bytes, size); }
    int amnezia_dns_feed_tunnel(unsigned char *bytes, int size)
    { return amnezia_native_dns_.feedTunnel(bytes, size); }
    bool amnezia_dns_active() const { return amnezia_native_dns_.active(); }
    void amnezia_dns_quiesce() { amnezia_native_dns_.quiesce(); }

  private:
    amnezia::NativeDNSState amnezia_native_dns_;
  public:
#endif
