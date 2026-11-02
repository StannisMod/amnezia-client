import Foundation
import NetworkExtension

extension PacketTunnelProvider {
    func startWireguard(activationAttemptId: String?,
                        errorNotifier: ErrorNotifier,
                        completionHandler: @escaping (Error?) -> Void) {
        guard let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration,
              let wgConfigData: Data = providerConfiguration[Constants.wireGuardConfigKey] as? Data else {
            wg_log(.error, message: "Can't start, config missing")
            completionHandler(nil)
            return
        }

        do {
            let wgConfig = try JSONDecoder().decode(WGConfig.self, from: wgConfigData)
            if wgConfig.routingConfig != nil {
                let routed = RoutingPacketTunnel(provider: self)
                routedAdapter = routed
                routed.start(config: wgConfig) { error in
                    if error != nil { errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend) }
                    completionHandler(error)
                }
                return
            }
            let wgConfigStr = wgConfig.str

            let tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: wgConfigStr)

            if tunnelConfiguration.peers.first!.allowedIPs
                .map({ $0.stringRepresentation })
                .joined(separator: ", ") == "0.0.0.0/0, ::/0" {
                if wgConfig.splitTunnelType == 1 {
                    for index in tunnelConfiguration.peers.indices {
                        tunnelConfiguration.peers[index].allowedIPs.removeAll()
                        var allowedIPs = [IPAddressRange]()

                        for allowedIPString in wgConfig.splitTunnelSites {
                            if let allowedIP = IPAddressRange(from: allowedIPString) {
                                allowedIPs.append(allowedIP)
                            }
                        }

                        tunnelConfiguration.peers[index].allowedIPs = allowedIPs
                    }
                } else if wgConfig.splitTunnelType == 2 {
                    for index in tunnelConfiguration.peers.indices {
                        var excludeIPs = [IPAddressRange]()

                        for excludeIPString in wgConfig.splitTunnelSites {
                            if let excludeIP = IPAddressRange(from: excludeIPString) {
                                excludeIPs.append(excludeIP)
                            }
                        }

                        tunnelConfiguration.peers[index].excludeIPs = excludeIPs
                    }
                }
            }

            wg_log(.info, message: "Starting tunnel from the " +
                   (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

            wireguardRefreshQueue.sync {
                wireguardRefreshPolicy.cancel()
                wireguardRefreshWork?.cancel()
                wireguardOriginalConfiguration = tunnelConfiguration
                wireguardCandidates.removeAll()
                wireguardEndpointStopped = false
                wireguardHealthBudget = EndpointHealthPolicy.staleBudget(rekey: wgConfig.rekeyAfterTime, reject: wgConfig.rejectAfterTime)
            }

            // Start the tunnel
            wgAdapter = WireGuardAdapter(with: self) { logLevel, message in
                wg_log(logLevel.osLogLevel, message: message)
            }

            wgAdapter?.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
                guard let adapterError else {
                    let interfaceName = self?.wgAdapter?.interfaceName ?? "unknown"
                    wg_log(.info, message: "Tunnel interface is \(interfaceName)")
                    self?.startWireguardEndpointWatchdog()
                    completionHandler(nil)
                    return
                }

                switch adapterError {
                case .cannotLocateTunnelFileDescriptor:
                    wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                    completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                case .dnsResolution(let dnsErrors):
                    let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                        .joined(separator: ", ")
                    wg_log(.error, message:
                            "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                    errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                    completionHandler(PacketTunnelProviderError.dnsResolutionFailure)
                case .setNetworkSettings(let error):
                    wg_log(.error, message:
                            "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                    completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)
                case .startWireGuardBackend(let errorCode):
                    wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                    completionHandler(PacketTunnelProviderError.couldNotStartBackend)
                case .invalidState:
                    fatalError()
                }
            }
        } catch {
            wg_log(.error, message: "Can't parse WG config: \(String(describing: error))")
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }
    }

    func handleWireguardStatusMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        if let routed = routedAdapter { routed.status(completion: completionHandler); return }
        guard let wgAdapter = wgAdapter else {
            completionHandler(nil)
            return
        }
        wgAdapter.getRuntimeConfiguration { settings in
            guard let settings = settings else {
                completionHandler(nil)
                return
            }
            let components = settings.components(separatedBy: "\n")

            var settingsDictionary: [String: String] = [:]
            for component in components {
                let pair = component.components(separatedBy: "=")
                if pair.count == 2 {
                    settingsDictionary[pair[0]] = pair[1]
                }
            }

            let lastHandshakeString = settingsDictionary["last_handshake_time_sec"]
            let lastHandshake: Int64

            if let lastHandshakeValue = lastHandshakeString, let handshakeValue = Int64(lastHandshakeValue) {
                lastHandshake = handshakeValue
            } else {
                lastHandshake = -2  // Return an error if there is no value for `last_handshake_time_sec`
            }

            let response: [String: Any] = [
                "rx_bytes": settingsDictionary["rx_bytes"] ?? "0",
                "tx_bytes": settingsDictionary["tx_bytes"] ?? "0",
                "last_handshake_time_sec": lastHandshake
            ]

            completionHandler(try? JSONSerialization.data(withJSONObject: response, options: []))
        }
    }

    func handleWireguardAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        // Routed sessions are replaced as a whole; never reinterpret legacy
        // UAPI updates as a destination-rule update or start another reader.
        if routedAdapter != nil { completionHandler(nil); return }
        if messageData.count == 1 && messageData[0] == 0 {
            wgAdapter?.getRuntimeConfiguration { settings in
                var data: Data?
                if let settings {
                    data = settings.data(using: .utf8)!
                }
                completionHandler(data)
            }
        } else if messageData.count >= 1 {
            // Updates the tunnel configuration and responds with the active configuration
            wg_log(.info, message: "Switching tunnel configuration")
            guard let configString = String(data: messageData, encoding: .utf8)
            else {
                completionHandler(nil)
                return
            }

            do {
                let tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: configString)
                wireguardRefreshQueue.async { [weak self] in
                    guard let self, !self.wireguardEndpointStopped, let adapter = self.wgAdapter else {
                        completionHandler(nil)
                        return
                    }
                    self.wireguardRefreshWork?.cancel()
                    let token = self.wireguardRefreshPolicy.begin()
                    // Stage the latest requested profile before yielding to the
                    // adapter: a simultaneous path change must use these keys
                    // and routes, even while the adapter's update is pending.
                    self.wireguardOriginalConfiguration = tunnelConfiguration
                    self.wireguardCandidates.removeAll()
                    adapter.update(tunnelConfiguration: tunnelConfiguration) { [weak self] error in
                        self?.wireguardRefreshQueue.async { [weak self] in
                            guard let self, !self.wireguardEndpointStopped,
                                  self.wireguardRefreshPolicy.accepts(token), error == nil else {
                                completionHandler(nil)
                                return
                            }
                            // A later network change must preserve the most
                            // recent user-supplied keys/routes, not undo them.
                            self.wireguardOriginalConfiguration = tunnelConfiguration
                            self.startWireguardEndpointWatchdog()
                            adapter.getRuntimeConfiguration { settings in
                                completionHandler(settings?.data(using: .utf8))
                            }
                        }
                    }
                }
            } catch {
                completionHandler(nil)
            }
        } else {
            completionHandler(nil)
        }
    }

    func startWireguardEndpointWatchdog() {
        wireguardRefreshQueue.async { [weak self] in
            guard let self, !self.wireguardEndpointStopped,
                  let configuration = self.wireguardOriginalConfiguration else { return }
            let hasDomain = configuration.peers.contains { peer in
                if let endpoint = peer.endpoint, case .name = endpoint.host { return true }
                return false
            }
            guard hasDomain else { return }
            self.wireguardHealthTimer?.cancel()
            self.wireguardHealthGeneration &+= 1
            let generation = self.wireguardHealthGeneration
            self.wireguardStatsInFlight = false
            self.wireguardHealth = EndpointHealthPolicy(staleMs: self.wireguardHealthBudget)
            let timer = DispatchSource.makeTimerSource(queue: self.wireguardRefreshQueue)
            timer.schedule(deadline: .now() + 5, repeating: 5, leeway: .milliseconds(500))
            timer.setEventHandler { [weak self] in
                guard let self, !self.wireguardEndpointStopped, generation == self.wireguardHealthGeneration,
                      !self.wireguardStatsInFlight, let adapter = self.wgAdapter else { return }
                self.wireguardStatsInFlight = true
                adapter.getRuntimeConfiguration { [weak self] text in
                    self?.wireguardRefreshQueue.async { [weak self] in
                        guard let self, generation == self.wireguardHealthGeneration else { return }
                        self.wireguardStatsInFlight = false
                        guard !self.wireguardEndpointStopped else { return }
                        var values = [String: String]()
                        for line in (text ?? "").split(separator: "\n") {
                            let pair = line.split(separator: "=", maxSplits: 1)
                            if pair.count == 2 { values[String(pair[0])] = String(pair[1]) }
                        }
                        // The vendor resolved the initial legacy activation.
                        // Seed its actual numeric endpoint so the first watchdog
                        // retry can move straight to another answer.
                        if configuration.peers.count == 1, let text = values["endpoint"], let endpoint = Endpoint(from: text) {
                            let candidates = self.wireguardCandidates[0] ?? EndpointAddressCandidates()
                            switch endpoint.host {
                            case .ipv4(let address): candidates.record(String(describing: address))
                            case .ipv6(let address): candidates.record(String(describing: address))
                            default: break
                            }
                            self.wireguardCandidates[0] = candidates
                        }
                        self.wireguardHealth.staleMs = max(self.wireguardHealth.staleMs,
                            EndpointHealthPolicy.staleBudget(rekey: values["rekey_after_time"], reject: values["reject_after_time"]))
                        let action = self.wireguardHealth.sample(backend: text == nil ? 1 : 0,
                            handshake: Int64(values["last_handshake_time_sec"] ?? "0") ?? 0,
                            tx: UInt64(values["tx_bytes"] ?? "0") ?? 0, rx: UInt64(values["rx_bytes"] ?? "0") ?? 0,
                            now: Int64(ProcessInfo.processInfo.systemUptime * 1000))
                        switch action {
                        case .none: break
                        case .refresh: self.refreshWireguardEndpoint()
                        case .exhausted:
                            self.wireguardHealthTimer?.cancel()
                            self.wireguardHealthTimer = nil
                            self.reasserting = false
                            self.cancelTunnelWithError(PacketTunnelProviderError.dnsResolutionFailure)
                        }
                    }
                }
            }
            self.wireguardHealthTimer = timer
            timer.resume()
        }
    }

    func refreshWireguardEndpoint() {
        wireguardRefreshQueue.async { [weak self] in
            guard let self, !self.wireguardEndpointStopped,
                  let configuration = self.wireguardOriginalConfiguration else { return }
            let hasDomain = configuration.peers.contains { peer in
                if let endpoint = peer.endpoint, case .name = endpoint.host { return true }
                return false
            }
            guard hasDomain else { return }
            self.wireguardRefreshWork?.cancel()
            let token = self.wireguardRefreshPolicy.begin()
            self.reasserting = true
            self.updateWireguardEndpoint(configuration: configuration, token: token)
        }
    }

    private func updateWireguardEndpoint(configuration: TunnelConfiguration, token: UInt64) {
        guard !wireguardEndpointStopped, wireguardRefreshPolicy.accepts(token), let adapter = wgAdapter else { return }
        guard let delay = wireguardRefreshPolicy.nextDelay(for: token) else {
            reasserting = false
            cancelTunnelWithError(PacketTunnelProviderError.dnsResolutionFailure)
            return
        }
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.wireguardEndpointStopped, self.wireguardRefreshPolicy.accepts(token) else { return }
            self.wireguardLookupGeneration &+= 1
            let lookup = self.wireguardLookupGeneration
            let deadline = DispatchWorkItem { [weak self] in
                guard let self, !self.wireguardEndpointStopped, self.wireguardRefreshPolicy.accepts(token),
                      self.wireguardLookupGeneration == lookup else { return }
                self.wireguardLookupGeneration &+= 1
                self.updateWireguardEndpoint(configuration: configuration, token: token)
            }
            self.wireguardRefreshWork = deadline
            self.wireguardRefreshQueue.asyncAfter(deadline: .now() + 15, execute: deadline)
            // Resolve outside the lifetime queue. Only the accepted result is
            // allowed to consume candidates or update the vendor adapter.
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let result = Result { try configuration.peers.map { peer -> [String]? in
                    guard let endpoint = peer.endpoint, case .name(let hostname, _) = endpoint.host else { return nil }
                    return try EndpointAddressResolver.addresses(hostname)
                } }
                self?.wireguardRefreshQueue.async { [weak self] in
                    guard let self, !self.wireguardEndpointStopped, self.wireguardRefreshPolicy.accepts(token),
                          self.wireguardLookupGeneration == lookup else { return }
                    self.wireguardRefreshWork?.cancel()
                    self.wireguardLookupGeneration &+= 1
                    guard case .success(let answers) = result else {
                        self.updateWireguardEndpoint(configuration: configuration, token: token); return
                    }
                    var peers = configuration.peers
                    for index in peers.indices {
                        guard let addresses = answers[index], let endpoint = peers[index].endpoint else { continue }
                        let candidates = self.wireguardCandidates[index] ?? EndpointAddressCandidates()
                        self.wireguardCandidates[index] = candidates
                        guard let host = candidates.select(addresses),
                              let numeric = Endpoint(from: host.contains(":") ? "[\(host)]:\(endpoint.port)" : "\(host):\(endpoint.port)") else {
                            self.updateWireguardEndpoint(configuration: configuration, token: token); return
                        }
                        peers[index].endpoint = numeric
                    }
                    let activation = TunnelConfiguration(name: configuration.name, interface: configuration.interface, peers: peers)
                    adapter.update(tunnelConfiguration: activation) { [weak self] error in
                        self?.wireguardRefreshQueue.async { [weak self] in
                            guard let self, !self.wireguardEndpointStopped, self.wireguardRefreshPolicy.accepts(token) else { return }
                            if error == nil { self.reasserting = false }
                            else { self.updateWireguardEndpoint(configuration: configuration, token: token) }
                        }
                    }
                }
            }
        }
        wireguardRefreshWork = work
        wireguardRefreshQueue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    func stopWireguard(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wireguardRefreshQueue.sync {
            wireguardEndpointStopped = true
            wireguardHealthGeneration &+= 1
            wireguardHealthTimer?.cancel()
            wireguardHealthTimer = nil
            wireguardRefreshPolicy.cancel()
            wireguardRefreshWork?.cancel()
            wireguardOriginalConfiguration = nil
            reasserting = false
        }
        if let routed = routedAdapter {
            routedAdapter = nil
            routed.stop(completion: completionHandler)
            return
        }
        wg_log(.info, message: "Stopping tunnel: reason: \(reason.amneziaDescription)")

        wgAdapter?.stop { error in
            ErrorNotifier.removeLastErrorFile()

            if let error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            completionHandler()

#if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
#endif
        }
    }
}
