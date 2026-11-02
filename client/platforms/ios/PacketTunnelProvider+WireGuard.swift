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
                wireguardEndpointStopped = false
            }

            // Start the tunnel
            wgAdapter = WireGuardAdapter(with: self) { logLevel, message in
                wg_log(logLevel.osLogLevel, message: message)
            }

            wgAdapter?.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
                guard let adapterError else {
                    let interfaceName = self?.wgAdapter?.interfaceName ?? "unknown"
                    wg_log(.info, message: "Tunnel interface is \(interfaceName)")
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
            adapter.update(tunnelConfiguration: configuration) { [weak self] error in
                self?.wireguardRefreshQueue.async { [weak self] in
                    guard let self, !self.wireguardEndpointStopped, self.wireguardRefreshPolicy.accepts(token) else { return }
                    if error == nil { self.reasserting = false }
                    else { self.updateWireguardEndpoint(configuration: configuration, token: token) }
                }
            }
        }
        wireguardRefreshWork = work
        wireguardRefreshQueue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    func stopWireguard(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wireguardRefreshQueue.sync {
            wireguardEndpointStopped = true
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
