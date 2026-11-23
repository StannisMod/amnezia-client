import Darwin
import Foundation
import NetworkExtension

enum XrayErrors: Error {
    case noXrayConfig
    case xrayConfigIsWrong
    case cantSaveXrayConfig
    case cantParseListenAndPort
    case cantAcquireLocalPort
    case cantSaveHevSocksConfig
    case stopped
    case nativeStartFailed
}

extension Constants {
    static let cachesDirectory: URL = {
        if let cachesDirectoryURL = FileManager.default.urls(for: .cachesDirectory,
                                                             in: .userDomainMask).first {
            return cachesDirectoryURL
        } else {
            fatalError("Unable to retrieve caches directory.")
        }
    }()
}

extension PacketTunnelProvider {
    /// TCP port chosen by the OS on IPv6 loopback (::1), matching inbound listen address.
    private func acquireFreeLocalPort() throws -> Int {
        let fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        guard fd != -1 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        defer { close(fd) }
        var reuse: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = in_port_t(0).bigEndian
        addr.sin6_addr = in6addr_loopback
        addr.sin6_scope_id = 0
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { p in
                bind(fd, p, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        var bound = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let gr = withUnsafeMutablePointer(to: &bound) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bp in
                getsockname(fd, bp, &len)
            }
        }
        guard gr == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        return Int(bound.sin6_port.byteSwapped)
    }

    private func applyXraySplitTunnel(_ xrayConfig: XrayConfig,
                                      settings: NEPacketTunnelNetworkSettings) {
        guard let splitTunnelType = xrayConfig.splitTunnelType else {
            return
        }

        guard let splitTunnelSites = xrayConfig.splitTunnelSites else {
            xrayLog(.error, message: "Split tunnel sites are not set")
            return
        }

        let routes = splitTunnelSites.compactMap { site -> XrayRoute? in
            guard let range = IPAddressRange(from: site) else { return nil }
            return XrayRoute(address: "\(range.address)", prefixLength: Int(range.networkPrefixLength))
        }
        if !XrayNetworkSettings.applySplit(type: splitTunnelType, routes: routes, to: settings) {
            xrayLog(.error, message: "Invalid Xray route prefix")
        }
    }

    func startXray(completionHandler: @escaping (Error?) -> Void) {
        enqueueXrayStart(expectedGeneration: nil, completionHandler: completionHandler)
    }

    private func enqueueXrayStart(expectedGeneration: UInt64?, completionHandler: @escaping (Error?) -> Void) {
        xrayLifecycleQueue.async {
            if let expectedGeneration, self.xrayGeneration != expectedGeneration {
                completionHandler(XrayErrors.stopped)
                return
            }
            guard !self.xrayClosing, !self.xrayActive else {
                completionHandler(NativeTunnelRunner.RunError.alreadyRunning)
                return
            }
            self.xrayGeneration &+= 1
            self.xrayActive = true
            self.xrayReady = false
            let generation = self.xrayGeneration
            self.startXraySession(generation: generation) { error in
                self.xrayLifecycleQueue.async {
                    guard self.xrayGeneration == generation else {
                        completionHandler(XrayErrors.stopped)
                        return
                    }
                    if let error {
                        self.stopXray { completionHandler(error) }
                    } else {
                        self.xrayReady = true
                        completionHandler(nil)
                    }
                }
            }
        }
    }

    private func startXraySession(generation: UInt64, completionHandler: @escaping (Error?) -> Void) {
        // Xray configuration
        guard let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration,
              let configData = providerConfiguration[Constants.xrayConfigKey] as? Data else {
            xrayLog(.error, message: "Can't get xray configuration")
            completionHandler(XrayErrors.noXrayConfig)
            return
        }

        let settings = XrayNetworkSettings.make()

        do {
            let xrayConfig = try JSONDecoder().decode(XrayConfig.self,
                                                      from: configData)

            var dnsArray = [String]()
            if let dns1 = xrayConfig.dns1 {
                dnsArray.append(dns1)
            }
            if let dns2 = xrayConfig.dns2 {
                dnsArray.append(dns2)
            }

            settings.dnsSettings = !dnsArray.isEmpty
            ? NEDNSSettings(servers: dnsArray)
            : NEDNSSettings(servers: ["1.1.1.1"])
            applyXraySplitTunnel(xrayConfig, settings: settings)
            if xrayConfig.ipv6Enabled == false {
                // Keep capture while the connection-local Xray policy rejects
                // IPv6. Dropping the routes would leak through the native NIC.
                settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
                settings.ipv6Settings?.excludedRoutes = []
            }

            let xrayConfigData = xrayConfig.config.data(using: .utf8)

            guard let xrayConfigData else {
                xrayLog(.error, message: "Can't encode config to data")
                completionHandler(XrayErrors.xrayConfigIsWrong)
                return
            }

            let jsonDict = try JSONSerialization.jsonObject(with: xrayConfigData,
                                                            options: []) as? [String: Any]

            guard var jsonDict else {
                xrayLog(.error, message: "Can't parse address and port for hevSocks")
                completionHandler(XrayErrors.cantParseListenAndPort)
                return
            }

            let port = try acquireFreeLocalPort()
            let address = "::1"

            // Extract existing SOCKS5 credentials or generate new ones per session.
            let socksCredentials = ensureInboundAuth(jsonDict: &jsonDict, port: port, address: address)

            let updatedData = try JSONSerialization.data(withJSONObject: jsonDict, options: [])

            let blocked = xrayConfig.ipv6Enabled == false
            if blocked {
                let controller = nativeXrayDNS
                nativeXrayDNSFilter = try NativeDNSPacketFilter(filter: { controller.intercept($0) })
                controller.start()
            }
            let applySettings: (@escaping (Error?) -> Void) -> Void = { done in
                if blocked {
                    self.applyNativeDNS(self.nativeXrayDNS, settings: settings, blocked: true,
                        publish: { prepared, published in
                            self.xrayLifecycleQueue.async {
                                guard self.xrayGeneration == generation, !self.xrayClosing else {
                                    published(XrayErrors.stopped)
                                    return
                                }
                                self.setTunnelNetworkSettings(prepared, completionHandler: published)
                            }
                        }, completion: done)
                } else {
                    self.setTunnelNetworkSettings(settings, completionHandler: done)
                }
            }
            applySettings { [weak self] error in
                guard let self else { completionHandler(XrayErrors.stopped); return }
                self.xrayLifecycleQueue.async {
                    guard self.xrayGeneration == generation, !self.xrayClosing else {
                        completionHandler(XrayErrors.stopped)
                        return
                    }
                    if let error {
                        completionHandler(error)
                        return
                    }
                    self.updateActiveInterfaceIndexForCurrentPath()
                    do {
                        try self.nativeXraySockets.start(index: self.nativeXrayScopeIndex(),
                                                        blockIPv6: xrayConfig.ipv6Enabled == false)
                    } catch {
                        completionHandler(error)
                        return
                    }
                    self.setupAndStartXray(configData: updatedData) { xrayError in
                        if let xrayError {
                            completionHandler(xrayError)
                            return
                        }

                        self.setupAndRunTun2socks(configData: updatedData, address: address, port: port,
                            filterNativeDNS: blocked,
                            username: socksCredentials.username, password: socksCredentials.password,
                            completionHandler: { error in
                            self.xrayLifecycleQueue.async {
                                guard self.xrayGeneration == generation, !self.xrayClosing else {
                                    completionHandler(XrayErrors.stopped)
                                    return
                                }
                                completionHandler(error)
                            }
                        }, exited: { error in
                            self.xrayLifecycleQueue.async {
                                if let error, self.xrayGeneration == generation, !self.xrayClosing {
                                    self.stopXray { self.cancelTunnelWithError(error) }
                                }
                            }
                        })
                    }
                }
            }
        } catch {
            completionHandler(error)
            return
        }
    }

    func stopXray(completionHandler: @escaping () -> Void) {
        stopXrayRequest(forRestart: false) { _ in completionHandler() }
    }

    func restartXray(completionHandler: @escaping (Error?) -> Void) {
        stopXrayRequest(forRestart: true) { [weak self] generation in
            guard let self, let generation else { completionHandler(XrayErrors.stopped); return }
            self.enqueueXrayStart(expectedGeneration: generation, completionHandler: completionHandler)
        }
    }

    private func stopXrayRequest(forRestart: Bool, completionHandler: @escaping (UInt64?) -> Void) {
        xrayLifecycleQueue.async {
            if forRestart && (!self.xrayReady || self.xrayClosing) {
                completionHandler(nil)
                return
            }
            self.xrayGeneration &+= 1
            self.xrayReady = false
            let generation = self.xrayGeneration
            let completed = { completionHandler(generation) }
            guard self.xrayActive || self.xrayClosing else { completed(); return }
            self.xrayStopWaiters.append(completed)
            guard !self.xrayClosing else { return }
            self.xrayClosing = true
            self.nativeXrayDNS.stop {
                Socks5Tunnel.quit {
                    self.xrayLifecycleQueue.async {
                        let result = LibXrayStopXray()
                        free(result)
                        self.nativeXrayDNSFilter?.stop()
                        self.nativeXrayDNSFilter = nil
                        self.nativeXraySockets.stop()
                        self.xrayActive = false
                        self.xrayClosing = false
                        let completions = self.xrayStopWaiters
                        self.xrayStopWaiters.removeAll()
                        for completion in completions { completion() }
                    }
                }
            }
        }
    }

    private struct SocksCredentials {
        let username: String
        let password: String
    }

    private func indexOfSocksInbound(in inboundsArray: [[String: Any]]) -> Int? {
        for (i, inbound) in inboundsArray.enumerated() {
            guard let proto = inbound["protocol"] as? String else { continue }
            if proto.caseInsensitiveCompare("socks") == .orderedSame {
                return i
            }
        }
        return nil
    }

    // Returns existing SOCKS5 credentials from the inbound config, or generates and injects
    // new random ones. Also sets port and address on the socks inbound entry.
    private func ensureInboundAuth(jsonDict: inout [String: Any], port: Int, address: String) -> SocksCredentials {
        var inboundsArray = jsonDict["inbounds"] as? [[String: Any]] ?? []

        if let socksIdx = indexOfSocksInbound(in: inboundsArray) {
            var inbound = inboundsArray[socksIdx]
            inbound["port"] = port
            inbound["listen"] = address

            var settings = inbound["settings"] as? [String: Any] ?? [:]
            if let accounts = settings["accounts"] as? [[String: Any]],
               let first = accounts.first,
               let user = first["user"] as? String, !user.isEmpty,
               let pass = first["pass"] as? String, !pass.isEmpty {
                // Re-use existing credentials, but always enforce auth mode in case the
                // imported config had accounts but auth: "noauth" (or no auth field).
                settings["auth"] = "password"
                inbound["settings"] = settings
                inboundsArray[socksIdx] = inbound
                jsonDict["inbounds"] = inboundsArray
                return SocksCredentials(username: user, password: pass)
            }

            // Generate new random credentials for this session
            let user = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)
            let pass = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            settings["auth"] = "password"
            settings["accounts"] = [["user": String(user), "pass": pass]]
            inbound["settings"] = settings
            inboundsArray[socksIdx] = inbound
            jsonDict["inbounds"] = inboundsArray
            return SocksCredentials(username: String(user), password: pass)
        }

        // Fallback: no socks inbound — generate credentials but can't inject
        let user = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)
        let pass = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return SocksCredentials(username: String(user), password: pass)
    }

    private func setupAndStartXray(configData: Data,
                                   completionHandler: @escaping (Error?) -> Void) {
        let path = Constants.cachesDirectory.appendingPathComponent("config.json", isDirectory: false).path
        guard FileManager.default.createFile(atPath: path, contents: configData) else {
            xrayLog(.error, message: "Can't save xray configuration")
            completionHandler(XrayErrors.cantSaveXrayConfig)
            return
        }

        updateActiveInterfaceIndexForCurrentPath()

        // nodep.WrapError returns an owned empty string on success and an
        // owned error string otherwise. Never report failed startup as ready.
        let result = LibXrayRunXray(nil, path, Int64.max)
        defer { free(result) }
        guard let result, result.pointee == 0 else {
            completionHandler(XrayErrors.nativeStartFailed)
            return
        }

        completionHandler(nil)
        xrayLog(.info, message: "Xray started")
    }

    private func hevSocksLogFile() -> String {
        guard Log.isLoggingEnabled else { return "stderr" }

        let path = Log.neLogURL.path
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0o644)
        guard fd >= 0 else { return "stderr" }
        close(fd)
        return path
    }

    private func setupAndRunTun2socks(configData: Data,
                                      address: String,
                                      port: Int,
                                      filterNativeDNS: Bool,
                                      username: String,
                                       password: String,
                                       completionHandler: @escaping (Error?) -> Void,
                                       exited: @escaping (Error?) -> Void) {
        let config = """
        tunnel:
          mtu: 9000
        socks5:
          port: \(port)
          address: \(address)
          username: \(username)
          password: \(password)
          udp: 'udp'
        misc:
          task-stack-size: 20480
          connect-timeout: 5000
          read-write-timeout: 60000
          log-file: '\(hevSocksLogFile())'
          log-level: warn
          limit-nofile: 65535
        """

        let configurationFilePath = Constants.cachesDirectory.appendingPathComponent("config.yml", isDirectory: false).path
        guard FileManager.default.createFile(atPath: configurationFilePath, contents: config.data(using: .utf8)!) else {
            xrayLog(.info, message: "Cant save hevSocks configuration")
            completionHandler(XrayErrors.cantSaveHevSocksConfig)
            return
        }

        Socks5Tunnel.start(withConfig: configurationFilePath, filterNativeDNS: filterNativeDNS,
                          started: completionHandler, exited: exited)
    }
}
