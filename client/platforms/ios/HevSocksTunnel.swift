import HevSocks5Tunnel
import NetworkExtension
import Foundation

public enum Socks5Tunnel {
    private static let runner = NativeTunnelRunner()

    private static var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    private static var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else {
                return nil
            }
            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize
            )
            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    public static func quit() {
        quit(completion: {})
    }

    public static func start(withConfig path: String, filterNativeDNS: Bool = false,
                             started: @escaping (Error?) -> Void,
                             exited: @escaping (Error?) -> Void) {
        runner.start(run: {
            amnezia_hev_filter_enable(filterNativeDNS ? 1 : 0)
            defer { amnezia_hev_filter_enable(0) }
            guard let fd = tunnelFileDescriptor else { return -1 }
            return hev_socks5_tunnel_main(path.cString(using: .utf8), fd)
        }, quit: { hev_socks5_tunnel_quit() }, started: started, exited: exited)
    }

    public static func quit(completion: @escaping () -> Void) {
        runner.stop(completion: completion)
    }

    static func nativeReady() {
        runner.ready()
    }
}

@_cdecl("amnezia_hev_ready")
func amneziaHevReady() { Socks5Tunnel.nativeReady() }
