import Foundation
import Darwin

// Ask the kernel for the selected route to the original numeric DNS server.
// This sends a local routing-socket request, not a DNS/network probe. Native
// owners must map the returned index to an explicit tunnel/underlay interface;
// unknown or unavailable interfaces are errors, never a default-path fallback.
enum NativeDNSRoute {
    enum LookupError: Error { case unavailable, invalidResponse }

    static func interfaceIndex(server: String) throws -> UInt32 {
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_addr = try NativeDNSResolver.validateIPv4Server(server)
        let fd = socket(PF_ROUTE, SOCK_RAW, AF_INET)
        guard fd >= 0 else { throw LookupError.unavailable }
        defer { close(fd) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw LookupError.unavailable }
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + MemoryLayout<sockaddr_in>.size)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_addrs = RTA_DST
        header.rtm_pid = getpid()
        header.rtm_seq = Int32.random(in: 1...Int32.max)
        var request = withUnsafeBytes(of: &header) { Data($0) }
        withUnsafeBytes(of: &destination) { request.append(contentsOf: $0) }
        let sent = request.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        guard sent == request.count else { throw LookupError.unavailable }
        let deadline = DispatchTime.now() + .milliseconds(250)
        var bytes = [UInt8](repeating: 0, count: 8192)
        while DispatchTime.now() < deadline {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline.uptimeNanoseconds else { break }
            let remaining = Int32(max(1, (deadline.uptimeNanoseconds - now) / 1_000_000))
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, remaining)
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, descriptor.revents & Int16(POLLIN) != 0 else { throw LookupError.unavailable }
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            guard count >= MemoryLayout<rt_msghdr>.size else { throw LookupError.invalidResponse }
            var reply = rt_msghdr()
            withUnsafeMutableBytes(of: &reply) { target in
                bytes.withUnsafeBytes { source in
                    target.copyMemory(from: UnsafeRawBufferPointer(rebasing: source.prefix(target.count)))
                }
            }
            guard reply.rtm_pid == header.rtm_pid, reply.rtm_seq == header.rtm_seq else { continue }
            guard reply.rtm_version == UInt8(RTM_VERSION), reply.rtm_type == UInt8(RTM_GET),
                  Int(reply.rtm_msglen) <= count, Int(reply.rtm_msglen) >= MemoryLayout<rt_msghdr>.size,
                  reply.rtm_errno == 0, reply.rtm_index > 0,
                  reply.rtm_flags & (RTF_REJECT | RTF_BLACKHOLE) == 0 else {
                throw LookupError.unavailable
            }
            return UInt32(reply.rtm_index)
        }
        throw LookupError.unavailable
    }

    static func interfaceOwnsIPv4(index: UInt32, addresses: [String]) -> Bool {
        var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        guard if_indextoname(index, &name) != nil else { return false }
        let expected = String(cString: name)
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return false }
        defer { freeifaddrs(first) }
        var current = first
        while let entry = current {
            defer { current = entry.pointee.ifa_next }
            guard String(cString: entry.pointee.ifa_name) == expected,
                  let address = entry.pointee.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let value = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            var copy = value
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &copy, &text, socklen_t(text.count)) != nil,
               addresses.contains(String(cString: text)) { return true }
        }
        return false
    }
}
