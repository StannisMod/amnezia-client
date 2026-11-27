package org.amnezia.vpn.protocol.openvpn

import org.amnezia.vpn.protocol.NativeDnsBinding
import org.amnezia.vpn.protocol.NativeDnsPublication
import org.amnezia.vpn.protocol.NativeDnsScope
import java.util.concurrent.atomic.AtomicReference

/** DIRECT public binding only. Tunnel DNS uses the existing native engine. */
internal class OpenVpnDnsNetwork(
    private val publication: NativeDnsPublication,
    private val strictPrivateDns: () -> Boolean,
    private val admitted: () -> Boolean
) {
    private val tunnel = AtomicReference<PublishedOpenVpnTun?>(null)
    val current: Boolean get() = tunnel.get()?.current() == true
    fun permitTunnel(): Boolean = admitted() && !strictPrivateDns() && current

    fun publish(capture: PublishedOpenVpnTun) {
        check(capture.current()) { "OpenVPN DNS capture generation is no longer current" }
        check(tunnel.compareAndSet(null, capture)) { "OpenVPN DNS capture is already published" }
    }

    fun bind(binding: NativeDnsBinding, fd: Int): Boolean {
        if (fd < 0 || !admitted() || strictPrivateDns()) return false
        return when (binding.scope) {
            NativeDnsScope.IPV6_UNAVAILABLE -> false
            NativeDnsScope.DIRECT ->
                publication.bindDirectSocket(fd) && admitted() && !strictPrivateDns()
            // Android checks the calling UID against VPN application ranges.
            // Never add the provider UID or bypass that check to make DNS work.
            // This scope has no OS socket/bind fallback.
            NativeDnsScope.TUNNEL -> false
        }
    }
}
