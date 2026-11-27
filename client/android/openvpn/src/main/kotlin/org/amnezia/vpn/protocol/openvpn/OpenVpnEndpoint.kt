package org.amnezia.vpn.protocol.openvpn

import java.net.InetAddress
import org.amnezia.vpn.protocol.BadConfigException

/** Numeric proof BEFORE any platform/native bootstrap resolver can run. */
internal fun openVpnIpv4Endpoint(text: String): InetAddress {
    val parts = text.split('.')
    if (parts.size != 4 || parts.any {
            it.isEmpty() || !it.all(Char::isDigit) ||
                it.toIntOrNull()?.let { number -> number !in 0..255 || number.toString() != it } != false
        }) throw BadConfigException("IPv6 OFF OpenVPN bootstrap requires its original numeric IPv4 endpoint")
    val address = InetAddress.getByAddress(parts.map { it.toInt().toByte() }.toByteArray())
    if (address.isAnyLocalAddress || address.isMulticastAddress)
        throw BadConfigException("Invalid OpenVPN bootstrap endpoint")
    return address
}
