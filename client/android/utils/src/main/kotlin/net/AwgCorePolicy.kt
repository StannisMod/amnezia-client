package org.amnezia.vpn.util.net

import org.json.JSONArray
import org.json.JSONObject

/** Backend selection is independent of the optional domain-rule editor. */
object AwgCorePolicy {
    fun prepare(input: JSONObject): JSONObject {
        val result = JSONObject(input.toString())
        if (result.optString("protocol") !in setOf("awg", "wireguard")) return result
        // Explicit diagnostic override, never an automatic failed-start fallback.
        if (result.optBoolean("android_legacy_awg_backend", false)) {
            require(!result.has("sing_box_routing") && !result.has("sing_box_dns") && !result.has("android_app_routing")) { "Legacy AWG cannot enforce shared routing or DNS policies" }
            return result
        }
        if (!result.has("sing_box_routing")) {
            val data = result.getJSONObject(result.getString("protocol") + "_config_data")
            val allowed = data.getJSONArray("allowed_ips")
            require(allowed.length() > 0) { "VPN allowed IPs are missing" }
            val prefixes = (0 until allowed.length()).map { InetNetwork.parse(allowed.getString(it)) }
            val ipv4Default = prefixes.any { it.isIpv4 && it.mask == 0 }
            val ipv6Default = prefixes.any { it.isIpv6 && it.mask == 0 }
            val restricted = !ipv4Default || (prefixes.any { it.isIpv6 } && !ipv6Default)
            val mode = if (restricted) 0 else result.optInt("splitTunnelType", 0)
            val sites = result.optJSONArray("splitTunnelSites") ?: JSONArray()
            require(mode in 0..2) { "Invalid destination split mode" }
            val rules = JSONArray()
            if (mode != 0) for (index in 0 until sites.length()) {
                val value = InetNetwork.parse(sites.getString(index)).toString()
                // Legacy destination lists have already been resolved to IPs.
                InetNetwork.parse(value)
                rules.put(JSONObject().put("kind", "cidr").put("value", value)
                    .put("action", if (mode == 1) "vpn" else "direct"))
            }
            if (restricted) {
                for (prefix in prefixes) rules.put(JSONObject().put("kind", "cidr")
                    .put("value", prefix.toString()).put("action", "vpn"))
                // A profile that never enabled IPv6 must not gain an implicit
                // native IPv6 bypass just because FakeIP capture has a ULA.
                val clientAddresses = data.optString("client_ip").split(',').mapNotNull {
                    it.trim().takeIf { value -> value.isNotBlank() }?.let { value -> InetNetwork.parse(value) }
                }
                if (prefixes.none { it.isIpv4 } && clientAddresses.none { it.isIpv4 })
                    rules.put(JSONObject().put("kind", "cidr").put("value", "0.0.0.0/0").put("action", "block"))
                if (prefixes.none { it.isIpv6 } && !data.optString("client_ip").contains(':'))
                    rules.put(JSONObject().put("kind", "cidr").put("value", "::/0").put("action", "block"))
            }
            result.put("sing_box_routing", JSONObject().put("version", 2)
                .put("default", if (restricted || mode == 1 && rules.length() > 0) "direct" else "vpn")
                .put("rules", rules))
            if (restricted && !result.has("sing_box_dns")) {
                val server = result.optString("dns1").ifBlank { result.optString("dns2") }
                require(server.isNotBlank()) { "VPN DNS resolver is missing" }
                val address = parseInetAddress(server).address
                val viaVpn = prefixes.any { prefix ->
                    val bytes = prefix.address.address
                    if (bytes.size != address.size || prefix.mask !in 0..bytes.size * 8) false else
                        address.indices.all { index ->
                            val bits = (prefix.mask - index * 8).coerceIn(0, 8)
                            val mask = if (bits == 0) 0 else (255 shl (8 - bits)) and 255
                            (address[index].toInt() and mask) == (bytes[index].toInt() and mask)
                        }
                }
                result.put("sing_box_dns", JSONObject().put("version", 1).put("default", "profile")
                    .put("policies", JSONObject().put("profile", JSONObject().put("transport", "udp")
                        .put("server", server).put("path", if (viaVpn) "vpn" else "direct"))).put("rules", JSONArray()))
            }
        }
        if (!result.has("sing_box_dns")) {
            val server = result.optString("dns1").ifBlank { result.optString("dns2") }
            require(server.isNotBlank()) { "VPN DNS resolver is missing" }
            // Existing raw routing profiles without a DNS policy used the
            // selected profile resolver through VPN. The C++ site-rule editor
            // supplies its explicit follow-routing DNS policy separately.
            val path = if (parseInetAddress(server).isLoopbackAddress) "direct"
                else result.optString("sing_box_dns_path", "vpn")
            val policies = JSONObject().put("vpn", JSONObject().put("transport", "udp")
                .put("server", server).put("path", path))
            result.put("sing_box_dns", JSONObject().put("version", 1).put("default", "vpn")
                .put("follow_routing", false).put("policies", policies).put("rules", JSONArray()))
        }
        return result
    }

    fun retainsVpnDns(config: JSONObject): Boolean {
        val dns = config.optJSONObject("sing_box_dns") ?: return false
        if (dns.optBoolean("preserve_network_domains")) return false
        val policies = dns.optJSONObject("policies") ?: return false
        return policies.length() > 0 && policies.keys().asSequence().all {
            val policy = policies.getJSONObject(it)
            policy.optString("source") != "network" && policy.optString("path") == "vpn"
        }
    }

    fun transportAdapter(protocol: String, extensionParameters: Boolean): String {
        require(protocol in setOf("awg", "wireguard"))
        // Imported WireGuard extension profiles used the same AWG device in
        // the original Android backend; keep that wire format and its options.
        return if (protocol == "awg" || extensionParameters) "awg" else "wireguard"
    }

    // API 28 cannot query VPN lockdown. Only policies with no protected
    // application DIRECT/network-DNS path can be enabled safely there.
    fun platformSafe(sdk: Int, lockdown: Boolean, config: JSONObject): Boolean =
        if (sdk < 29 || lockdown) lockdownSafe(config) else true

    /** No application DIRECT or physical DNS socket may bypass Android lockdown. */
    fun lockdownSafe(config: JSONObject): Boolean {
        val routing = config.optJSONObject("sing_box_routing") ?: return false
        if (routing.optString("default") !in setOf("vpn", "block")) return false
        val rules = routing.optJSONArray("rules") ?: JSONArray()
        for (index in 0 until rules.length()) {
            val row = rules.getJSONObject(index)
            if (!row.optBoolean("disabled") && row.optString("action") !in setOf("vpn", "block")) return false
        }
        val dns = config.optJSONObject("sing_box_dns") ?: return false
        val policies = dns.optJSONObject("policies") ?: return false
        for (name in policies.keys()) {
            val policy = policies.getJSONObject(name)
            if (policy.optString("path") != "vpn" || policy.optString("source") == "network") return false
        }
        return true
    }
}
