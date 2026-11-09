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
            require(!result.has("sing_box_routing")) { "Legacy AWG cannot enforce domain routing" }
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
                if (prefixes.none { it.isIpv6 } && !data.optString("client_ip").contains(':'))
                    rules.put(JSONObject().put("kind", "cidr").put("value", "::/0").put("action", "block"))
            }
            result.put("sing_box_routing", JSONObject().put("version", 1)
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
            val routing = result.getJSONObject("sing_box_routing")
            var direct = routing.optString("default") == "direct"
            val rules = routing.optJSONArray("rules") ?: JSONArray()
            for (index in 0 until rules.length()) {
                val row = rules.getJSONObject(index)
                if (!row.optBoolean("disabled") && row.optString("action") == "direct" &&
                    row.optString("kind") in setOf("domain", "suffix") &&
                    row.optString("ports").isBlank() && row.optString("network").isBlank()) direct = true
            }
            val policies = JSONObject().put("vpn", JSONObject().put("transport", "udp")
                .put("server", server).put("path", "vpn"))
            val dns = JSONObject().put("version", 1).put("default", "vpn")
                .put("follow_routing", direct).put("policies", policies).put("rules", JSONArray())
            if (direct) {
                policies.put("direct", JSONObject().put("source", "network").put("path", "direct").put("transport", "udp"))
                dns.put("direct", "direct").put("vpn", "vpn")
            }
            result.put("sing_box_dns", dns)
        }
        return result
    }

    fun allTrafficUsesVpn(config: JSONObject): Boolean {
        val route = config.optJSONObject("sing_box_routing") ?: return false
        if (route.optString("default") != "vpn") return false
        val rules = route.optJSONArray("rules") ?: JSONArray()
        return (0 until rules.length()).none {
            val row = rules.getJSONObject(it)
            !row.optBoolean("disabled") && row.optString("action") == "direct"
        }
    }

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
