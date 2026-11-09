package org.amnezia.vpn.util.net

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AwgCorePolicyTest {
    private fun profile(): JSONObject = JSONObject("""{"protocol":"awg","dns1":"10.77.0.2","appSplitTunnelType":1,"splitTunnelType":0,"appSplitTunnelApps":["org.telegram.messenger"],"awg_config_data":{"allowed_ips":["0.0.0.0/0"],"client_priv_key":"keep-me","mtu":"1380","PersistentKeepalive":"25"}}""")
    @Test fun ordinaryAppOnlyAwgUsesSharedCoreAndVpnDnsWithoutSiteFlag() {
        val input = profile(); val original = input.toString()
        val result = AwgCorePolicy.prepare(input)
        val route = result.getJSONObject("sing_box_routing")
        assertEquals("vpn", route.getString("default"));assertEquals(0, route.getJSONArray("rules").length())
        val dns = result.getJSONObject("sing_box_dns")
        assertEquals("vpn", dns.getString("default"));assertFalse(dns.getBoolean("follow_routing"))
        assertEquals("vpn", dns.getJSONObject("policies").getJSONObject("vpn").getString("path"))
        assertEquals(input.getJSONArray("appSplitTunnelApps").toString(), result.getJSONArray("appSplitTunnelApps").toString())
        assertEquals(input.getJSONObject("awg_config_data").toString(), result.getJSONObject("awg_config_data").toString())
        assertEquals(original, input.toString());assertTrue(AwgCorePolicy.lockdownSafe(result))
    }
    @Test fun explicitLegacyOverrideDoesNotSilentlyDiscardRequestedDomainRules() {
        val input = profile().put("android_legacy_awg_backend", true)
        assertFalse(AwgCorePolicy.prepare(input).has("sing_box_routing"))
        input.put("sing_box_routing", JSONObject().put("version", 1).put("default", "vpn"))
        try { AwgCorePolicy.prepare(input);fail("domain policy was silently discarded") }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun legacyDestinationIncludeAndExcludeKeepTheirSemantics() {
        for (mode in 1..2) {
            val input = profile().put("splitTunnelType", mode).put("splitTunnelSites", JSONArray().put("192.0.2.5"))
            val result = AwgCorePolicy.prepare(input)
            val routing = result.getJSONObject("sing_box_routing")
            assertEquals(if (mode == 1) "direct" else "vpn", routing.getString("default"))
            val rule = routing.getJSONArray("rules").getJSONObject(0)
            assertEquals("cidr", rule.getString("kind"));assertEquals("192.0.2.5/32", rule.getString("value"))
            assertEquals(if (mode == 1) "vpn" else "direct", rule.getString("action"))
            assertFalse(AwgCorePolicy.lockdownSafe(result))
            assertEquals("vpn", result.getJSONObject("sing_box_dns").getJSONObject("policies").getJSONObject("vpn").getString("path"))
        }
    }
    @Test fun lockdownRejectsDirectTrafficAndPhysicalDnsButAllowsVpnAndBlock() {
        val result = AwgCorePolicy.prepare(profile())
        result.getJSONObject("sing_box_routing").getJSONArray("rules")
            .put(JSONObject().put("kind", "domain").put("value", "blocked.test").put("action", "block"))
        assertTrue(AwgCorePolicy.lockdownSafe(result))
        result.getJSONObject("sing_box_dns").getJSONObject("policies").getJSONObject("vpn").put("path", "direct")
        assertFalse(AwgCorePolicy.lockdownSafe(result))
    }
    @Test fun wireguardUsesSameDefaultAndOtherProtocolsAreUnchanged() {
        val wg = profile().let { it.put("protocol", "wireguard").put("wireguard_config_data", it.getJSONObject("awg_config_data")) }
        assertTrue(AwgCorePolicy.prepare(wg).has("sing_box_routing"))
        val other = JSONObject("""{"protocol":"openvpn","dns1":"192.0.2.53"}""")
        assertEquals(other.toString(), AwgCorePolicy.prepare(other).toString())
    }
    @Test fun restrictedAllowedIpsKeepNativeDestinationsAndExplicitProfileDns() {
        val input = profile()
        input.getJSONObject("awg_config_data").put("allowed_ips", JSONArray().put("10.0.0.0/8"))
        val result = AwgCorePolicy.prepare(input)
        assertEquals("direct", result.getJSONObject("sing_box_routing").getString("default"))
        assertEquals(2, result.getJSONObject("sing_box_routing").getInt("version"))
        assertEquals("vpn", result.getJSONObject("sing_box_dns").getJSONObject("policies").getJSONObject("profile").getString("path"))
        input.put("dns1", "192.0.2.53")
        val nativeDns = AwgCorePolicy.prepare(input).getJSONObject("sing_box_dns").getJSONObject("policies").getJSONObject("profile")
        assertEquals("direct", nativeDns.getString("path"));assertEquals("192.0.2.53", nativeDns.getString("server"))
    }

    @Test fun wireguardExtensionsRetainTheirOriginalDeviceFormat() {
        assertEquals("wireguard", AwgCorePolicy.transportAdapter("wireguard", false))
        assertEquals("awg", AwgCorePolicy.transportAdapter("wireguard", true))
        assertEquals("awg", AwgCorePolicy.transportAdapter("awg", false))
    }

    @Test fun ipv6OnlyProfileDoesNotGainImplicitNativeIpv4Bypass() {
        val input = profile().put("dns1", "fd77::53")
        input.getJSONObject("awg_config_data").put("client_ip", "fd77::1/128")
            .put("allowed_ips", JSONArray().put("::/0"))
        val result = AwgCorePolicy.prepare(input)
        val rules = result.getJSONObject("sing_box_routing").getJSONArray("rules")
        assertTrue((0 until rules.length()).any { rules.getJSONObject(it).optString("value") == "0.0.0.0/0" && rules.getJSONObject(it).optString("action") == "block" })
    }

    @Test fun unavailableAndroid9LockdownQueryCannotEnableProtectedDirectBypass() {
        val safe = AwgCorePolicy.prepare(profile())
        assertTrue(AwgCorePolicy.platformSafe(28, false, safe))
        assertTrue(AwgCorePolicy.platformSafe(35, true, safe))
        safe.getJSONObject("sing_box_routing").put("default", "direct")
        assertFalse(AwgCorePolicy.platformSafe(28, false, safe))
        assertFalse(AwgCorePolicy.platformSafe(35, true, safe))
        assertTrue(AwgCorePolicy.platformSafe(35, false, safe))
    }

}
