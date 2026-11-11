package org.amnezia.vpn.util.net

import org.json.JSONArray
import org.json.JSONObject

/** Resolve persistent package choices at connection time; never persist UIDs. */
object AndroidAppRoutingPolicy {
    fun resolve(profile: JSONObject, api: Int, uidForPackage: (String) -> Int?, packagesForUid: (Int) -> List<String>): JSONObject? {
        val policy = profile.optJSONObject("android_app_routing") ?: return null
        require(api >= 29) { "Per-application site rules require Android 10 or newer" }
        require(policy.getInt("version") == 1) { "Unsupported Android application routing version" }
        require(policy.keys().asSequence().all { it in setOf("version", "site_rule_packages", "vpn_dns_policy") }) { "Unknown Android application routing field" }
        val selected = policy.getJSONArray("site_rule_packages")
        require(selected.length() <= 4096) { "Too many application routing entries" }
        val names = linkedSetOf<String>()
        for (i in 0 until selected.length()) {
            val name = selected.getString(i)
            require(name.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) && names.add(name)) { "Invalid or duplicate application package" }
        }
        val splitMode = profile.optInt("appSplitTunnelType", 0)
        require(splitMode in 0..2) { "Invalid application split mode" }
        val scoped = profile.optJSONArray("splitTunnelApps") ?: JSONArray()
        val scope = (0 until scoped.length()).map { scoped.getString(it) }.toSet()
        fun captured(name: String) = when (splitMode) { 1 -> name in scope; 2 -> name !in scope; else -> true }
        val uids = sortedSetOf<Int>()
        for (name in names) {
            require(captured(name)) { "Site-rule application is excluded from VPN: $name" }
            // Missing packages retain their saved choice and become effective
            // on a later connection after installation.
            val uid = uidForPackage(name) ?: continue
            require(uid > 0) { "Invalid Android application UID" }
            val siblings = packagesForUid(uid)
            require(name in siblings && siblings.filter(::captured).all { it in names }) { "Applications sharing a UID must use the same routing mode" }
            uids.add(uid)
        }
        return JSONObject().put("site_rules_uids", JSONArray(uids.toList())).apply {
            if (policy.has("vpn_dns_policy")) put("vpn_dns_policy", policy.getString("vpn_dns_policy"))
        }
    }
}
