package org.amnezia.vpn.util.net

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AndroidAppRoutingPolicyTest {
    private fun profile(names: String = "\"app.one\"") = JSONObject("""{"android_app_routing":{"version":1,"site_rule_packages":[$names]}}""")
    @Test fun absentPolicyPreservesExistingSemantics() {
        assertNull(AndroidAppRoutingPolicy.resolve(JSONObject(),28,{error("unexpected lookup")},{emptyList()}))
    }
    @Test fun resolvesFreshUidAndKeepsMissingPackageChoice() {
        val input=profile("\"app.one\",\"app.missing\"")
        val original=input.toString()
        for(uid in listOf(10281,110281)) {
            val output=AndroidAppRoutingPolicy.resolve(input,29,{if(it=="app.one")uid else null},{listOf("app.one")})!!
            assertEquals(uid,output.getJSONArray("site_rules_uids").getInt(0))
            assertEquals(1,output.getJSONArray("site_rules_uids").length())
        }
        assertEquals(original,input.toString())
    }
    @Test fun rejectsMixedModeOnAndroid9() {
        assertThrows(IllegalArgumentException::class.java) {AndroidAppRoutingPolicy.resolve(profile(),28,{10281},{listOf("app.one")})}
    }
    @Test fun legacyBackendCannotSilentlyIgnoreApplicationPolicy() {
        val input=profile().put("protocol","awg").put("android_legacy_awg_backend",true)
        assertThrows(IllegalArgumentException::class.java) {AwgCorePolicy.prepare(input)}
    }
    @Test fun rejectsSharedUidConflictButAllowsMatchingChoices() {
        val siblings=listOf("app.one","app.two")
        assertThrows(IllegalArgumentException::class.java) {AndroidAppRoutingPolicy.resolve(profile(),35,{10281},{siblings})}
        val result=AndroidAppRoutingPolicy.resolve(profile("\"app.one\",\"app.two\""),35,{10281},{siblings})!!
        assertEquals(1,result.getJSONArray("site_rules_uids").length())
    }
    @Test fun rejectsSiteRulesForExcludedApplication() {
        val input=profile().put("appSplitTunnelType",2).put("splitTunnelApps",org.json.JSONArray().put("app.one"))
        assertThrows(IllegalArgumentException::class.java) {AndroidAppRoutingPolicy.resolve(input,35,{10281},{listOf("app.one")})}
    }
    @Test fun rejectsUnknownSchemaAndDuplicatePackages() {
        for(input in listOf(profile().apply{getJSONObject("android_app_routing").put("version",2)},profile("\"app.one\",\"app.one\""))) {
            assertThrows(IllegalArgumentException::class.java) {AndroidAppRoutingPolicy.resolve(input,35,{10281},{listOf("app.one")})}
        }
    }
}
