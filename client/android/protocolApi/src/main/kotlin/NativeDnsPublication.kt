package org.amnezia.vpn.protocol

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.NativeDnsPlan
import org.amnezia.vpn.protocol.NativeDnsScope
import org.json.JSONArray
import org.json.JSONObject

/** No OS/network fallback. This object retains the original pre-publication scope. */
class NativeDnsPublication private constructor(
    val raw: String,
    val aliases: List<InetAddress>,
    val bindings: List<NativeDnsBinding>,
    private val token: String?,
    private val identity: String?,
    private val currentIdentity: (() -> String?)?,
    private val protect: (Int) -> Boolean,
    private val bind: ((Int, String) -> Boolean)?
) {
    private val retired = AtomicBoolean(false)
    private val failureReported = AtomicBoolean(false)

    fun beginFailure(): Boolean = !retired.get() && failureReported.compareAndSet(false, true)
    fun bindDirectSocket(fd: Int): Boolean =
        token?.let { bindSocket(fd.toLong(), it) } ?: false

    fun bindSocket(fd: Long, requestedToken: String): Boolean {
        if (retired.get() || failureReported.get() || fd !in 0..Int.MAX_VALUE.toLong() || token == null ||
            requestedToken != token || identity == null) return false
        return try {
            currentIdentity?.invoke() == identity && protect(fd.toInt()) &&
                bind?.invoke(fd.toInt(), token) == true && currentIdentity?.invoke() == identity
        } catch (_: Exception) { false }
    }

    fun retire() { retired.set(true) }

    companion object {
        fun prepare(
            plan: NativeDnsPlan,
            strictPrivateDns: Boolean,
            lockdown: Boolean,
            snapshot: (() -> JSONObject)?,
            currentIdentity: (() -> String?)?,
            protect: (Int) -> Boolean,
            bind: ((Int, String) -> Boolean)?
        ): NativeDnsPublication {
            if (strictPrivateDns)
                throw BadConfigException("IPv6 OFF native DNS is incompatible with strict encrypted Android DNS")
            var token: String? = null
            var captured: String? = null
            if (plan.bindings.any { it.scope == NativeDnsScope.DIRECT }) {
                if (lockdown || snapshot == null || currentIdentity == null || bind == null)
                    throw BadConfigException("Original DIRECT native DNS network is unavailable")
                captured = currentIdentity() ?: throw BadConfigException("Missing original DNS network identity")
                val links = snapshot().optJSONArray("links")
                    ?: throw BadConfigException("Missing original DNS network snapshot")
                val defaults = (0 until links.length()).map { links.getJSONObject(it) }
                    .filter { it.optBoolean("default") }
                if (defaults.size != 1)
                    throw BadConfigException("Ambiguous original DIRECT DNS network")
                val selected = defaults.single()
                token = selected.optString("id").takeIf { it.isNotBlank() }
                    ?: throw BadConfigException("Missing original DIRECT DNS network token")
                val servers = selected.optJSONArray("servers")
                    ?: throw BadConfigException("Missing original DNS transport metadata")
                if (servers.length() == 0 || (0 until servers.length()).any {
                        servers.getJSONObject(it).optString("transport", "udp") !in setOf("udp", "tcp")
                    })
                    throw BadConfigException("Encrypted DIRECT DNS cannot be reduced to plaintext forwarding")
                if (currentIdentity() != captured)
                    throw BadConfigException("Original DNS network changed during preparation")
            }
            val bindings = JSONArray()
            val aliases = plan.bindings.map { binding ->
                val scope = when (binding.scope) {
                    NativeDnsScope.TUNNEL -> "tunnel"
                    NativeDnsScope.DIRECT -> "direct"
                    NativeDnsScope.IPV6_UNAVAILABLE -> "unavailable"
                }
                bindings.put(JSONObject().put("endpoint", binding.endpoint)
                    .put("upstream", binding.upstream).put("scope", scope).apply {
                        if (binding.scope == NativeDnsScope.DIRECT) put("network_token", token)
                        if (binding.transport != NativeDnsTransport.PLAIN) {
                            put("transport", binding.transport.wire)
                            put("server_name", binding.serverName)
                            if (binding.httpsUrl.isNotEmpty()) put("https_url", binding.httpsUrl)
                        }
                    })
                InetAddress.getByName(binding.endpoint.substringBefore(':'))
            }
            return NativeDnsPublication(JSONObject().put("bindings", bindings).toString(), aliases,
                plan.bindings.toList(), token, captured, currentIdentity, protect, bind)
        }
    }
}
