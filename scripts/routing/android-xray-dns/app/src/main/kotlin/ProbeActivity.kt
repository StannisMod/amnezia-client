package org.amnezia.vpn.frontendprobe

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

class ProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val action = intent.getStringExtra("action") ?: "start"
        if (action == "start" && VpnService.prepare(this) != null)
            error("VPN consent must be granted explicitly on the owned test device")
        startForegroundService(Intent(this, ProbeService::class.java).setAction(action)
            .putExtra("run_id", intent.getStringExtra("run_id")))
        finish()
    }
}
