package org.amnezia.routingtest;

import android.app.Activity;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import java.util.Objects;

// Test APK only; installed as device owner exclusively on disposable emulators.
public final class RoutingPolicyReceiver extends DeviceAdminReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!"org.amnezia.routingtest.POLICY".equals(intent.getAction())) {
            super.onReceive(context, intent);
            return;
        }
        try {
            String mode = intent.getStringExtra("mode");
            DevicePolicyManager policy = context.getSystemService(DevicePolicyManager.class);
            if (!policy.isDeviceOwnerApp(context.getPackageName())) throw new SecurityException("test admin is not device owner");
            if ("test-wifi".equals(mode)) {
                android.net.wifi.WifiManager wifi = (android.net.wifi.WifiManager)context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                boolean selected = false;
                for (android.net.wifi.WifiConfiguration network : wifi.getConfiguredNetworks()) {
                    if ("\"AndroidWifi\"".equals(network.SSID)) selected = wifi.enableNetwork(network.networkId, true);
                }
                if (!selected || !wifi.reconnect()) throw new IllegalStateException("synthetic Wi-Fi was not selected");
                setResultCode(Activity.RESULT_OK);
                return;
            }
            if (!"off".equals(mode) && !"alwayson".equals(mode) && !"lockdown".equals(mode)) throw new IllegalArgumentException("policy mode");
            ComponentName admin = new ComponentName(context, RoutingPolicyReceiver.class);
            String vpn = "off".equals(mode) ? null : "org.amnezia.vpn";
            boolean lockdown = "lockdown".equals(mode);
            policy.setAlwaysOnVpnPackage(admin, vpn, lockdown);
            if (!Objects.equals(policy.getAlwaysOnVpnPackage(admin), vpn)
                    || (android.os.Build.VERSION.SDK_INT >= 29 && policy.isAlwaysOnVpnLockdownEnabled(admin) != lockdown)) throw new IllegalStateException("policy was not applied");
            setResultCode(Activity.RESULT_OK);
        } catch (Exception error) {
            setResultCode(Activity.RESULT_CANCELED);
            setResultData(error.getClass().getSimpleName());
        }
    }
}
