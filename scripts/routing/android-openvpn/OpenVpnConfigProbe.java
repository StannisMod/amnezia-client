package org.amnezia.openvpntest;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import org.json.JSONObject;
import net.openvpn.ovpn3.ClientAPI_Config;
import net.openvpn.ovpn3.ClientAPI_EvalConfig;
import net.openvpn.ovpn3.ClientAPI_OpenVPNClient;
import net.openvpn.ovpn3.ClientAPI_Status;
import net.openvpn.ovpn3.ClientAPI_LogInfo;
import net.openvpn.ovpn3.ClientAPI_Event;

/** Runs shipped JNI option initialization, optionally TLS/TUN callbacks. Never creates a TUN. */
public final class OpenVpnConfigProbe {
    private static final class ProbeClient extends ClientAPI_OpenVPNClient {
        final String remote;
        final boolean tls;
        boolean established;
        final org.json.JSONArray tun = new org.json.JSONArray();
        ProbeClient(String remote, boolean tls) { this.remote = remote; this.tls = tls; }
        boolean protectedSocket;
        boolean unexpectedRemote;
        final ArrayList<String> warnings = new ArrayList<>();
        @Override public void event(ClientAPI_Event event) { if (tls) tun.put("event " + event.getName() + " " + event.getInfo()); }
        @Override public boolean pause_on_connection_timeout() { return false; }
        @Override public boolean socket_protect(int fd, String remote, boolean ipv6) {
            protectedSocket = true;
            if (tls) tun.put("socket " + remote + " ipv6=" + ipv6);
            unexpectedRemote |= ipv6 || !remote.equals(this.remote);
            return tls && !unexpectedRemote;
        }
        @Override public boolean tun_builder_new() { tun.put("new"); return true; }
        @Override public boolean tun_builder_add_address(String address, int prefix, String gateway, boolean ipv6, boolean net30) {
            tun.put("address " + address + "/" + prefix); return true;
        }
        @Override public boolean tun_builder_add_route(String address, int prefix, int metric, boolean ipv6) {
            tun.put("route " + address + "/" + prefix); return true;
        }
        @Override public boolean tun_builder_exclude_route(String address, int prefix, int metric, boolean ipv6) {
            tun.put("exclude " + address + "/" + prefix); return true;
        }
        @Override public boolean tun_builder_set_allow_family(int af, boolean allow) { tun.put("family " + af + " " + allow); return true; }
        @Override public boolean tun_builder_reroute_gw(boolean ipv4, boolean ipv6, long flags) {
            tun.put("reroute " + ipv4 + " " + ipv6 + " " + flags); return true;
        }
        @Override public boolean tun_builder_set_remote_address(String address, boolean ipv6) { return true; }
        @Override public boolean tun_builder_add_dns_server(String address, boolean ipv6) { return true; }
        @Override public boolean tun_builder_set_layer(int layer) { return layer == 3; }
        @Override public boolean tun_builder_set_mtu(int mtu) { return true; }
        @Override public boolean tun_builder_set_session_name(String name) { return true; }
        @Override public int tun_builder_establish() { established = true; return -1; }
        @Override public void log(ClientAPI_LogInfo info) {
            String text = info.getText();
            if (tls || text.contains("UNUSED") || text.contains("Unsupported") || text.contains("unknown"))
                warnings.add(text.substring(0, Math.min(text.length(), 2048)));
        }
    }
    public static void main(String[] args) throws Exception {
        File libs = new File(args[0]);
        System.load(new File(libs, "libc++_shared.so").getAbsolutePath());
        System.load(new File(libs, "libck-ovpn-plugin.so").getAbsolutePath());
        System.load(new File(libs, "libovpn3.so").getAbsolutePath());
        JSONObject input = new JSONObject(new String(Files.readAllBytes(new File(args[1]).toPath()), StandardCharsets.UTF_8));
        JSONObject profiles = input.getJSONObject("profiles");
        boolean tls = input.optBoolean("tls", false);
        String remote = tls ? "10.0.2.2" : "127.0.0.1";
        ArrayList<String> names = new ArrayList<>();
        java.util.Iterator<String> keys = profiles.keys();
        while (keys.hasNext()) names.add(keys.next());
        Collections.sort(names);
        JSONObject cases = new JSONObject();
        boolean passed = true;
        for (String name : names) {
            System.out.println("PROBE_CASE=" + name);
            ProbeClient client = new ProbeClient(remote, tls);
            ClientAPI_Config config = new ClientAPI_Config();
            try {
                config.setContent(profiles.getString(name));
                config.setServerOverride(remote);
                config.setPortOverride(tls ? "21943" : "9");
                config.setProtoOverride("tcp");
                config.setConnTimeout(1);
                ClientAPI_EvalConfig result = client.eval_config(config);
                try {
                    boolean expectedError = name.equals("invalid-control");
                    boolean ok = result.getError() == expectedError;
                    JSONObject row = new JSONObject();
                    row.put("error", result.getError());
                    row.put("message", result.getMessage());
                    if (!expectedError && !result.getError()) {
                        Thread stopper = new Thread(() -> {
                            try { Thread.sleep(tls ? 5000 : 1500); client.stop(); }
                            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                        });
                        stopper.setDaemon(true);
                        stopper.start();
                        ClientAPI_Status startup;
                        try { startup = client.connect(); }
                        finally { stopper.interrupt(); stopper.join(); }
                        try {
                            ok &= client.protectedSocket && !client.unexpectedRemote;
                            if (tls) ok &= client.established;
                            row.put("options_initialized", client.protectedSocket);
                            row.put("tun_callbacks", client.tun);
                            row.put("tun_establish_called", client.established);
                            row.put("startup_status", startup.getStatus());
                            row.put("startup_message", startup.getMessage());
                            row.put("warnings", new org.json.JSONArray(client.warnings));
                        } finally { startup.delete(); }
                    }
                    passed &= ok;
                    row.put("pass", ok);
                    cases.put(name, row);
                } finally {
                    result.delete();
                }
            } finally {
                config.delete();
                client.delete();
            }
        }
        JSONObject report = new JSONObject();
        report.put("status", passed ? "PASS" : "FAIL");
        report.put("cases", cases);
        System.out.println("OPENVPN3_CONFIG_PROBE=" + report.toString());
        if (!passed) throw new AssertionError("Shipped OpenVPN3 rejected a generated profile or accepted the invalid control");
    }
}
