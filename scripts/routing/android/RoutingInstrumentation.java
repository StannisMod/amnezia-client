package org.amnezia.routingtest;

import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.SystemClock;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import java.util.concurrent.TimeUnit;

/** Tests the installed production service over its existing Messenger API.
 * No alternate VpnService, TUN fixture or production test hook.
 * The QUIC probe runs as a separate executable with the instrumented app UID.
 * IPC numbers below are checked against source by the host driver.
 */
public final class RoutingInstrumentation extends Instrumentation {
    private static final int REGISTER = 0, UNREGISTER = 1, CONNECT = 2, DISCONNECT = 3, REQUEST_STATUS = 4;
    private static final int DISCONNECTED = 0, CONNECTED = 1;
    private final Object lock = new Object();
    private final List<String> passed = new ArrayList<>();
    private volatile int state = -1;
    private volatile boolean serviceError;
    private volatile String serviceErrorText = "";
    private volatile String serviceErrorKind = "";
    private volatile JSONObject diagnostics;
    private volatile boolean retainedCheck;
    private volatile boolean retainedStateChanged;
    private JSONObject retainedResult;
    private JSONObject applicationFailureDiagnostics;
    private Messenger service, replies;
    private JSONObject fixture;
    private int cycles = 100;
    private String observerIP;
    private boolean performanceOnly;
    private boolean sharedFirst;
    private boolean primaryOnly;
    private boolean uploadMtuOnly;
    private boolean appPolicyOnly;
    private boolean packageLifecycle;
    private int androidUser;
    private boolean privateDnsOpportunistic;
    private boolean privateDnsStrict;
    private boolean privateDnsPolicyOnly;
    private boolean xrayIpv6Only;
    private boolean openVpnIpv6Only;
    private boolean ipv6PreferenceOnly;
    private volatile boolean policyPaused;
    private boolean api28CompatOnly;
    private boolean diagnoseControl;
    private long applicationPolicyReply = -1;
    private boolean applicationPolicyAccepted;
    private String applicationPolicyError = "";
    private final CountDownLatch bound = new CountDownLatch(1);
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            service = new Messenger(binder); bound.countDown();
        }
        @Override public void onServiceDisconnected(ComponentName name) {
            synchronized (lock) { serviceError = true; lock.notifyAll(); }
        }
    };

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        sharedFirst="shared-first".equals(args.getString("performance_order","legacy-first"));
        performanceOnly=Boolean.parseBoolean(args.getString("performance_only","false"));
        cycles = Integer.parseInt(args.getString("cycles", "100"));
        observerIP=args.getString("observer_ip","10.0.2.2");
        primaryOnly = Boolean.parseBoolean(args.getString("primary_only", "false"));
        uploadMtuOnly = Boolean.parseBoolean(args.getString("upload_mtu_only", "false"));
        appPolicyOnly = Boolean.parseBoolean(args.getString("app_policy_only", "false"));
        privateDnsStrict = Boolean.parseBoolean(args.getString("private_dns_strict", "false"));
        xrayIpv6Only = Boolean.parseBoolean(args.getString("xray_ipv6_only", "false"));
        openVpnIpv6Only = Boolean.parseBoolean(args.getString("openvpn_ipv6_only", "false"));
        ipv6PreferenceOnly = Boolean.parseBoolean(args.getString("ipv6_preference_only", "false"));
        privateDnsPolicyOnly = Boolean.parseBoolean(args.getString("private_dns_policy_only", "false"));
        privateDnsOpportunistic = Boolean.parseBoolean(args.getString("private_dns_opportunistic", "false"));
        androidUser = Integer.parseInt(args.getString("android_user", "0"));
        packageLifecycle = Boolean.parseBoolean(args.getString("package_lifecycle", "false"));
        api28CompatOnly = Boolean.parseBoolean(args.getString("api28_compat_only", "false"));
        diagnoseControl = Boolean.parseBoolean(args.getString("diagnose_control", "false"));
        start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        int code = -1;
        boolean didBind = false;
        try {
            require(android.os.Process.myUid()/100000 == androidUser, "instrumentation is running in the wrong Android profile");
            require(cycles >= 1 && cycles <= 1000, "invalid cycle count");
            require(VpnService.prepare(getTargetContext()) == null, "VPN consent was not granted by the disposable emulator driver");
            java.io.ByteArrayOutputStream fixtureBytes = new java.io.ByteArrayOutputStream();
            try (java.io.InputStream input = getContext().getAssets().open("fixture.json")) {
                byte[] buffer = new byte[4096]; int n;
                while ((n = input.read(buffer)) >= 0) fixtureBytes.write(buffer, 0, n);
            }
            fixture = new JSONObject(new String(fixtureBytes.toByteArray(), StandardCharsets.UTF_8));
            replies = new Messenger(new Handler(Looper.getMainLooper(), message -> {
                synchronized (lock) {
                    if (message.what == 0 || message.what == 1) {
                        state = message.getData().getInt("state", -1);
                        if (retainedCheck && state != CONNECTED) retainedStateChanged = true;
                        String raw = message.getData().getString("CONNECTION_DIAGNOSTICS");
                        if (raw != null) try { diagnostics = new JSONObject(raw); }
                        catch (Exception bad) { serviceError = true; serviceErrorText = "invalid connection diagnostics"; }
                    }
                    if (message.what == 3) {
                        if (message.getData().getBoolean("POLICY_NOTICE", false)) policyPaused = message.getData().getBoolean("POLICY_PAUSED", false);
                        else { serviceError = true; serviceErrorText = message.getData().getString("ERROR", ""); serviceErrorKind = message.getData().getString("ERROR_KIND", ""); }
                    }
                    if (message.what == 4) {
                        applicationPolicyReply = message.getData().getLong("APPLICATION_POLICY_REQUEST_ID", -1);
                        applicationPolicyAccepted = message.getData().getBoolean("APPLICATION_POLICY_SUCCESS");
                        applicationPolicyError = message.getData().getString("APPLICATION_POLICY_ERROR", "");
                    }
                    lock.notifyAll();
                }
                return true;
            }));
            Intent intent = new Intent().setComponent(new ComponentName("org.amnezia.vpn", "org.amnezia.vpn."+serviceClass()));
            didBind = getTargetContext().bindService(intent, connection, Context.BIND_AUTO_CREATE);
            require(didBind && bound.await(15, TimeUnit.SECONDS), "AwgService binding failed");
            Bundle registration = new Bundle(); registration.putString("CLIENT_NAME", "routing-acceptance");
            send(REGISTER, registration);
            if (ipv6PreferenceOnly) {
                ipv6Preference();result.putString("routing_result","PASS_IPV6_PREFERENCE_ONLY");code=0;return;
            }
            if (openVpnIpv6Only) {
                openVpnIpv6();result.putString("routing_result","PASS_OPENVPN_IPV6_ONLY");code=0;return;
            }
            if (xrayIpv6Only) {
                xrayIpv6();result.putString("routing_result","PASS_XRAY_IPV6_ONLY");code=0;return;
            }
            if (privateDnsPolicyOnly) {
                privateDnsPolicy();result.putString("routing_result","PASS_PRIVATE_DNS_POLICY_ONLY");code=0;return;
            }
            if (api28CompatOnly) {
                api28Compatibility();result.putString("routing_result","PASS_API28_COMPAT_ONLY");code=0;return;
            }
            if (appPolicyOnly) {
                perApplicationPolicy();
                result.putString("routing_result", "PASS_APP_POLICY_ONLY");code = 0;return;
            }
            if (uploadMtuOnly) {
                automaticUploadMtu();
                result.putString("routing_result", "PASS_UPLOAD_MTU_ONLY");code = 0;return;
            }
            if (performanceOnly) {
                performanceComparison();
                result.putString("routing_result","PASS_PERFORMANCE_ONLY");code=0;return;
            }
            if (primaryOnly) {
                retainedPrimarySession();
                result.putString("retained_result", retainedResult.toString());
                result.putString("routing_result", "PASS_PRIMARY_ONLY");code = 0;return;
            }
            // Domain miss/default assertions must not be masked by the CIDR
            // exception for the native control server at the shared real IP.
            JSONObject domainOnly=configuration(false);
            JSONArray domainRules=new JSONArray();
            for(int i=0;i<domainOnly.getJSONObject("sing_box_routing").getJSONArray("rules").length();i++) {
                JSONObject entry=domainOnly.getJSONObject("sing_box_routing").getJSONArray("rules").getJSONObject(i);
                if(!entry.optString("kind").equals("cidr") || entry.optString("value").equals("127.0.0.0/8") || entry.optString("value").equals("::1/128")) domainRules.put(entry);
            }
            domainOnly.getJSONObject("sing_box_routing").put("rules",domainRules);
            state=-1;serviceError=false;startService(domainOnly);awaitState(CONNECTED,false);
            progress("CHECK: service CONNECTED; requesting DIRECT FakeIP");
            InetAddress direct = dns("direct.ru", 1);
            progress("CHECK: DIRECT FakeIP returned; requesting VPN FakeIP");
            InetAddress vpn = dns("vpn.test", 1);
            progress("CHECK: both FakeIPs returned; checking actual TCP+UDP egress");
            require(!direct.equals(vpn) && fake(direct) && fake(vpn), "domains did not receive independent FakeIPs");
            requireRoute(direct, "DIRECT"); requireRoute(vpn, "VPN");
            pass("actual APK/service: independent TCP+UDP egress for two names sharing one real IP");
            requireRoute(dns("shop.direct.ru", 1), "DIRECT");
            requireRoute(dns("notdirect.ru.test", 1), "VPN");
            requireRoute(dns("override.direct.ru", 1), "VPN");
            requireRoute(dns("cname.test", 1), "VPN");
            pass("suffix boundaries, apex, exact-domain precedence and upstream CNAME");
            InetAddress six = dns("ipv6.test", 28);
            require(six.getAddress().length == 16 && fake(six), "AAAA did not return IPv6 FakeIP");
            requireRoute(six, "VPN"); pass("IPv6 FakeIP and real inner IPv6 TCP+UDP through AWG");
            quic(direct, "DIRECT"); quic(vpn, "VPN"); quic(six, "VPN");
            pass("native QUIC/TLS: DIRECT IPv4 and AWG IPv4/IPv6, verified 64 KiB digest");
            InetAddress[] system = InetAddress.getAllByName("system.direct.ru");
            InetAddress four = null;
            for (InetAddress address : system) if (address.getAddress().length == 4) four = address;
            require(four != null && fake(four), "system resolver did not use managed DNS");
            requireRoute(four, "DIRECT"); pass("Android system resolver uses the installed VPN DNS");
            loopback("127.0.0.1"); loopback("::1"); pass("native IPv4/IPv6 loopback stays local");
            disconnect();connect(false);
            direct=dns("direct.ru",1);vpn=dns("vpn.test",1);
            requireRoute(dns("notdirect.ru.test",1),"DIRECT");
            pass("unmatched domain follows its resolved-IP CIDR exception");

            // Allocate fresh FakeIPs without warming their real-address lookup.
            // During the outage these UDP flows must wait for VPN DNS without
            // blocking the sole capture reader or unrelated literal DIRECT TCP.
            InetAddress pendingFour = dns("outage-resolve.test", 1);
            InetAddress pendingSix = dns("outage-resolve.test", 28);
            JSONObject before = control("/stats", false);
            control("/peer?state=off", true);
            boolean tcpFailed = false, udpFailed = false;
            try { tcpFailed = tcp(vpn) == null; } catch (Exception expected) { tcpFailed = true; }
            try { udp(vpn); } catch (Exception expected) { udpFailed = true; }
            require(tcpFailed && udpFailed, "VPN traffic succeeded with the AWG peer down");
            JSONObject after;
            try (DatagramSocket pending = new DatagramSocket()) {
                byte[] unresolved = new byte[] {0, 1, 2, 3};
                pending.send(new DatagramPacket(unresolved, unresolved.length, pendingFour, 123));
                pending.send(new DatagramPacket(unresolved, unresolved.length, pendingSix, 123));
                after = control("/stats", false);
            }
            pass("unresolved IPv4/IPv6 UDP during VPN DNS outage does not block DIRECT TCP");
            require(before.getLong("direct_tcp") == after.getLong("direct_tcp") && before.getLong("direct_udp") == after.getLong("direct_udp"), "VPN traffic fell back to the DIRECT observer");
            // Real upstream DNS may need VPN, so do not claim fresh uncached
            // names resolve during outage. A literal DIRECT destination works.
            requireRoute(InetAddress.getByName("10.0.2.2"), "DIRECT");
            control("/peer?state=on", true);
            disconnect(); connect(true);
            progress("CHECK: inverse restart; verify explicit DIRECT and VPN rules before default policy");
            requireRoute(dns("direct.ru", 1), "DIRECT");
            requireRoute(dns("vpn.test", 1), "VPN");
            requireRoute(dns("unlisted.test", 1), "DIRECT");
            requireRoute(dns("vpn.test", 1), "VPN");
            pass("AWG outage fails closed, configured DIRECT remains reachable, inverse default policy");
            disconnect();
            progress("RESOURCE_CHECKPOINT baseline"); SystemClock.sleep(3000);
            connect(false);
            require(dns("vpn.test", 1).equals(vpn), "restart reassigned a cached FakeIP");
            requireRoute(vpn, "VPN"); pass("cached FakeIP retains identity after session restart");

            // Keep the same real service process bound throughout: process
            // replacement cannot hide descriptors/threads leaked per session.
            for (int i = 0; i < cycles; ++i) {
                disconnect(); connect((i & 1) == 1);
                requireRoute(dns("vpn.test", 1), "VPN");
                if ((i + 1) % 10 == 0) progress("completed reconnects: " + (i + 1));
            }
            disconnect(); pass(cycles + " connect/disconnect cycles through the production service");
            progress("RESOURCE_CHECKPOINT after_cycles"); SystemClock.sleep(3000);
            state = -1; serviceError = false;
            JSONObject bad = configuration(false); bad.getJSONObject("sing_box_routing").put("version", 99);
            startService(bad);
            awaitState(DISCONNECTED, true);
            connect(false); requireRoute(dns("vpn.test", 1), "VPN"); disconnect();
            pass("failed engine start releases resources and a subsequent valid start succeeds");
            // Switch the real service to its unchanged legacy AWG backend,
            // then back to routed AWG. Use an inner literal IPv4 observer:
            // legacy profiles deliberately have no FakeIP/domain guarantee.
            JSONObject legacy = configuration(false);
            legacy.remove("sing_box_routing"); legacy.remove("sing_box_dns");
            legacy.put("android_legacy_awg_backend", true);
            startService(legacy); awaitState(CONNECTED, false);
            progress("LEGACY_CAPTURE_READY_MS "+awaitCapture("10.77.0.1"));
            requireRoute(InetAddress.getByName("10.77.0.2"), "VPN");
            quic(InetAddress.getByName("10.77.0.2"), "VPN");
            disconnect(); connect(false);
            requireRoute(dns("vpn.test", 1), "VPN"); disconnect();
            pass("legacy AWG TCP/UDP/QUIC and routed-to-legacy-to-routed service transition");
            retainedPrimarySession();
            automaticUploadMtu();
            perApplicationPolicy();
            restrictedProfiles();
            // restrictedProfiles leaves an IPv6-only profile in the service's
            // saved configuration. Always-on restores that exact profile;
            // seed the intended mixed-routing profile before checking IPv4
            // reachability and subsequent lockdown rejection.
            connect(false); disconnect();
            // The driver owns a real DevicePolicyManager admin on this AVD.
            // Always-on may start the saved profile itself; await that event.
            state = -1; serviceError = false;
            policy("alwayson"); awaitState(CONNECTED, false);
            requireRoute(dns("vpn.test", 1), "VPN");
            state = -1; serviceError = false; serviceErrorText = "";
            policy("lockdown"); awaitState(DISCONNECTED, true);
            require(serviceErrorText.contains("lockdown"), "active lockdown did not produce the policy error");
            state = -1; serviceError = false; serviceErrorText = "";
            startService(configuration(false)); awaitState(DISCONNECTED, true);
            require(serviceErrorText.contains("lockdown"), "lockdown startup was not rejected before capture");
            policy("off");
            connect(false); requireRoute(dns("vpn.test", 1), "VPN"); disconnect();
            pass("OS always-on, active lockdown shutdown, lockdown startup rejection and recovery");
            allVpnLockdown();
            performanceComparison();
            result.putString("retained_result", retainedResult.toString());
            result.putString("routing_result", "PASS"); code = 0;
        } catch (Throwable error) {
            // Avoid dumping fixture/keys in an exception or Android log.
            result.putString("routing_result", "FAIL");
            result.putString("failure", error.getClass().getSimpleName() + ": " + error.getMessage());
            StringBuilder stack = new StringBuilder();
            for (StackTraceElement frame : error.getStackTrace()) if (frame.getClassName().startsWith("org.amnezia.routingtest")) stack.append(frame).append("\n");
            result.putString("test_stack", stack.toString());
            // Capture the blocked native/JNI path before another network call
            // or cleanup changes it. The rooted driver collects debuggerd.
            if (openVpnIpv6Only) { progress("RESOURCE_CHECKPOINT failure");SystemClock.sleep(10000); }
            else if (applicationFailureDiagnostics != null) result.putString("connection_diagnostics", applicationFailureDiagnostics.toString());
            else {
                try { result.putString("connection_diagnostics", connectionDiagnostics().toString()); } catch (Exception ignored) {}
                progress("RESOURCE_CHECKPOINT failure"); SystemClock.sleep(10000);
            }
            if (!openVpnIpv6Only) try { result.putString("observers", control("/stats", false).toString()); } catch (Exception ignored) {}
        } finally {
            if (service != null) try { send(DISCONNECT, new Bundle()); send(UNREGISTER, new Bundle()); } catch (Exception ignored) {}
            if (didBind) getTargetContext().unbindService(connection);
            result.putString("passed", new JSONArray(passed).toString());
            finish(code, result);
        }
    }

    private long awaitCapture(String expectedSource) throws Exception {
        return awaitCapture(expectedSource,"10.77.0.2");
    }

    private long awaitCapture(String expectedSource,String probeDestination) throws Exception {
            ConnectivityManager manager=getTargetContext().getSystemService(ConnectivityManager.class);
            InetAddress expectedAddress=InetAddress.getByName(expectedSource);
            long readyStart=SystemClock.elapsedRealtime();boolean captureReady=false;
            do {
                Network network=manager.getActiveNetwork();
                NetworkCapabilities caps=network==null?null:manager.getNetworkCapabilities(network);
                android.net.LinkProperties links=network==null?null:manager.getLinkProperties(network);
                if(caps!=null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && links!=null) {
                    for(android.net.LinkAddress address:links.getLinkAddresses()) if(expectedAddress.equals(address.getAddress())) captureReady=true;
                    if(captureReady) {
                        // UDP connect selects a source without sending a packet.
                        // This checks kernel routing, beyond cached framework data.
                        try(DatagramSocket route=new DatagramSocket()) {
                            route.connect(InetAddress.getByName(probeDestination),18081);
                            captureReady=expectedAddress.equals(route.getLocalAddress());
                        } catch(Exception notReady) {captureReady=false;}
                    }
                }
                if(!captureReady) SystemClock.sleep(25);
            } while(!captureReady && !serviceError && SystemClock.elapsedRealtime()-readyStart<5000);
            require(captureReady && !serviceError,"VPN capture is not installed in Android");
            return SystemClock.elapsedRealtime()-readyStart;
    }

    private void performanceComparison() throws Exception {
        for (boolean legacy : new boolean[]{!sharedFirst, sharedFirst}) {
            String mode = legacy ? "legacy" : "shared";
            JSONObject config = primaryConfiguration();
            if (legacy) {
                config.remove("sing_box_routing"); config.remove("sing_box_dns");
                config.put("android_legacy_awg_backend", true);
            }
            state=-1;serviceError=false;startService(config); awaitState(CONNECTED, false);
            // Legacy handshake completion may precede Android installing the
            // new per-UID VPN network. Measure throughput only after OS capture
            // is ready; never retry or replace the measured TCP stream.
            long captureWait=awaitCapture(legacy?"10.77.0.1":"172.19.0.1");
            ExecutorService io = Executors.newSingleThreadExecutor();
            try (Socket connection = retainedSocket(InetAddress.getByName("10.77.0.2"))) {
                byte[] payload = new byte[256 * 1024];
                new java.security.SecureRandom().nextBytes(payload);
                exchange(io, connection, payload);
                retainedCheckpoint("perf_" + mode + "_before");
                long begin = SystemClock.elapsedRealtime(), bytes = 0;
                while (SystemClock.elapsedRealtime() - begin < 8000) {
                    exchange(io, connection, payload); bytes += payload.length;
                }
                long elapsed = SystemClock.elapsedRealtime() - begin;
                retainedCheckpoint("perf_" + mode + "_after");
                progress("PERFORMANCE " + new JSONObject().put("backend", mode).put("bytes", bytes).put("elapsed_ms", elapsed).put("capture_ready_wait_ms",captureWait));
            } finally { io.shutdownNow(); disconnect(); }
        }
        pass("legacy/shared CPU and RSS observations with verified original-stream payloads");
    }

    private JSONObject connectionDiagnostics() throws Exception {
        diagnostics = null; send(REQUEST_STATUS, new Bundle());
        long until = SystemClock.elapsedRealtime() + 5000;
        synchronized (lock) {
            while (diagnostics == null && !serviceError && SystemClock.elapsedRealtime() < until) lock.wait(50);
            require(diagnostics != null && !serviceError, "backend diagnostics unavailable");
            return new JSONObject(diagnostics.toString());
        }
    }

    private JSONObject retainedCheckpoint(String name) throws Exception {
        File ready = new File(getTargetContext().getFilesDir(), "routing-retain-" + name + ".ready");
        ready.delete(); progress("RETAIN_CHECKPOINT " + name);
        long until = SystemClock.elapsedRealtime() + 20000;
        while (!ready.exists() && SystemClock.elapsedRealtime() < until) SystemClock.sleep(50);
        require(ready.exists(), "retained-session host checkpoint timed out: " + name); ready.delete();
        File stats = new File(getTargetContext().getFilesDir(), "routing-stats-" + name + ".json");
        try (InputStream input = new java.io.FileInputStream(stats)) {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            byte[] data = new byte[4096]; int count;
            while ((count = input.read(data)) >= 0) bytes.write(data, 0, count);
            return new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    private void api28Compatibility() throws Exception {
        require(android.os.Build.VERSION.SDK_INT==28,"API28 compatibility requires a real Android 9 emulator");
        JSONObject normal=primaryConfiguration();
        state=-1;serviceError=false;startService(normal);awaitState(CONNECTED,false);
        require("shared".equals(connectionDiagnostics().getString("backend")),"ordinary API28 all-VPN profile lost the shared core");
        requireRoute(InetAddress.getByName("10.77.0.2"),"VPN");requireRoute(InetAddress.getByName("fd77::2"),"VPN");disconnect();
        JSONObject mixed=primaryConfiguration();mixed.put("android_app_routing",new JSONObject().put("version",1).put("site_rule_packages",new JSONArray().put("org.amnezia.vpn")));
        state=-1;serviceError=false;serviceErrorText="";startService(mixed);awaitState(DISCONNECTED,true);
        require(serviceErrorText.contains("Android 10"),"unsupported API28 policy was not rejected explicitly: "+serviceErrorText);
        state=-1;serviceError=false;startService(normal);awaitState(CONNECTED,false);requireRoute(InetAddress.getByName("10.77.0.2"),"VPN");disconnect();
        progress("API28_COMPAT_RESULT "+new JSONObject().put("sdk",28).put("ordinary_shared_ipv4_ipv6",true).put("mixed_policy_rejected",true).put("subsequent_connect",true));
        pass("Android 9 ordinary shared core works and unsupported mixed policy fails explicitly");
    }

    private void xrayTraffic(String address) throws Exception {
            try(Socket connection=new Socket()) {
                connection.connect(new InetSocketAddress(InetAddress.getByName(address),18081),4000);connection.setSoTimeout(4000);
                connection.getOutputStream().write("route-proof\n".getBytes(StandardCharsets.US_ASCII));connection.getOutputStream().flush();
                String answer=new BufferedReader(new InputStreamReader(connection.getInputStream(),StandardCharsets.US_ASCII)).readLine();
                require("XRAY".equals(answer),"Xray TCP failed for "+address);
            }
            require("XRAY:route-proof".equals(udp(InetAddress.getByName(address))),"Xray UDP failed for "+address);
    }

    private String serviceClass() { return openVpnIpv6Only ? "OpenVpnService" : xrayIpv6Only ? "XrayService" : "AwgService"; }

    private Network openVpnNetwork(ConnectivityManager manager) throws Exception {
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities caps=manager.getNetworkCapabilities(network);
            android.net.LinkProperties links=manager.getLinkProperties(network);
            if (caps==null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || links==null) continue;
            for (android.net.LinkAddress address : links.getLinkAddresses())
                if (InetAddress.getByName("10.76.0.2").equals(address.getAddress())) return network;
        }
        return null;
    }

    private String openVpnObserved(String address, String answer, String expected, InetAddress local) throws Exception {
        if (!(expected.equals("BLOCKED") ? answer==null : expected.equals(answer))) {
            progress("OPENVPN_UNEXPECTED_SOCKET "+address+" local="+local+" actual="+answer+" state="+state);
            progress("RESOURCE_CHECKPOINT failure_socket");
            // Optional causal experiment driven only by the root-owned emulator
            // monitor after a failed packet. Never turns the original failure
            // into a pass and never changes routes from the application.
            File replay=new File(getTargetContext().getFilesDir(),"routing-ipv6-cache-flushed.ready");
            long until=SystemClock.elapsedRealtime()+10000;
            while(!replay.exists() && SystemClock.elapsedRealtime()<until)SystemClock.sleep(25);
            if(replay.exists()) {
                replay.delete();
                try(Socket retry=new Socket()) {
                    retry.setSoTimeout(1500);retry.connect(new InetSocketAddress(address,21944),1500);
                    String after=new BufferedReader(new InputStreamReader(retry.getInputStream(),StandardCharsets.US_ASCII)).readLine();
                    progress("OPENVPN_CACHE_RETRY "+address+" local="+retry.getLocalAddress()+" after="+after);
                } catch(java.io.IOException error) { progress("OPENVPN_CACHE_RETRY "+address+" error="+error.getClass().getSimpleName()); }
            }
        }
        return answer;
    }

    private String openVpnOrigin(String address, boolean udp, String expected) throws Exception {
        if (udp) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(1500);
                socket.connect(InetAddress.getByName(address), 21944);
                byte[] probe = "route-proof".getBytes(StandardCharsets.US_ASCII);
                socket.send(new DatagramPacket(probe, probe.length));
                DatagramPacket reply = new DatagramPacket(new byte[64], 64);socket.receive(reply);
                return openVpnObserved(address,new String(reply.getData(), 0, reply.getLength(), StandardCharsets.US_ASCII).trim(),expected,socket.getLocalAddress());
            }
        }
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(1500);socket.connect(new InetSocketAddress(address, 21944), 1500);
            return openVpnObserved(address,new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine(),expected,socket.getLocalAddress());
        }
    }

    private void openVpnLoopbackIpv6() throws Exception {
        InetAddress loopback=InetAddress.getByName("::1");
        ExecutorService io=Executors.newSingleThreadExecutor();
        try {
            try(ServerSocket server=new ServerSocket(0,1,loopback)) {
                server.setSoTimeout(2000);
                Future<Boolean> echo=io.submit(() -> {
                    try(Socket peer=server.accept()) {
                        peer.setSoTimeout(2000);int value=peer.getInputStream().read();
                        peer.getOutputStream().write(value);return value==17;
                    }
                });
                try(Socket client=new Socket()) {
                    client.setSoTimeout(2000);client.connect(new InetSocketAddress(loopback,server.getLocalPort()),2000);
                    client.getOutputStream().write(17);
                    require(client.getInputStream().read()==17 && loopback.equals(client.getLocalAddress()),"IPv6 loopback TCP entered the tunnel");
                }
                require(echo.get(3,TimeUnit.SECONDS),"IPv6 loopback TCP echo failed");
            }
            try(DatagramSocket server=new DatagramSocket(new InetSocketAddress(loopback,0));
                DatagramSocket client=new DatagramSocket(new InetSocketAddress(loopback,0))) {
                server.setSoTimeout(2000);client.setSoTimeout(2000);
                Future<Boolean> echo=io.submit(() -> {
                    DatagramPacket packet=new DatagramPacket(new byte[1],1);server.receive(packet);
                    server.send(packet);return loopback.equals(packet.getAddress()) && packet.getData()[0]==23;
                });
                client.send(new DatagramPacket(new byte[]{23},1,loopback,server.getLocalPort()));
                DatagramPacket reply=new DatagramPacket(new byte[1],1);client.receive(reply);
                require(reply.getData()[0]==23 && loopback.equals(reply.getAddress()),"IPv6 loopback UDP entered the tunnel");
                require(echo.get(3,TimeUnit.SECONDS),"IPv6 loopback UDP echo failed");
            }
        } finally { io.shutdownNow(); }
        progress("OPENVPN_LOOPBACK_IPV6 TCP_UDP_LOCAL");
    }

    private void openVpnIpv6() throws Exception {
        JSONArray cases = fixture.getJSONArray("openvpn_cases");
        JSONArray targets = fixture.getJSONArray("ipv6_test_destinations");
        for (int index = 0; index < cases.length(); index++) {
            JSONObject test = cases.getJSONObject(index), config = test.getJSONObject("config");
            for (int target=0; target<targets.length(); target++) {
                String address=targets.getString(target);
                for (boolean udp : new boolean[]{false,true}) require("NATIVE".equals(openVpnOrigin(address,udp,"NATIVE")), "native baseline unavailable: " + address);
            }
            config.put("appSplitTunnelType",1).put("splitTunnelApps",new JSONArray().put("org.amnezia.vpn"));
            state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
            ConnectivityManager manager=getTargetContext().getSystemService(ConnectivityManager.class);
            Network network=null;long captureDeadline=SystemClock.elapsedRealtime()+5000;
            while (SystemClock.elapsedRealtime()<captureDeadline && !serviceError) {
                network=openVpnNetwork(manager);
                if (network!=null) {
                    try (DatagramSocket route=new DatagramSocket()) {
                        route.connect(InetAddress.getByName("10.76.0.1"),18080);
                        if (InetAddress.getByName("10.76.0.2").equals(route.getLocalAddress())) break;
                    }
                }
                network=null;SystemClock.sleep(25);
            }
            require(network!=null && !serviceError,"OpenVPN capture/source route is not installed");
            progress("OPENVPN_CAPTURE " + test.getString("name") + " " + manager.getLinkProperties(network));
            try (Socket first = new Socket(); Socket second = new Socket()) {
                for (Socket socket : new Socket[]{first,second}) {
                    socket.setSoTimeout(3000);socket.connect(new InetSocketAddress("10.76.0.1",18080),3000);
                    socket.getOutputStream().write('a');require(socket.getInputStream().read()=='a',"IPv4 tunnel echo before IPv6 check failed");
                }
                JSONObject expected=test.getJSONObject("expected");
                openVpnLoopbackIpv6();
                for (int target=0; target<targets.length(); target++) for (boolean udp : new boolean[]{false,true}) {
                    String address=targets.getString(target);
                    String answer=null;Exception failure=null;
                    String want=expected.getString(address);
                    try { answer=openVpnOrigin(address,udp,want); } catch (java.io.IOException error) { failure=error; }
                    if (want.equals("BLOCKED")) require(failure!=null || answer==null,"selected IPv6 escaped blocking: "+address+" "+answer);
                    else require(failure==null && want.equals(answer),"IPv6 scope mismatch: "+address+" udp="+udp+" expected="+want+" actual="+answer+" error="+failure);
                }
                require(state==CONNECTED && java.util.Objects.equals(network,openVpnNetwork(manager)),"IPv6 check replaced the VPN network");
                for (Socket socket : new Socket[]{first,second}) {
                    socket.getOutputStream().write('z');require(socket.getInputStream().read()=='z',"original IPv4 TCP was lost");
                }
            }
            progress("OPENVPN_IPV6_CASE "+new JSONObject().put("name",test.getString("name")).put("expected",test.getJSONObject("expected")).put("old_ipv4_tcp_retained",true).put("loopback_ipv6_local",true));
            disconnect();
            long until=SystemClock.elapsedRealtime()+5000;
            while(java.util.Objects.equals(network,openVpnNetwork(manager)) && SystemClock.elapsedRealtime()<until)SystemClock.sleep(25);
            require(!java.util.Objects.equals(network,openVpnNetwork(manager)),"old VPN network survived disconnect");
        }
        pass("OpenVpnService IPv6 scope and original IPv4 TCP on actual Android TUN");
    }

    private void xrayIpv6() throws Exception {
        JSONObject config=new JSONObject(fixture.toString());
        config.put("appSplitTunnelType",1).put("splitTunnelApps",new JSONArray().put("org.amnezia.vpn"));
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        awaitCapture("10.0.42.2");
        awaitCapture("fdfe:dcba:9876::2","2001:db8:42::2");
        ConnectivityManager captureManager=getTargetContext().getSystemService(ConnectivityManager.class);
        progress("XRAY_CAPTURE_ROUTES "+captureManager.getLinkProperties(captureManager.getActiveNetwork()));
        JSONArray targets=config.getJSONArray("ipv6_test_destinations");
        require(targets.length()==4,"Xray fixture must include IPv4, GUA, ULA and NAT64");
        for(int i=0;i<targets.length();i++) {
            String address=targets.getString(i);
            progress("XRAY_IPV6_CHECK "+address);
            JSONObject before=control("/stats",false).getJSONObject("vless");
            xrayTraffic(address);
            JSONObject after=control("/stats",false).getJSONObject("vless");
            for(String network:new String[]{"tcp","udp"}) require(after.getJSONObject(network).optLong(address)==before.getJSONObject(network).optLong(address)+1,
                "Xray "+network+" bypassed VLESS/TLS for "+address);
            progress("XRAY_PATH_VERIFIED "+address);
        }
        ConnectivityManager manager=getTargetContext().getSystemService(ConnectivityManager.class);
        Network oldNetwork=manager.getActiveNetwork();
        disconnect();
        config.put("splitTunnelType",1).put("splitTunnelSites",new JSONArray().put(targets.getString(0)+"/32"));
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        long until=SystemClock.elapsedRealtime()+5000;
        while(java.util.Objects.equals(oldNetwork,manager.getActiveNetwork()) && SystemClock.elapsedRealtime()<until)SystemClock.sleep(25);
        require(!java.util.Objects.equals(oldNetwork,manager.getActiveNetwork()),"Android did not publish the new site-scoped VPN");
        awaitCapture("10.0.42.2",targets.getString(0));
        JSONObject before=control("/stats",false).getJSONObject("vless");
        xrayTraffic(targets.getString(0));xrayTraffic(targets.getString(2));
        JSONObject after=control("/stats",false).getJSONObject("vless");
        for(String network:new String[]{"tcp","udp"}) {
            require(after.getJSONObject(network).optLong(targets.getString(0))==before.getJSONObject(network).optLong(targets.getString(0))+1,"selected IPv4 escaped Xray");
            require(after.getJSONObject(network).optLong(targets.getString(2))==before.getJSONObject(network).optLong(targets.getString(2)),"IPv4 site inclusion captured unselected IPv6");
        }
        disconnect();
        progress("XRAY_SITE_SCOPE_RESULT include_ipv4_keeps_unselected_ipv6_direct");
        progress("XRAY_IPV6_RESULT ipv4_gua_ula_nat64_tcp_udp");
        pass("real Xray VLESS/TLS captures IPv4 and all tested IPv6 ranges for TCP/UDP");
    }

    private void awaitFlowPause(boolean paused) throws Exception {
        long until=SystemClock.elapsedRealtime()+30000;
        while (SystemClock.elapsedRealtime()<until) {
            JSONObject current=connectionDiagnostics();
            if (current.getJSONObject("routing").getBoolean("new_flows_paused")==paused && policyPaused==paused) return;
            SystemClock.sleep(100);
        }
        applicationFailureDiagnostics=connectionDiagnostics();
        throw new AssertionError("flow pause/notice did not become "+paused+"; notice="+policyPaused+"; "+applicationFailureDiagnostics);
    }

    private void strictDnsCheckpoint(boolean strict) throws Exception {
        retainedCheckpoint(strict ? "strict_dns_on" : "strict_dns_off");
        ConnectivityManager manager=(ConnectivityManager)getTargetContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        long until=SystemClock.elapsedRealtime()+15000;
        while(SystemClock.elapsedRealtime()<until) {
            boolean configured=false;
            for(Network network:manager.getAllNetworks()) {
                NetworkCapabilities caps=manager.getNetworkCapabilities(network);
                android.net.LinkProperties link=manager.getLinkProperties(network);
                if(caps!=null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && link!=null &&
                    link.getPrivateDnsServerName()!=null && !link.getPrivateDnsServerName().isEmpty()) configured=true;
            }
            if(configured==strict)return;
            SystemClock.sleep(100);
        }
        throw new AssertionError("Android did not publish strict DNS configuration "+strict);
    }

    private void privateDnsPolicy() throws Exception {
        require(android.os.Build.VERSION.SDK_INT>=29,"strict DNS policy needs Android 10+");
        JSONObject domain=primaryConfiguration();
        domain.put("sing_box_routing",new JSONObject().put("version",1).put("default","vpn")
            .put("rules",new JSONArray().put(rule("suffix","app-policy.test","direct"))));
        strictDnsCheckpoint(true);
        state=-1;serviceError=false;startService(domain);awaitState(DISCONNECTED,true);
        require("STRICT_PRIVATE_DNS_DOMAIN_RULES".equals(serviceErrorKind) && !serviceErrorText.isEmpty(),"strict DNS startup refusal had no policy explanation: "+serviceErrorKind);
        // An explicit always-VPN app ignores optional site rules. Strict DNS
        // remains usable until the user tries to enable those rules for it.
        JSONObject always=new JSONObject(domain.toString()).put("android_app_routing",new JSONObject()
            .put("version",1).put("site_rule_packages",new JSONArray()));
        state=-1;serviceError=false;startService(always);awaitState(CONNECTED,false);
        long request=System.nanoTime();
        Bundle update=new Bundle();update.putLong("APPLICATION_POLICY_REQUEST_ID",request);
        update.putString("APPLICATION_POLICY",new JSONObject().put("version",1)
            .put("site_rule_packages",new JSONArray().put("org.amnezia.vpn")).toString());
        applicationPolicyReply=-1;send(7,update);
        long until=SystemClock.elapsedRealtime()+20000;
        synchronized(lock) { while(applicationPolicyReply!=request && SystemClock.elapsedRealtime()<until)lock.wait(100); }
        require(applicationPolicyReply==request && !applicationPolicyAccepted && !applicationPolicyError.isEmpty(),"strict DNS live site-rule enable was accepted");
        require(state==CONNECTED && !serviceError,"refused checkbox disconnected an always-VPN session");
        disconnect();strictDnsCheckpoint(false);
        state=-1;serviceError=false;startService(domain);awaitState(CONNECTED,false);
        long session=connectionDiagnostics().getLong("session_id");
        ExecutorService io=Executors.newSingleThreadExecutor();
        try(Socket old=retainedSocket(InetAddress.getByName("10.77.0.2"))) {
            int port=old.getLocalPort();retainedCheck=true;retainedStateChanged=false;
            exchange(io,old,new byte[]{1,2,3});
            strictDnsCheckpoint(true);awaitFlowPause(true);
            exchange(io,old,new byte[]{4,5,6});
            boolean refused=false;
            try(Socket fresh=new Socket()) { fresh.setSoTimeout(3000);fresh.connect(new InetSocketAddress("10.77.0.2",18081),3000);refused=fresh.getInputStream().read()==-1; }
            catch(java.net.SocketTimeoutException stalled) { throw new AssertionError("new captured flow stalled instead of being rejected",stalled); }
            catch(java.io.IOException expected) { refused=true; }
            require(refused,"incompatible strict DNS allowed a new captured TCP flow");
            strictDnsCheckpoint(false);awaitFlowPause(false);
            exchange(io,old,new byte[]{7,8,9});
            try(Socket fresh=retainedSocket(InetAddress.getByName("10.77.0.2"))) { exchange(io,fresh,new byte[]{10}); }
            require(old.getLocalPort()==port && connectionDiagnostics().getLong("session_id")==session && !retainedStateChanged,"DNS policy replaced the old TCP or TUN session");
        } finally { retainedCheck=false;io.shutdownNow();disconnect(); }
        progress("PRIVATE_DNS_POLICY_RESULT startup_rejected_live_enable_rejected_old_tcp_preserved_resumed");
        pass("strict Private DNS requires manual change and pauses only new flows without replacing the TUN");
    }

    private JSONObject primaryConfiguration() throws Exception {
        JSONObject config = new JSONObject(fixture.toString());
        config.remove("sing_box_routing"); config.remove("sing_box_dns");
        config.remove("sing_box_dns_path");
        config.put("splitTunnelType", 0).put("splitTunnelSites", new JSONArray());
        config.put("appSplitTunnelType", 1).put("splitTunnelApps", new JSONArray().put("org.amnezia.vpn"));
        return config;
    }

    private Socket retainedSocket(InetAddress address) throws Exception {
        return retainedSocket(address, null);
    }

    private Socket retainedVpnSocket(InetAddress address, String captureAddress) throws Exception {
        ConnectivityManager manager = getTargetContext().getSystemService(ConnectivityManager.class);
        InetAddress expected = InetAddress.getByName(captureAddress);
        long until = SystemClock.elapsedRealtime() + 10000;
        do {
            for (Network network : manager.getAllNetworks()) {
                NetworkCapabilities caps = manager.getNetworkCapabilities(network);
                android.net.LinkProperties links = manager.getLinkProperties(network);
                if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || links == null) continue;
                for (android.net.LinkAddress local : links.getLinkAddresses()) {
                    if (expected.equals(local.getAddress())) return retainedSocket(address, network);
                }
            }
            SystemClock.sleep(25);
        } while (SystemClock.elapsedRealtime() < until);
        throw new AssertionError("retained socket capture VPN unavailable");
    }

    private Socket retainedSocket(InetAddress address, Network capture) throws Exception {
        Socket socket = new Socket(); socket.setSoTimeout(30000);
        try {
            // Instrumentation shares the VPN-owner UID. Its implicit socket
            // netId can be an underlay which Android destroys after handover.
            // Bind only test-owned VPN streams, never process-wide/native probes.
            if (capture != null) capture.bindSocket(socket);
            socket.connect(new InetSocketAddress(address, 18081), 10000);
            byte[] banner = new byte[4]; new DataInputStream(socket.getInputStream()).readFully(banner);
            require("VPN\n".equals(new String(banner, StandardCharsets.US_ASCII)), "retained socket reached non-VPN observer");
            return socket;
        } catch (Exception | AssertionError error) {
            socket.close();
            throw error;
        }
    }

    private void exchange(ExecutorService executor, Socket socket, byte[] payload) throws Exception {
        Future<?> work = executor.submit(() -> {
            try {
                socket.getOutputStream().write(payload);socket.getOutputStream().flush();
                byte[] reply = new byte[payload.length];new DataInputStream(socket.getInputStream()).readFully(reply);
                if (!java.util.Arrays.equals(payload, reply)) throw new AssertionError("corrupt original TCP payload");
            } catch (Exception error) { throw new RuntimeException(error); }
        });
        try { work.get(35, TimeUnit.SECONDS); }
        catch (Exception error) { socket.close();work.cancel(true);throw error; }
        require(!serviceError && !retainedStateChanged, "network recovery changed the service connection state");
    }

    private void verifyLargeDownlink() throws Exception {
        byte[] payload = new byte[1190];
        new java.security.SecureRandom().nextBytes(payload);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(2000);
            socket.connect(InetAddress.getByName("fd77::2"), 18082);
            socket.send(new DatagramPacket(payload, payload.length));
            byte[] buffer = new byte[1280];
            DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
            socket.receive(reply);
            require(reply.getLength() == 4 + payload.length &&
                    "VPN:".equals(new String(buffer, 0, 4, StandardCharsets.US_ASCII)) &&
                    java.util.Arrays.equals(payload, java.util.Arrays.copyOfRange(buffer, 4, reply.getLength())),
                    "large downlink witness mismatch");
        }
    }

    private boolean cellularAvailable() {
        ConnectivityManager manager = getTargetContext().getSystemService(ConnectivityManager.class);
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return true;
        }
        return false;
    }

    private void retainedPrimarySession() throws Exception {
        state = -1; serviceError = false; startService(primaryConfiguration());awaitState(CONNECTED, false);
        JSONObject owner = connectionDiagnostics();
        require("shared".equals(owner.getString("backend")) && owner.getBoolean("preserves_connections"),
                "ordinary app-only AWG/WG did not select the shared core");
        long session = owner.getLong("session_id");
        requireRoute(InetAddress.getByName("fd77::2"), "VPN");
        requireRoute(InetAddress.getByName("64:ff9b::c000:201"), "VPN");
        JSONObject before = retainedCheckpoint("before");
        ExecutorService io = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "retained-tcp");t.setDaemon(true);return t; });
        Socket interactive = null, media = null;
        long start = SystemClock.elapsedRealtime(); boolean cellular = false;
        try {
            retainedStateChanged = false; retainedCheck = true;
            interactive = retainedVpnSocket(dns("vpn.test", 1), "172.19.0.1");
            exchange(io, interactive, "before-fault".getBytes(StandardCharsets.US_ASCII));
            retainedCheckpoint("drop_before_media");SystemClock.sleep(3000);retainedCheckpoint("restore_before_media");
            exchange(io, interactive, "after-first-loss".getBytes(StandardCharsets.US_ASCII));
            media = retainedVpnSocket(dns("ipv6.test", 28), "172.19.0.1");
            byte[] payload = new byte[256 * 1024];for (int i = 0; i < payload.length; ++i) payload[i] = (byte)(i * 31 + 7);
            exchange(io, media, payload);
            // Age both streams through a normal WireGuard rekey interval.
            long warmUntil = SystemClock.elapsedRealtime() + 125000;
            while (SystemClock.elapsedRealtime() < warmUntil) {
                exchange(io, interactive, new byte[]{42});
                SystemClock.sleep(1000);
            }
            ExecutorService download = Executors.newSingleThreadExecutor();
            java.util.concurrent.atomic.AtomicInteger chunks = new java.util.concurrent.atomic.AtomicInteger();
            java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean(true);
            final Socket mediaSocket = media;
            Future<?> transfer = download.submit(() -> {
                do {
                    mediaSocket.getOutputStream().write(payload);
                    byte[] reply = new byte[payload.length];
                    new DataInputStream(mediaSocket.getInputStream()).readFully(reply);
                    require(java.util.Arrays.equals(payload, reply), "damaged media chunk");
                    chunks.incrementAndGet();
                    SystemClock.sleep(50);
                } while (running.get());
                return null;
            });
            try {
                long deadline = SystemClock.elapsedRealtime() + 10000;
                while (chunks.get() < 2 && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50);
                require(chunks.get() >= 2, "media never started");
                retainedCheckpoint("drop_mtu");
                int baseline = chunks.get();
                int completedDuringLimit;
                try {
                    for (int pulse = 0; pulse < 10; pulse++) {
                        exchange(io, interactive, new byte[]{42});
                        SystemClock.sleep(1000);
                    }
                    completedDuringLimit = chunks.get() - baseline;
                    progress("MTU_RESULT short_echoes=10 media_chunks=" + completedDuringLimit);
                } finally { retainedCheckpoint("restore_mtu"); }
                long restored = SystemClock.elapsedRealtime();
                verifyLargeDownlink();
                progress("MTU_RESULT verified_large_downlink_ms=" + (SystemClock.elapsedRealtime() - restored));
                running.set(false);
                transfer.get(35, TimeUnit.SECONDS);
                progress("MTU_RESULT media_resumed_after_restore_ms=" + (SystemClock.elapsedRealtime() - restored));
                exchange(io, media, payload);
            } finally { running.set(false); download.shutdownNow(); }
            retainedCheckpoint("wifi_off");
            try {
                SystemClock.sleep(3000); cellular = cellularAvailable();
                if (cellular) exchange(io, interactive, "over-cellular".getBytes(StandardCharsets.US_ASCII));
            } finally { retainedCheckpoint("wifi_on"); }
            exchange(io, interactive, "after-radio-return".getBytes(StandardCharsets.US_ASCII));exchange(io, media, payload);
            retainedCheckpoint("drop_with_media");SystemClock.sleep(3000);retainedCheckpoint("restore_with_media");
            exchange(io, interactive, "same-interactive-tcp".getBytes(StandardCharsets.US_ASCII));exchange(io, media, payload);
            JSONObject current = connectionDiagnostics();
            require(current.getLong("session_id") == session && "shared".equals(current.getString("backend")), "network recovery replaced native TCP owner");
            JSONObject after = retainedCheckpoint("after");
            require(after.getLong("vpn_tcp") == before.getLong("vpn_tcp") + 2, "replacement TCP accept concealed interruption");
            retainedResult = new JSONObject().put("same_session", true).put("original_tcp_accepts", 2)
                .put("media_after_old_interactive_session", "PASS").put("ipv6_ula_nat64_capture", "PASS")
                .put("emulated_cellular_handover", cellular ? "PASS" : "NOT_AVAILABLE")
                .put("elapsed_ms", SystemClock.elapsedRealtime() - start);
            pass("ordinary app-only core: original interactive/late-media TCP survive UDP blackholes and Wi-Fi return; IPv6 ULA/NAT64 use VPN");
        } catch (Exception | AssertionError error) {
            // Preserve the live owner before finally closes sockets/session.
            // A post-cleanup "backend=stopped" cannot diagnose recovery loss.
            try {
                applicationFailureDiagnostics = connectionDiagnostics();
                applicationFailureDiagnostics.put("retained_age_ms", SystemClock.elapsedRealtime() - start);
                progress("RETAIN_FAILURE " + applicationFailureDiagnostics);
                retainedCheckpoint("failure");
            } catch (Exception | AssertionError ignored) {}
            throw error;
        } finally {
            retainedCheck = false;if (interactive != null) interactive.close();if (media != null) media.close();
            io.shutdownNow();disconnect();
        }
    }

    private void restrictedProfiles() throws Exception {
        String key = fixture.getString("protocol") + "_config_data";
        JSONObject four = primaryConfiguration();
        four.getJSONObject(key).put("client_ip", "10.77.0.1/32")
            .put("allowed_ips", new JSONArray().put("10.77.0.0/24")).put("mtu", "1200");
        state = -1;serviceError = false;startService(four);awaitState(CONNECTED, false);
        require("shared".equals(connectionDiagnostics().getString("backend")), "restricted IPv4 profile fell back to legacy");
        requireRoute(InetAddress.getByName("10.77.0.2"), "VPN");
        requireRoute(InetAddress.getByName("10.0.2.2"), "DIRECT");
        disconnect();
        JSONObject six = primaryConfiguration().put("dns1", "fd77::2");
        six.getJSONObject(key).put("client_ip", "fd77::1/128")
            .put("allowed_ips", new JSONArray().put("fd77::/64"));
        state = -1;serviceError = false;startService(six);awaitState(CONNECTED, false);
        requireRoute(dns("ipv6.test", 28), "VPN");
        boolean blocked = false;try { blocked = tcp(InetAddress.getByName("10.0.2.2")) == null; } catch (Exception expected) { blocked = true; }
        require(blocked, "IPv6-only profile gained an implicit native IPv4 bypass");disconnect();
        pass("restricted IPv4 MTU1200 and IPv6-only profiles preserve scope; IPv6 DNS over VPN");
    }

    private JSONObject appProbe(int index, String operation, String tag) throws Exception {
        return appProbe(index, operation, tag, true);
    }
    private JSONObject appProbe(int index, String operation, String tag, boolean requireSuccess) throws Exception {
        JSONObject command = new JSONObject().put("op", operation).put("tag", tag).put("address",observerIP).put("payload", "old TCP after live policy switch");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 19091 + index), 2000);socket.setSoTimeout(12000);
            socket.getOutputStream().write((command.toString()+"\n").getBytes(StandardCharsets.UTF_8));
            JSONObject reply = new JSONObject(new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine());
            if (!operation.equals("ready")) progress("APP_PROBE " + reply);
            if (requireSuccess) require(reply.getBoolean("ok"), "application probe failed: " + reply.optString("error"));
            if (reply.getBoolean("ok")) require(reply.getString("package").equals("org.amnezia.routingprobe." + (index == 0 ? "a" : "b")), "wrong probe package");
            return reply;
        }
    }
    private JSONObject personalProbe(String operation, String tag) throws Exception {
        JSONObject command = new JSONObject().put("op",operation).put("tag",tag).put("address",observerIP).put("payload","personal TCP across work-profile policy switch");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1",19093),2000);socket.setSoTimeout(12000);
            socket.getOutputStream().write((command.toString()+"\n").getBytes(StandardCharsets.UTF_8));
            JSONObject reply = new JSONObject(new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.UTF_8)).readLine());
            require(reply.getBoolean("ok"), "personal-profile probe failed: "+reply.optString("error"));
            require(reply.getInt("uid")/100000==0 && reply.getString("package").equals("org.amnezia.routingprobe.a"),"wrong personal-profile probe");
            return reply;
        }
    }

    private void awaitAppProbe(int index) throws Exception {
        long until = SystemClock.elapsedRealtime()+15000;
        while (true) {
            try {appProbe(index,"ready","old");return;}
            catch (java.net.ConnectException notReady) {if(SystemClock.elapsedRealtime()>=until)throw notReady;SystemClock.sleep(100);}
        }
    }
    private void updateApplicationPolicy(String sitePackage) throws Exception {
        long request = System.nanoTime();
        JSONObject policy = new JSONObject().put("version",1).put("site_rule_packages",new JSONArray().put(sitePackage));
        Bundle args = new Bundle();args.putLong("APPLICATION_POLICY_REQUEST_ID",request);args.putString("APPLICATION_POLICY",policy.toString());
        synchronized(lock){applicationPolicyReply=-1;applicationPolicyAccepted=false;applicationPolicyError="";}
        send(7,args);
        long until=SystemClock.elapsedRealtime()+20000;
        synchronized(lock){
            while(applicationPolicyReply!=request && !serviceError && SystemClock.elapsedRealtime()<until)lock.wait(100);
            require(applicationPolicyReply==request && applicationPolicyAccepted && !serviceError,"live application update was not acknowledged: "+applicationPolicyError);
        }
    }
    private void packageLifecycleCheckpoint(String operation) throws Exception {
        File ready=new File(getTargetContext().getFilesDir(),"routing-package-"+operation+".ready");
        ready.delete();progress("PACKAGE_LIFECYCLE_UPDATE_B "+operation);
        long deadline=SystemClock.elapsedRealtime()+60000;
        while(!ready.exists() && SystemClock.elapsedRealtime()<deadline)SystemClock.sleep(100);
        require(ready.exists(),"package update driver did not acknowledge: "+operation);ready.delete();
        awaitAppProbe(1);
    }

    private void perApplicationPolicy() throws Exception {
        awaitAppProbe(0);awaitAppProbe(1);
        JSONObject personal = null;
        if (androidUser != 0) {
            long deadline=SystemClock.elapsedRealtime()+15000;
            while(true) {
                try { personalProbe("ready","personal-old");break; }
                catch(java.net.ConnectException notReady) { if(SystemClock.elapsedRealtime()>=deadline)throw notReady;SystemClock.sleep(100); }
            }
            personal = personalProbe("open-ip","personal-old");
            require(personal.getString("route").equals("DIRECT"),"personal TCP was not initially direct");
        }
        if (privateDnsOpportunistic || privateDnsStrict) {
            ConnectivityManager manager = (ConnectivityManager)getTargetContext().getSystemService(Context.CONNECTIVITY_SERVICE);
            long deadline = SystemClock.elapsedRealtime()+30000;
            boolean active = false;
            while (!active && SystemClock.elapsedRealtime()<deadline) {
                Network network = manager.getActiveNetwork();
                android.net.LinkProperties properties = network == null ? null : manager.getLinkProperties(network);
                NetworkCapabilities capabilities = network == null ? null : manager.getNetworkCapabilities(network);
                active = properties != null && properties.isPrivateDnsActive() && (privateDnsStrict ? "routing-fixture.invalid".equals(properties.getPrivateDnsServerName()) : properties.getPrivateDnsServerName() == null) &&
                    capabilities != null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                if (!active) SystemClock.sleep(100);
            }
            require(active, "Android did not activate the requested local Private DNS mode");
        }
        JSONObject config=primaryConfiguration();
        config.put("splitTunnelApps",new JSONArray().put("org.amnezia.routingprobe.a").put("org.amnezia.routingprobe.b"));
        config.put("android_app_routing",new JSONObject().put("version",1).put("site_rule_packages",new JSONArray().put("org.amnezia.routingprobe.b")));
        config.put("sing_box_routing",new JSONObject().put("version",1).put("default","vpn")
            .put("rules",new JSONArray().put(rule("suffix","app-policy.test","direct"))));
        JSONObject policies=new JSONObject()
            .put("lan",new JSONObject().put("transport","udp").put("server","10.0.2.2").put("port",1053).put("path","direct"))
            .put("vpn",new JSONObject().put("transport","udp").put("server","10.77.0.2").put("port",53).put("path","vpn"));
        if (privateDnsOpportunistic || privateDnsStrict) policies.put("lan",new JSONObject().put("transport","udp").put("source","network").put("path","direct"));
        config.put("sing_box_dns",new JSONObject().put("version",1).put("default","vpn").put("follow_routing",true)
            .put("direct","lan").put("vpn","vpn").put("policies",policies).put("rules",new JSONArray()));
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        long session=connectionDiagnostics().getLong("session_id");
        retainedCheck=true;retainedStateChanged=false;
        try {
            JSONObject before=retainedCheckpoint("app_policy_before");
            JSONObject a=appProbe(0,"open","old"),b=appProbe(1,"open","old");
            require(a.getInt("uid")!=b.getInt("uid"),"two probes share a UID");
            require(a.getInt("uid")/100000==androidUser && b.getInt("uid")/100000==androidUser,"application UID lost its Android user");
            if(personal != null) require(a.getInt("uid")-personal.getInt("uid")==androidUser*100000,"same package did not retain its full per-profile UID");
            require(a.getString("route").equals("VPN") && b.getString("route").equals("DIRECT"),"initial per-app routing wrong");
            require(a.getString("address").equals(b.getString("address")) && fake(InetAddress.getByName(a.getString("address"))),"apps did not share a FakeIP");
            JSONObject isolated=appProbe(0,"isolated","old").getJSONObject("isolated");
            require(isolated.getInt("uid")!=a.getInt("uid"),"isolated service reused application UID");
            require(isolated.getString("tcp").equals("ANDROID_PERMISSION_DENIED") || isolated.getString("tcp").equals("VPN"),"isolated TCP bypassed VPN");
            require(isolated.getString("udp").equals("ANDROID_PERMISSION_DENIED") || isolated.getString("udp").equals("VPN:app-policy-proof"),"isolated UDP bypassed VPN");
            for(int i=0;i<2;i++) {
                require(appProbe(i,"txt","old").getString("answer").equals(i==0?"VPN":"DIRECT"),"initial application DNS context wrong");
                require(appProbe(i,"udp","old").getString("reply").equals((i==0?"VPN:":"DIRECT:")+"app-policy-proof"),"initial application UDP route wrong");
            }
            updateApplicationPolicy("org.amnezia.routingprobe.a");
            JSONObject oldA=appProbe(0,"echo","old"),oldB=appProbe(1,"echo","old");
            require(oldA.getInt("local_port")==a.getInt("local_port") && oldB.getInt("local_port")==b.getInt("local_port"),"old TCP was replaced");
            require(oldA.getString("route").equals("VPN") && oldB.getString("route").equals("DIRECT"),"old TCP changed outbound");
            JSONObject newA=appProbe(0,"open","fresh"),newB=appProbe(1,"open","fresh");
            require(newA.getString("route").equals("DIRECT") && newB.getString("route").equals("VPN"),"new flows ignored updated policy");
            require(newA.getString("address").equals(a.getString("address")) && newB.getString("address").equals(a.getString("address")),"FakeIP changed during policy update");
            for(int i=0;i<2;i++) {
                require(appProbe(i,"txt","fresh").getString("answer").equals(i==0?"DIRECT":"VPN"),"old DNS cache/policy survived update");
                require(appProbe(i,"udp","fresh").getString("reply").equals((i==0?"DIRECT:":"VPN:")+"app-policy-proof"),"new UDP flow ignored policy update");
            }
            JSONObject after=retainedCheckpoint("app_policy_after");
            require(after.getLong("vpn_tcp")==before.getLong("vpn_tcp")+2+(isolated.getString("tcp").equals("VPN")?1:0) && after.getLong("direct_tcp")==before.getLong("direct_tcp")+2,"unexpected TCP redial or observer");
            require(after.getLong("native_dns_queries")>before.getLong("native_dns_queries") && after.getLong("dns_queries")>before.getLong("dns_queries"),"both DNS observers were not exercised");
            if (privateDnsOpportunistic || privateDnsStrict) {
                require(after.getLong("native_tls_queries")>before.getLong("native_tls_queries"), "DIRECT network DNS did not use TLS");
                progress("PRIVATE_DNS_RESULT active_"+(privateDnsStrict ? "strict" : "opportunistic")+"_network_tls");
            }
            require(connectionDiagnostics().getLong("session_id")==session && !retainedStateChanged,"application update replaced/disconnected the core");
            if(personal != null) {
                JSONObject kept=personalProbe("echo","personal-old");
                JSONObject fresh=personalProbe("open-ip","personal-fresh");
                require(kept.getInt("local_port")==personal.getInt("local_port") && kept.getString("route").equals("DIRECT"),"work VPN replaced or captured personal TCP");
                require(fresh.getString("route").equals("DIRECT"),"work VPN captured a new personal TCP");
                progress("WORK_PROFILE_RESULT "+new JSONObject().put("user",androidUser).put("personal_uid",personal.getInt("uid")).put("work_uid",a.getInt("uid")).put("personal_tcp_preserved",true).put("personal_new_tcp_direct",true));
            }
            progress("APP_POLICY_RESULT "+new JSONObject().put("uids",new JSONArray().put(a.getInt("uid")).put(b.getInt("uid")))
                .put("same_session",true).put("same_old_ports",true).put("dns_contexts_switched",true)
                .put("isolated_process",new JSONObject().put("parent_uid",a.getInt("uid")).put("result",isolated).put("parent_old_ports_preserved",true)));
            if (packageLifecycle) {
                long captureGeneration=connectionDiagnostics().optLong("capture_refresh_count",0);
                packageLifecycleCheckpoint("same-uid");
                JSONObject updated=appProbe(1,"ready","updated");
                require(updated.getInt("uid")==b.getInt("uid"),"in-place update unexpectedly changed UID");
                // Allow already delivered package broadcasts to finish; no
                // network outage or reconnection is needed for an unchanged UID.
                SystemClock.sleep(2000);
                require(connectionDiagnostics().getLong("session_id")==session && connectionDiagnostics().optLong("capture_refresh_count",0)==captureGeneration && !retainedStateChanged,"same-UID update restarted VPN");
                JSONObject unchanged=appProbe(0,"echo","old");
                require(unchanged.getInt("local_port")==a.getInt("local_port") && unchanged.getString("route").equals("VPN"),"same-UID update broke another app TCP");
                progress("PACKAGE_LIFECYCLE_SAME_UID "+new JSONObject().put("uid",updated.getInt("uid")).put("same_session",true).put("other_tcp_preserved",true));
                File ready=new File(getTargetContext().getFilesDir(),"routing-package-reinstalled.ready");
                ready.delete();progress("PACKAGE_LIFECYCLE_REINSTALL_B");
                long deadline=SystemClock.elapsedRealtime()+60000;
                while(!ready.exists() && SystemClock.elapsedRealtime()<deadline)SystemClock.sleep(100);
                require(ready.exists(),"package reinstall driver did not acknowledge");ready.delete();
                awaitAppProbe(1);
                JSONObject identity=appProbe(1,"ready","reinstalled");
                progress("PACKAGE_LIFECYCLE_UIDS "+new JSONObject().put("before",b.getInt("uid")).put("after",identity.getInt("uid")));
                require(identity.getInt("uid")!=b.getInt("uid"),"reinstall did not exercise UID change");
                long refreshDeadline=SystemClock.elapsedRealtime()+20000;
                while(connectionDiagnostics().optLong("capture_refresh_count",0)<=captureGeneration && !serviceError && SystemClock.elapsedRealtime()<refreshDeadline)SystemClock.sleep(100);
                require(connectionDiagnostics().optLong("capture_refresh_count",0)>captureGeneration,"automatic package reconnect was not acknowledged");
                retainedCheckpoint("package_refreshed");
                JSONObject capture=connectionDiagnostics();
                progress("PACKAGE_LIFECYCLE_CAPTURE "+new JSONObject().put("session_id",capture.optLong("session_id",-1)).put("capture_refresh_count",capture.optLong("capture_refresh_count",-1)));
                // UID replacement explicitly permits restarting the VPN. The
                // ordinary live-policy checks above still require retained TCP.
                JSONObject reinstalled=appProbe(1,"open","reinstalled",false);
                JSONObject reinstalledDns=appProbe(1,"txt","reinstalled",false);
                progress("PACKAGE_LIFECYCLE_OBSERVATIONS "+new JSONObject().put("new_tcp",reinstalled).put("new_dns",reinstalledDns));
                require(reinstalled.getBoolean("ok") && reinstalled.optString("route").equals("VPN"),"reinstalled always-VPN app escaped its policy");
                require(reinstalledDns.getBoolean("ok") && reinstalledDns.optString("answer").equals("VPN"),"reinstalled app lost VPN DNS context");
                require(connectionDiagnostics().getLong("session_id")!=session,"UID replacement did not restart the VPN session");
                progress("PACKAGE_LIFECYCLE_RESULT "+new JSONObject().put("uid_changed",true).put("automatic_reconnect",true).put("vpn_tcp_dns",true).put("same_session",false));
                pass("package reinstall with a new UID automatically reconnects and restores VPN TCP/DNS");
                retainedCheck=false;
                disconnect();
                packageLifecycleCheckpoint("disconnected");
                SystemClock.sleep(2000);
                require(state==DISCONNECTED && !serviceError,"package event re-enabled manually disconnected VPN");
                progress("PACKAGE_LIFECYCLE_DISCONNECTED "+new JSONObject().put("stayed_disconnected",true));
            }
        } catch (Exception | AssertionError error) {
            // Preserve the live failure before this method disconnects in finally.
            applicationFailureDiagnostics = new JSONObject();
            try { applicationFailureDiagnostics = connectionDiagnostics(); } catch (Exception ignored) {}
            progress("RESOURCE_CHECKPOINT failure"); SystemClock.sleep(10000);
            throw error;
        } finally {
            retainedCheck=false;
            for(int i=0;i<2;i++)try{appProbe(i,"stop","old");}catch(Exception ignored){}
            if(androidUser != 0)try{personalProbe("stop","personal-old");}catch(Exception ignored){}
            if(state!=DISCONNECTED) disconnect();
        }
        pass("two real Android UIDs switch new TCP/UDP/DNS policy while original TCP and shared FakeIP survive");
    }

    private void automaticUploadMtu() throws Exception {
        JSONObject config = primaryConfiguration();
        // Keep IPv6 configured: its mandatory minimum must not prevent IPv4
        // from adapting below 1280 on this already established connection.
        config.getJSONObject(config.getString("protocol") + "_config_data").put("client_ip", "10.77.0.1/32, fd77::1/128")
            .put("allowed_ips", new JSONArray().put("0.0.0.0/0").put("::/0")).put("mtu", "1420")
            .put("path_mtu_probe", "10.77.0.2")
            .put("path_mtu_probes", new JSONArray().put("10.77.0.2").put("fd77::2"));
        state = -1; serviceError = false; startService(config); awaitState(CONNECTED, false);
        long session = connectionDiagnostics().getLong("session_id");
        JSONObject before = retainedCheckpoint("upload_mtu_before");
        ExecutorService interactiveIo = Executors.newSingleThreadExecutor();
        ExecutorService uploadIo = Executors.newSingleThreadExecutor();
        Socket interactive = null, media = null;
        boolean fault = false;
        try {
            interactive = retainedVpnSocket(dns("vpn.test", 1), "172.19.0.1");
            media = retainedVpnSocket(dns("vpn.test", 1), "172.19.0.1"); media.setSoTimeout(60000);
            // Keep both original sockets through at least two normal worker
            // periods. The impairment must exercise a changed established path,
            // rather than just the first probe after connecting the VPN.
            long opened = SystemClock.elapsedRealtime();
            while (SystemClock.elapsedRealtime() - opened < 65000) {
                exchange(interactiveIo, interactive, new byte[]{42});
                exchange(uploadIo, media, new byte[]{43});
                SystemClock.sleep(250);
            }
            long ageAtFault = SystemClock.elapsedRealtime() - opened;
            retainedCheckpoint("drop_upload_mtu"); fault = true;
            final Socket originalMedia = media;
            byte[] payload = new byte[256 * 1024]; new java.security.SecureRandom().nextBytes(payload);
            long started = SystemClock.elapsedRealtime();
            Future<?> transfer = uploadIo.submit(() -> {
                originalMedia.getOutputStream().write(payload);
                byte[] response = new byte[payload.length];
                new DataInputStream(originalMedia.getInputStream()).readFully(response);
                require(java.util.Arrays.equals(payload, response), "automatic MTU upload payload corrupted");
                return null;
            });
            while (!transfer.isDone() && SystemClock.elapsedRealtime() - started < 55000) {
                exchange(interactiveIo, interactive, new byte[]{42}); SystemClock.sleep(250);
            }
            transfer.get(1, TimeUnit.SECONDS);
            // The packet-size filter is still active here. No reconnect or
            // clearing the impairment may stand in for actual adaptation.
            JSONObject after = retainedCheckpoint("upload_mtu_after");
            require(connectionDiagnostics().getLong("session_id") == session, "MTU adaptation replaced the core");
            require(after.getLong("vpn_tcp") == before.getLong("vpn_tcp") + 2, "MTU adaptation redialled TCP");
            progress("MTU_UPLOAD_RESULT " + new JSONObject().put("elapsed_ms", SystemClock.elapsedRealtime() - started)
                .put("original_tcp_accepts", 2).put("age_before_fault_ms", ageAtFault)
                .put("same_session", true).put("filter_still_active", true));
        } finally {
            if (fault) retainedCheckpoint("restore_upload_mtu");
            if (media != null) media.close(); if (interactive != null) interactive.close();
            uploadIo.shutdownNow(); interactiveIo.shutdownNow(); disconnect();
        }
        pass("automatic client MTU restores original upload TCP while large encrypted packets remain blocked");
    }

    private void allVpnLockdown() throws Exception {
        state = -1; serviceError = false;startService(primaryConfiguration());awaitState(CONNECTED, false);
        long owner = connectionDiagnostics().getLong("session_id");
        retainedCheckpoint("safe_policy_before");
        policy("alwayson");policy("lockdown");SystemClock.sleep(1500);
        require(state == CONNECTED && !serviceError, "all-VPN shared core was rejected under lockdown");
        require(connectionDiagnostics().getLong("session_id") == owner, "safe lockdown replaced active core");
        requireRoute(dns("vpn.test", 1), "VPN");
        retainedCheckpoint("safe_policy_after");disconnect();policy("off");
        pass("all-VPN app-only shared core remains active under OS always-on/lockdown");
    }

    private void policy(String mode) throws Exception {
        File ready = new File(getTargetContext().getFilesDir(), "routing-policy-" + mode + ".ready");
        ready.delete();
        progress("POLICY_CHECKPOINT " + mode);
        long until = SystemClock.elapsedRealtime() + 20000;
        while (!ready.exists() && SystemClock.elapsedRealtime() < until) SystemClock.sleep(100);
        require(ready.exists(), "emulator policy driver did not acknowledge " + mode);
        ready.delete();
    }

    private void pass(String text) { passed.add(text); progress("PASS: " + text); }
    private void progress(String text) { Bundle b = new Bundle(); b.putString("stream", text + "\n"); sendStatus(0, b); }
    private static void require(boolean ok, String text) { if (!ok) throw new AssertionError(text); }
    private void send(int action, Bundle data) throws Exception {
        Message message = Message.obtain(); message.what = action; message.replyTo = replies; message.setData(data); service.send(message);
    }
    private void awaitState(int wanted, boolean allowError) throws Exception {
        long end = SystemClock.elapsedRealtime() + 30000;
        synchronized (lock) {
            // A rejected start emits DISCONNECTED and ERROR separately. Consume
            // both before starting the next session, so the previous error
            // cannot be misattributed to its successful replacement.
            while ((state != wanted || (allowError && !serviceError)) && (allowError || !serviceError) && SystemClock.elapsedRealtime() < end) lock.wait(100);
            require(state == wanted && (allowError ? serviceError : !serviceError), "service failed to reach state " + wanted);
        }
    }
    private void connect(boolean inverse) throws Exception {
        state = -1; serviceError = false;
        startService(configuration(inverse)); awaitState(CONNECTED, false);
    }

    private void ipv6Preference() throws Exception {
        JSONObject config = configuration(false);
        config.remove("ipv6_enabled"); // Real old-profile/default path.
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        InetAddress cached = dns("ipv6.test",28);
        require(cached.getAddress().length==16 && fake(cached),"default ON lost IPv6 FakeIP");
        InetAddress ula = InetAddress.getByName("fd77::2");
        InetAddress nat64 = InetAddress.getByName("64:ff9b::c000:201");
        for (InetAddress address : new InetAddress[]{cached,ula,nat64}) requireRoute(address,"VPN");
        disconnect();

        config.put("ipv6_enabled",false);
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        require(dnsAnswer("ipv6.test",28,true)==null,"OFF still returned AAAA");
        requireRoute(dns("vpn.test",1),"VPN");
        requireRoute(dns("direct.ru",1),"DIRECT");
        JSONObject before = control("/stats",false);
        for (InetAddress address : new InetAddress[]{cached,ula,nat64}) {
            String answer=null;
            try { answer=tcp(address); } catch (Exception expected) {}
            require(answer==null,"OFF leaked IPv6 TCP");
            answer=null;
            try { answer=udp(address); } catch (Exception expected) {}
            require(answer==null,"OFF leaked IPv6 UDP");
        }
        JSONObject after = control("/stats",false);
        for (String counter : new String[]{"direct_tcp","direct_udp","vpn_tcp","vpn_udp"})
            require(before.getLong(counter)==after.getLong(counter),"OFF delivered IPv6 to observer: "+counter);
        requireRoute(dns("vpn.test",1),"VPN");
        requireRoute(dns("direct.ru",1),"DIRECT");
        disconnect();

        config.put("ipv6_enabled",true);
        state=-1;serviceError=false;startService(config);awaitState(CONNECTED,false);
        requireRoute(dns("ipv6.test",28),"VPN");
        requireRoute(ula,"VPN");requireRoute(nat64,"VPN");
        disconnect();
        progress("IPV6_PREFERENCE_RESULT "+new JSONObject().put("default_on",true).put("explicit_on",true)
            .put("off_aaaa_nodata",true).put("off_cached_fakeip_and_literals_blocked",true)
            .put("blocked_tcp_udp_probes",6).put("independent_observers_unchanged",true)
            .put("ipv4_vpn_and_direct_preserved",true));
    }
    private void startService(JSONObject config) {
        Intent intent = new Intent().setComponent(new ComponentName("org.amnezia.vpn", "org.amnezia.vpn."+serviceClass()));
        intent.putExtra("VPN_CONFIG", config.toString());
        getTargetContext().startForegroundService(intent);
    }
    private void disconnect() throws Exception {
        state = -1; serviceError = false; send(DISCONNECT, new Bundle()); awaitState(DISCONNECTED, false);
    }
    private JSONObject configuration(boolean inverse) throws Exception {
        JSONObject config = new JSONObject(fixture.toString());
        JSONArray rules = new JSONArray();
        rules.put(rule("suffix", "direct.ru", "direct"));
        rules.put(rule("domain", "override.direct.ru", "vpn"));
        rules.put(rule("domain", "vpn.test", "vpn"));
        rules.put(rule("cidr", "10.0.2.2/32", "direct"));
        if(!observerIP.equals("10.0.2.2")) rules.put(rule("cidr",observerIP+(observerIP.contains(":")?"/128":"/32"),"direct"));
        rules.put(rule("cidr", "127.0.0.0/8", "direct"));
        rules.put(rule("cidr", "::1/128", "direct"));
        config.put("sing_box_routing", new JSONObject().put("version", 1).put("default", inverse ? "direct" : "vpn").put("rules", rules));
        return config;
    }
    private static JSONObject rule(String kind, String value, String action) throws Exception {
        return new JSONObject().put("kind", kind).put("value", value).put("action", action);
    }
    private static boolean fake(InetAddress address) {
        byte[] b = address.getAddress();
        return b.length == 4 ? (b[0] & 255) == 198 && ((b[1] & 254) == 18) : (b[0] & 255) == 252 && b[1] == 0 && (b[2] & 192) == 0;
    }
    private static String tcp(InetAddress address) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, 18081), 4000); socket.setSoTimeout(4000);
            return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
        }
    }
    private static String udp(InetAddress address) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(4000); byte[] nonce = "route-proof".getBytes(StandardCharsets.US_ASCII);
            socket.send(new DatagramPacket(nonce, nonce.length, address, 18082));
            DatagramPacket reply = new DatagramPacket(new byte[256], 256); socket.receive(reply);
            return new String(reply.getData(), 0, reply.getLength(), StandardCharsets.US_ASCII);
        }
    }
    private void requireRoute(InetAddress address, String expected) throws Exception {
        progress("CHECK: TCP to " + expected + " observer");
        require(expected.equals(tcp(address)), "TCP reached wrong observer; expected " + expected);
        progress("CHECK: UDP to " + expected + " observer");
        require((expected + ":route-proof").equals(udp(address)), "UDP reached wrong observer; expected " + expected);
    }
    private void quic(InetAddress address, String expected) throws Exception {
        File ca = new File(getTargetContext().getCacheDir(), "routing-quic-ca.der");
        try (InputStream input = getContext().getAssets().open("quic-ca.der");
             FileOutputStream output = new FileOutputStream(ca)) {
            byte[] buffer = new byte[4096]; int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
        }
        File executable = new File(getContext().getApplicationInfo().nativeLibraryDir, "libtrafficprobe.so");
        String host = address.getHostAddress();
        if (address.getAddress().length == 16) host = "[" + host + "]";
        Process process = new ProcessBuilder(executable.getAbsolutePath(), "--quic", host + ":18443", "--ca", ca.getAbsolutePath())
                .redirectErrorStream(true).start();
        try {
            require(process.waitFor(25, TimeUnit.SECONDS), "native QUIC probe timeout");
            StringBuilder result = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.US_ASCII))) {
                String line;
                while ((line = reader.readLine()) != null && result.length() < 4096) result.append(line).append('\n');
            }
            require(process.exitValue() == 0 && result.toString().trim().endsWith(expected),
                    "native QUIC expected " + expected + ": " + result);
        } finally {
            if (process.isAlive()) process.destroyForcibly();
            ca.delete();
        }
    }
    private static int u16(byte[] b, int i) { return ((b[i] & 255) << 8) | (b[i + 1] & 255); }
    private static int skipName(byte[] b, int i) {
        while (i < b.length && b[i] != 0) { if ((b[i] & 192) == 192) return i + 2; i += 1 + (b[i] & 255); }
        return i + 1;
    }
    private static InetAddress dns(String name, int type) throws Exception {
        return dnsAnswer(name,type,false);
    }
    private static InetAddress dnsAnswer(String name, int type, boolean allowNoData) throws Exception {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream out = new java.io.DataOutputStream(bytes);
        out.writeShort(123); out.writeShort(0x100); out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(0);
        for (String label : name.split("\\.")) { byte[] b = label.getBytes(StandardCharsets.US_ASCII); out.writeByte(b.length); out.write(b); }
        out.writeByte(0); out.writeShort(type); out.writeShort(1);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); byte[] query = bytes.toByteArray();
            socket.send(new DatagramPacket(query, query.length, InetAddress.getByName("172.19.0.2"), 53));
            DatagramPacket packet = new DatagramPacket(new byte[4096], 4096); socket.receive(packet);
            byte[] b = java.util.Arrays.copyOf(packet.getData(), packet.getLength());
            require(u16(b, 0) == 123 && (u16(b, 2) & 0x800f) == 0x8000, "DNS error");
            int i = skipName(b, 12) + 4;
            for (int n = 0; n < u16(b, 6); ++n) {
                i = skipName(b, i); int rrtype = u16(b, i), length = u16(b, i + 8); i += 10;
                if (rrtype == type && length == (type == 1 ? 4 : 16)) return InetAddress.getByAddress(java.util.Arrays.copyOfRange(b, i, i + length));
                i += length;
            }
            if (allowNoData && u16(b,6)==0) return null;
            throw new AssertionError("missing DNS address");
        }
    }
    private JSONObject control(String path, boolean post) throws Exception {
        long request = System.nanoTime();
        if (diagnoseControl) progress("CONTROL_PENDING " + request);
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("10.0.2.2", 18080), 4000); socket.setSoTimeout(4000);
            socket.getOutputStream().write(((post ? "POST " : "GET ") + path + " HTTP/1.0\r\nHost: 10.0.2.2\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            require(reader.readLine().contains("200"), "fixture control failed");
            String line; while ((line = reader.readLine()) != null && !line.isEmpty()) {}
            return post ? new JSONObject() : new JSONObject(reader.readLine());
        } finally {
            if (diagnoseControl) progress("CONTROL_FINISHED " + request);
        }
    }
    private static void loopback(String ip) throws Exception {
        InetAddress address = InetAddress.getByName(ip);
        try (ServerSocket listener = new ServerSocket(0, 1, address)) {
            Thread worker = new Thread(() -> { try (Socket peer = listener.accept()) { peer.getOutputStream().write(7); } catch (Exception ignored) {} });
            listener.setSoTimeout(4000); worker.start();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(address, listener.getLocalPort()), 4000); socket.setSoTimeout(4000);
                require(socket.getInputStream().read() == 7, "loopback was rerouted");
            }
            worker.join(5000); require(!worker.isAlive(), "loopback worker leaked");
        }
    }
}
