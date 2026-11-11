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
    private volatile JSONObject diagnostics;
    private volatile boolean retainedCheck;
    private volatile boolean retainedStateChanged;
    private JSONObject retainedResult;
    private Messenger service, replies;
    private JSONObject fixture;
    private int cycles = 100;
    private boolean primaryOnly;
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
        cycles = Integer.parseInt(args.getString("cycles", "100"));
        primaryOnly = Boolean.parseBoolean(args.getString("primary_only", "false"));
        start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        int code = -1;
        boolean didBind = false;
        try {
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
                    if (message.what == 3) { serviceError = true; serviceErrorText = message.getData().getString("ERROR", ""); }
                    lock.notifyAll();
                }
                return true;
            }));
            Intent intent = new Intent().setComponent(new ComponentName("org.amnezia.vpn", "org.amnezia.vpn.AwgService"));
            didBind = getTargetContext().bindService(intent, connection, Context.BIND_AUTO_CREATE);
            require(didBind && bound.await(15, TimeUnit.SECONDS), "AwgService binding failed");
            Bundle registration = new Bundle(); registration.putString("CLIENT_NAME", "routing-acceptance");
            send(REGISTER, registration);
            if (primaryOnly) {
                retainedPrimarySession();
                result.putString("retained_result", retainedResult.toString());
                result.putString("routing_result", "PASS_PRIMARY_ONLY");code = 0;return;
            }
            connect(false);
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

            JSONObject before = control("/stats", false);
            control("/peer?state=off", true);
            boolean tcpFailed = false, udpFailed = false;
            try { tcpFailed = tcp(vpn) == null; } catch (Exception expected) { tcpFailed = true; }
            try { udp(vpn); } catch (Exception expected) { udpFailed = true; }
            require(tcpFailed && udpFailed, "VPN traffic succeeded with the AWG peer down");
            JSONObject after = control("/stats", false);
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
            requireRoute(InetAddress.getByName("10.77.0.2"), "VPN");
            quic(InetAddress.getByName("10.77.0.2"), "VPN");
            disconnect(); connect(false);
            requireRoute(dns("vpn.test", 1), "VPN"); disconnect();
            pass("legacy AWG TCP/UDP/QUIC and routed-to-legacy-to-routed service transition");
            retainedPrimarySession();
            restrictedProfiles();
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
            try { result.putString("observers", control("/stats", false).toString()); } catch (Exception ignored) {}
            // Let the rooted driver snapshot the failed session before the
            // finally block disconnects it and removes its capture routes.
            progress("RESOURCE_CHECKPOINT failure"); SystemClock.sleep(3000);
        } finally {
            if (service != null) try { send(DISCONNECT, new Bundle()); send(UNREGISTER, new Bundle()); } catch (Exception ignored) {}
            if (didBind) getTargetContext().unbindService(connection);
            result.putString("passed", new JSONArray(passed).toString());
            finish(code, result);
        }
    }

    private void performanceComparison() throws Exception {
        for (boolean legacy : new boolean[]{true, false}) {
            String mode = legacy ? "legacy" : "shared";
            JSONObject config = primaryConfiguration();
            if (legacy) {
                config.remove("sing_box_routing"); config.remove("sing_box_dns");
                config.put("android_legacy_awg_backend", true);
            }
            startService(config); awaitState(CONNECTED, false);
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
                progress("PERFORMANCE " + new JSONObject().put("backend", mode).put("bytes", bytes).put("elapsed_ms", elapsed));
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

    private JSONObject primaryConfiguration() throws Exception {
        JSONObject config = new JSONObject(fixture.toString());
        config.remove("sing_box_routing"); config.remove("sing_box_dns");
        config.remove("sing_box_dns_path");
        config.put("splitTunnelType", 0).put("splitTunnelSites", new JSONArray());
        config.put("appSplitTunnelType", 1).put("splitTunnelApps", new JSONArray().put("org.amnezia.vpn"));
        return config;
    }

    private Socket retainedSocket(InetAddress address) throws Exception {
        Socket socket = new Socket(); socket.setSoTimeout(30000);
        socket.connect(new InetSocketAddress(address, 18081), 10000);
        byte[] banner = new byte[4]; new DataInputStream(socket.getInputStream()).readFully(banner);
        require("VPN\n".equals(new String(banner, StandardCharsets.US_ASCII)), "retained socket reached non-VPN observer");
        return socket;
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
            interactive = retainedSocket(dns("vpn.test", 1));
            exchange(io, interactive, "before-fault".getBytes(StandardCharsets.US_ASCII));
            retainedCheckpoint("drop_before_media");SystemClock.sleep(3000);retainedCheckpoint("restore_before_media");
            exchange(io, interactive, "after-first-loss".getBytes(StandardCharsets.US_ASCII));
            media = retainedSocket(dns("ipv6.test", 28));
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
    private void startService(JSONObject config) {
        Intent intent = new Intent().setComponent(new ComponentName("org.amnezia.vpn", "org.amnezia.vpn.AwgService"));
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
            throw new AssertionError("missing DNS address");
        }
    }
    private static JSONObject control(String path, boolean post) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("10.0.2.2", 18080), 4000); socket.setSoTimeout(4000);
            socket.getOutputStream().write(((post ? "POST " : "GET ") + path + " HTTP/1.0\r\nHost: fixture\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            require(reader.readLine().contains("200"), "fixture control failed");
            String line; while ((line = reader.readLine()) != null && !line.isEmpty()) {}
            return post ? new JSONObject() : new JSONObject(reader.readLine());
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
