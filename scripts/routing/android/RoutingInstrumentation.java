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
import java.util.concurrent.TimeUnit;

/** Tests the installed production service over its existing Messenger API.
 * No alternate VpnService, TUN fixture, native library or production test hook.
 * IPC numbers below are checked against source by the host driver.
 */
public final class RoutingInstrumentation extends Instrumentation {
    private static final int REGISTER = 0, UNREGISTER = 1, CONNECT = 2, DISCONNECT = 3;
    private static final int DISCONNECTED = 0, CONNECTED = 1;
    private final Object lock = new Object();
    private final List<String> passed = new ArrayList<>();
    private volatile int state = -1;
    private volatile boolean serviceError;
    private Messenger service, replies;
    private JSONObject fixture;
    private int cycles = 100;
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
                    if (message.what == 0 || message.what == 1) state = message.getData().getInt("state", -1);
                    if (message.what == 3) serviceError = true;
                    lock.notifyAll();
                }
                return true;
            }));
            Intent intent = new Intent().setComponent(new ComponentName("org.amnezia.vpn", "org.amnezia.vpn.AwgService"));
            didBind = getTargetContext().bindService(intent, connection, Context.BIND_AUTO_CREATE);
            require(didBind && bound.await(15, TimeUnit.SECONDS), "AwgService binding failed");
            Bundle registration = new Bundle(); registration.putString("CLIENT_NAME", "routing-acceptance");
            send(REGISTER, registration);
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
            InetAddress[] system = InetAddress.getAllByName("system.direct.ru");
            InetAddress four = null;
            for (InetAddress address : system) if (address.getAddress().length == 4) four = address;
            require(four != null && fake(four), "system resolver did not use managed DNS");
            requireRoute(four, "DIRECT"); pass("Android system resolver uses the installed VPN DNS");
            loopback("127.0.0.1"); loopback("::1"); pass("native IPv4/IPv6 loopback stays local");

            JSONObject before = control("/stats", false);
            control("/peer?state=off", true);
            boolean tcpFailed = false, udpFailed = false;
            try { tcp(vpn); } catch (Exception expected) { tcpFailed = true; }
            try { udp(vpn); } catch (Exception expected) { udpFailed = true; }
            require(tcpFailed && udpFailed, "VPN traffic succeeded with the AWG peer down");
            JSONObject after = control("/stats", false);
            require(before.getLong("direct_tcp") == after.getLong("direct_tcp") && before.getLong("direct_udp") == after.getLong("direct_udp"), "VPN traffic fell back to the DIRECT observer");
            // Real upstream DNS may need VPN, so do not claim fresh uncached
            // names resolve during outage. A literal DIRECT destination works.
            requireRoute(InetAddress.getByName("10.0.2.2"), "DIRECT");
            control("/peer?state=on", true);
            disconnect(); connect(true);
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
            result.putString("routing_result", "PASS"); code = 0;
        } catch (Throwable error) {
            // Avoid dumping fixture/keys in an exception or Android log.
            result.putString("routing_result", "FAIL");
            result.putString("failure", error.getClass().getSimpleName() + ": " + error.getMessage());
            StringBuilder stack = new StringBuilder();
            for (StackTraceElement frame : error.getStackTrace()) if (frame.getClassName().startsWith("org.amnezia.routingtest")) stack.append(frame).append("\n");
            result.putString("test_stack", stack.toString());
        } finally {
            if (service != null) try { send(DISCONNECT, new Bundle()); send(UNREGISTER, new Bundle()); } catch (Exception ignored) {}
            if (didBind) getTargetContext().unbindService(connection);
            result.putString("passed", new JSONArray(passed).toString());
            finish(code, result);
        }
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
            while (state != wanted && (allowError || !serviceError) && SystemClock.elapsedRealtime() < end) lock.wait(100);
            require(state == wanted && (allowError || !serviceError), "service failed to reach state " + wanted);
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
