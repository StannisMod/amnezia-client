package org.amnezia.appprobe;

import android.app.Instrumentation;
import android.os.Bundle;
import android.os.Process;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

/** An independent application UID owns every tested DNS/TCP/UDP socket. */
public final class Probe extends Instrumentation {
    private int port;
    private final Map<String, Socket> streams = new HashMap<>();
    private final Map<String, String> routes = new HashMap<>();
    private final Set<Integer> udpPorts = new HashSet<>();
    private static final String DOMAIN = "shared.app-policy.test";
    @Override public void onCreate(Bundle args) {
        super.onCreate(args); port = Integer.parseInt(args.getString("port")); start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try (ServerSocket broker = new ServerSocket()) {
            broker.bind(new InetSocketAddress("127.0.0.1", port)); broker.setSoTimeout(2400000);
            boolean running = true;
            while (running) {
                try (Socket control = broker.accept()) {
                    control.setSoTimeout(15000);
                    JSONObject reply = new JSONObject().put("uid", Process.myUid()).put("package", getTargetContext().getPackageName());
                    try {
                        JSONObject command = new JSONObject(new BufferedReader(new InputStreamReader(control.getInputStream(), StandardCharsets.UTF_8)).readLine());
                        String operation = command.getString("op"), tag = command.optString("tag", "old");
                        if (operation.equals("open")) {
                            if (streams.containsKey(tag)) throw new IOException("stream already exists");
                            InetAddress address = address();
                            Socket stream = new Socket(); stream.setSoTimeout(8000);
                            try {
                                stream.connect(new InetSocketAddress(address, 18081), 8000);
                                String route = line(stream.getInputStream());
                                streams.put(tag, stream); routes.put(tag, route);
                                reply.put("route", route).put("address", address.getHostAddress()).put("local_port", stream.getLocalPort());
                            } catch (Exception failure) { stream.close(); throw failure; }
                        } else if (operation.equals("echo")) {
                            Socket stream = streams.get(tag);
                            if (stream == null) throw new IOException("missing original stream");
                            byte[] payload = command.getString("payload").getBytes(StandardCharsets.UTF_8);
                            stream.getOutputStream().write(payload);
                            byte[] response = new byte[payload.length]; new DataInputStream(stream.getInputStream()).readFully(response);
                            if (!java.util.Arrays.equals(payload, response)) throw new IOException("echo mismatch");
                            reply.put("route", routes.get(tag)).put("local_port", stream.getLocalPort()).put("echo", new String(response, StandardCharsets.UTF_8));
                        } else if (operation.equals("udp")) {
                            try (DatagramSocket socket = freshUdp()) {
                                socket.setSoTimeout(8000);
                                byte[] payload = "app-policy-proof".getBytes(StandardCharsets.US_ASCII);
                                socket.send(new DatagramPacket(payload, payload.length, address(), 18082));
                                DatagramPacket response = new DatagramPacket(new byte[256], 256); socket.receive(response);
                                reply.put("reply", new String(response.getData(), 0, response.getLength(), StandardCharsets.US_ASCII));
                            }
                        } else if (operation.equals("txt")) {
                            reply.put("answer", txt());
                        } else if (operation.equals("stop")) {
                            running = false;
                        } else if (!operation.equals("ready")) throw new IOException("unknown operation");
                        reply.put("ok", true);
                    } catch (Exception failure) {
                        reply.put("ok", false).put("error", failure.getClass().getSimpleName()+": "+failure.getMessage());
                    }
                    control.getOutputStream().write((reply.toString()+"\n").getBytes(StandardCharsets.UTF_8));
                }
            }
            result.putString("probe_result", "PASS"); finish(0, result);
        } catch (Exception failure) {
            result.putString("probe_result", "FAIL"); result.putString("error", failure.toString()); finish(-1, result);
        } finally {
            for (Socket stream : streams.values()) try { stream.close(); } catch (IOException ignored) {}
        }
    }
    private DatagramSocket freshUdp() throws IOException {
        for (int i=0;i<32;i++) {
            DatagramSocket socket = new DatagramSocket();
            if (udpPorts.add(socket.getLocalPort())) return socket;
            socket.close();
        }
        throw new IOException("could not allocate a fresh UDP tuple");
    }
    private static InetAddress address() throws Exception {
        for (InetAddress address : InetAddress.getAllByName(DOMAIN)) if (address.getAddress().length == 4) return address;
        throw new IOException("missing IPv4 answer");
    }
    private static String line(InputStream stream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (int i=0;i<64;i++) { int value=stream.read(); if(value<0)throw new EOFException(); if(value=='\n')return result.toString("US-ASCII"); result.write(value); }
        throw new IOException("invalid route banner");
    }
    private static String txt() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = new DataOutputStream(bytes);
        out.writeShort(123);out.writeShort(0x100);out.writeShort(1);out.writeShort(0);out.writeShort(0);out.writeShort(0);
        for(String label:DOMAIN.split("\\.")){byte[] part=label.getBytes(StandardCharsets.US_ASCII);out.writeByte(part.length);out.write(part);}
        out.writeByte(0);out.writeShort(16);out.writeShort(1);
        try(DatagramSocket socket=new DatagramSocket()) {
            socket.setSoTimeout(8000);byte[] query=bytes.toByteArray();
            socket.send(new DatagramPacket(query,query.length,InetAddress.getByName("172.19.0.2"),53));
            DatagramPacket packet=new DatagramPacket(new byte[4096],4096);socket.receive(packet);byte[] answer=packet.getData();
            if(u16(answer,0)!=123 || (u16(answer,2)&0x800f)!=0x8000)throw new IOException("DNS error");
            int offset=skipName(answer,12)+4;
            for(int i=0;i<u16(answer,6);i++) {
                offset=skipName(answer,offset);int kind=u16(answer,offset),length=u16(answer,offset+8);offset+=10;
                if(kind==16 && length>1 && (answer[offset]&255)+1<=length)return new String(answer,offset+1,answer[offset]&255,StandardCharsets.US_ASCII);
                offset+=length;
            }
            throw new IOException("missing TXT answer");
        }
    }
    private static int u16(byte[] b,int i){return ((b[i]&255)<<8)|(b[i+1]&255);}
    private static int skipName(byte[] b,int i){while(b[i]!=0){if((b[i]&192)==192)return i+2;i+=1+(b[i]&255);}return i+1;}
}
