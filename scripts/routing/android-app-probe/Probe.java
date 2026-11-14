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
                        if (operation.equals("open") || operation.equals("open-ip")) {
                            if (streams.containsKey(tag)) throw new IOException("stream already exists");
                            InetAddress address = operation.equals("open-ip") ? InetAddress.getByName(command.getString("address")) : address();
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
                        } else if (operation.equals("isolated") || operation.equals("isolated-echo")) {
                            Socket stream = streams.get(tag);
                            if (stream == null) throw new IOException("missing original stream");
                            reply.put("isolated", isolated(stream, command.getString("address"), operation.equals("isolated")))
                                .put("local_port", stream.getLocalPort());
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
    private JSONObject isolated(Socket stream, String address, boolean probeNetwork) throws Exception {
        android.content.Context context = getTargetContext();
        java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(1);
        android.os.IBinder[] peer = new android.os.IBinder[1];
        android.content.ServiceConnection connection = new android.content.ServiceConnection() {
            public void onServiceConnected(android.content.ComponentName name, android.os.IBinder binder) { peer[0]=binder;ready.countDown(); }
            public void onServiceDisconnected(android.content.ComponentName name) { }
        };
        android.content.Intent intent = new android.content.Intent().setClassName(context.getPackageName(), "org.amnezia.appprobe.Probe$IsolatedService");
        if (!context.bindService(intent, connection, android.content.Context.BIND_AUTO_CREATE)) throw new IOException("isolated service bind rejected");
        try {
            if (!ready.await(5, java.util.concurrent.TimeUnit.SECONDS)) throw new IOException("isolated service bind timeout");
            android.os.Parcel request=android.os.Parcel.obtain(),response=android.os.Parcel.obtain();
            try (android.os.ParcelFileDescriptor fd=android.os.ParcelFileDescriptor.fromSocket(stream)) {
                request.writeInterfaceToken("amnezia.isolated.probe");
                request.writeInt(probeNetwork?1:0);
                request.writeByteArray(InetAddress.getByName(address).getAddress());
                request.writeParcelable(fd,0);
                if (!peer[0].transact(android.os.IBinder.FIRST_CALL_TRANSACTION,request,response,0)) throw new IOException("isolated transaction rejected");
                response.readException();return new JSONObject(response.readString());
            } finally { request.recycle();response.recycle(); }
        } finally { context.unbindService(connection); }
    }
    /** Real Android isolated UID; no permissions or network binding are granted by the fixture. */
    public static final class IsolatedService extends android.app.Service {
        @Override public android.os.IBinder onBind(android.content.Intent intent) {
            return new android.os.Binder() {
                @Override protected boolean onTransact(int code, android.os.Parcel input, android.os.Parcel output, int flags) throws android.os.RemoteException {
                    if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code,input,output,flags);
                    input.enforceInterface("amnezia.isolated.probe");
                    try {
                        boolean probeNetwork=input.readInt()!=0;
                        InetAddress address=InetAddress.getByAddress(input.createByteArray());
                        try (android.os.ParcelFileDescriptor fd=input.readParcelable(getClass().getClassLoader())) {
                        JSONObject result=new JSONObject().put("uid",Process.myUid());
                        if(probeNetwork) { result.put("tcp", attempt(address,false));result.put("udp",attempt(address,true)); }
                        result.put("delegated_port",((InetSocketAddress)android.system.Os.getsockname(fd.getFileDescriptor())).getPort());
                        byte[] payload="isolated-old-tcp".getBytes(StandardCharsets.US_ASCII);
                        android.system.Os.write(fd.getFileDescriptor(),payload,0,payload.length);
                        byte[] received=new byte[payload.length];int count=0;
                        while(count<received.length) {
                            android.system.StructPollfd poll=new android.system.StructPollfd();poll.fd=fd.getFileDescriptor();poll.events=(short)android.system.OsConstants.POLLIN;
                            if(android.system.Os.poll(new android.system.StructPollfd[]{poll},2000)!=1)throw new IOException("delegated echo timeout");
                            int n=android.system.Os.read(fd.getFileDescriptor(),received,count,received.length-count);
                            if(n<=0)throw new EOFException("delegated echo closed");count+=n;
                        }
                        if(!java.util.Arrays.equals(payload,received))throw new IOException("delegated echo mismatch");
                        result.put("delegated_echo",true);output.writeNoException();output.writeString(result.toString());return true;
                        }
                    } catch(Exception error) { throw new android.os.RemoteException(error.toString()); }
                }
            };
        }
        private static String attempt(InetAddress address,boolean udp) throws Exception {
            try {
                if(udp)try(DatagramSocket socket=new DatagramSocket()) {
                    socket.setSoTimeout(2000);byte[] payload="app-policy-proof".getBytes(StandardCharsets.US_ASCII);
                    socket.send(new DatagramPacket(payload,payload.length,address,18082));
                    DatagramPacket response=new DatagramPacket(new byte[256],256);socket.receive(response);
                    return new String(response.getData(),0,response.getLength(),StandardCharsets.US_ASCII);
                }
                else try(Socket socket=new Socket()) {
                    socket.connect(new InetSocketAddress(address,18081),2000);socket.setSoTimeout(2000);return line(socket.getInputStream());
                }
            } catch(SecurityException denied) { return "ANDROID_PERMISSION_DENIED"; }
            catch(IOException error) {
                for(Throwable cause=error;cause!=null;cause=cause.getCause())if(cause instanceof android.system.ErrnoException) {
                    int errno=((android.system.ErrnoException)cause).errno;
                    if(errno==android.system.OsConstants.EACCES||errno==android.system.OsConstants.EPERM)return "ANDROID_PERMISSION_DENIED";
                }
                throw error;
            }
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
