package org.amnezia.uidprobe;

import android.app.Instrumentation;
import android.os.Bundle;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public class Probe extends Instrumentation {
    private String sharedName;
    private volatile String systemResult="pending";
    private volatile String txtResult="not_requested";
    private boolean systemTxt;
    @Override public void onCreate(Bundle args){super.onCreate(args);sharedName=args.getString("shared_name");systemTxt="true".equals(args.getString("system_txt"));start();}
    private void queryTxt(String name)throws Exception {
        txtResult="pending";
        java.util.concurrent.CountDownLatch finished=new java.util.concurrent.CountDownLatch(1);
        android.os.CancellationSignal cancel=new android.os.CancellationSignal();
        android.net.DnsResolver.getInstance().rawQuery(null,name,1,16,0,Runnable::run,cancel,
            new android.net.DnsResolver.Callback<byte[]>() {
                @Override public void onAnswer(byte[] answer,int rcode) {
                    txtResult=rcode==0 && answer.length>=5 ? new String(answer,answer.length-5,5,java.nio.charset.StandardCharsets.US_ASCII) : "rcode="+rcode;
                    finished.countDown();
                }
                @Override public void onError(android.net.DnsResolver.DnsException error) {txtResult=error.toString();finished.countDown();}
            });
        if(!finished.await(8,java.util.concurrent.TimeUnit.SECONDS)){cancel.cancel();throw new java.io.IOException("system TXT timeout");}
    }
    @Override public void onStart(){
        String label=getTargetContext().getPackageName().endsWith(".a")?"a":"b";
        String unique=Long.toString(System.nanoTime());
        Thread dns=new Thread(()->{
            for(int attempt=0;attempt<10;attempt++) {
                try {
                    InetAddress[] addresses=InetAddress.getAllByName(sharedName!=null?sharedName:"system-"+label+"-"+unique+"-"+attempt+".uid.test");
                    systemResult=java.util.Arrays.toString(addresses);
                    // Attribute the original tuple of the subsequent flow,
                    // even when netd hid the UID of the DNS request itself.
                    try(Socket resolved=new Socket()) {
                        resolved.connect(new InetSocketAddress(addresses[0],18083),2000);
                    } catch(java.io.IOException expectedPacketSink) {}
                    if(systemTxt)queryTxt(sharedName!=null?"txt-"+sharedName:"txt-"+label+"-"+unique+".uid.test");
                    return;
                }
                catch(Exception error){try{Thread.sleep(200);}catch(InterruptedException cancelled){return;}}
            }
        });
        dns.setDaemon(true);
        try(DatagramSocket udp=new DatagramSocket();DatagramSocket rawDns=new DatagramSocket();Socket tcp=new Socket()){
            udp.connect(InetAddress.getByName("198.51.100.10"),18082);
            boolean sent=false;
            for(int attempt=0;attempt<10;attempt++) {
                try {udp.send(new DatagramPacket(new byte[]{1},1));sent=true;break;}
                catch(java.io.IOException error){if(attempt==9)throw error;Thread.sleep(200);}
            }
            if(!sent)throw new java.io.IOException("UDP probe was not sent");
            Thread.sleep(200);dns.start();
            java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
            bytes.write(new byte[]{1,2,1,0,0,1,0,0,0,0,0,0});
            for(String part:("raw-"+label+"-"+unique+".uid.test").split("\\.")){
                byte[] value=part.getBytes(java.nio.charset.StandardCharsets.US_ASCII);bytes.write(value.length);bytes.write(value);
            }
            bytes.write(new byte[]{0,0,1,0,1});byte[] query=bytes.toByteArray();
            rawDns.connect(InetAddress.getByName("172.31.255.2"),53);rawDns.send(new DatagramPacket(query,query.length));
            try{tcp.connect(new InetSocketAddress("198.51.100.10",18081),sharedName!=null?2000:8000);}catch(Exception ignored){}
            // Do not report an unfinished resolver as a cache observation.
            // Shared-name probes need the actual result from both applications.
            if(sharedName!=null)dns.join(12000);
            else Thread.sleep(3000);
        }catch(Exception error){Bundle failure=new Bundle();failure.putString("failure",error.toString());finish(-1,failure);return;}
        Bundle result=new Bundle();result.putString("system_result",systemResult);result.putString("system_txt_result",txtResult);
        if(sharedName!=null && dns.isAlive()) {
            result.putString("failure","system resolver did not complete within 12 seconds");
            finish(-1,result);return;
        }
        finish(0,result);
    }
}
