package org.amnezia.uidprobe;

import android.app.Instrumentation;
import android.os.Bundle;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public class Probe extends Instrumentation {
    @Override public void onCreate(Bundle args){super.onCreate(args);start();}
    @Override public void onStart(){
        String label=getTargetContext().getPackageName().endsWith(".a")?"a":"b";
        String unique=Long.toString(System.nanoTime());
        Thread dns=new Thread(()->{
            for(int attempt=0;attempt<10;attempt++) {
                try {InetAddress.getAllByName("system-"+label+"-"+unique+"-"+attempt+".uid.test");return;}
                catch(Exception error){try{Thread.sleep(200);}catch(InterruptedException cancelled){return;}}
            }
        });
        dns.setDaemon(true);dns.start();
        try(DatagramSocket udp=new DatagramSocket();DatagramSocket rawDns=new DatagramSocket();Socket tcp=new Socket()){
            udp.connect(InetAddress.getByName("198.51.100.10"),18082);
            boolean sent=false;
            for(int attempt=0;attempt<10;attempt++) {
                try {udp.send(new DatagramPacket(new byte[]{1},1));sent=true;break;}
                catch(java.io.IOException error){if(attempt==9)throw error;Thread.sleep(200);}
            }
            if(!sent)throw new java.io.IOException("UDP probe was not sent");
            java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();
            bytes.write(new byte[]{1,2,1,0,0,1,0,0,0,0,0,0});
            for(String part:("raw-"+label+"-"+unique+".uid.test").split("\\.")){
                byte[] value=part.getBytes(java.nio.charset.StandardCharsets.US_ASCII);bytes.write(value.length);bytes.write(value);
            }
            bytes.write(new byte[]{0,0,1,0,1});byte[] query=bytes.toByteArray();
            rawDns.connect(InetAddress.getByName("172.31.255.2"),53);rawDns.send(new DatagramPacket(query,query.length));
            try{tcp.connect(new InetSocketAddress("198.51.100.10",18081),8000);}catch(Exception ignored){}
            Thread.sleep(3000);
        }catch(Exception error){Bundle failure=new Bundle();failure.putString("failure",error.toString());finish(-1,failure);return;}
        finish(0,new Bundle());
    }
}
