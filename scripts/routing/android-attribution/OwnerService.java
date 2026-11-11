package org.amnezia.uidprobe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.json.JSONObject;

/** Disposable packet sink for observing Android UID attribution, not a VPN backend. */
public class OwnerService extends VpnService {
    private ParcelFileDescriptor tunnel;
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        NotificationManager manager=getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("probe","UID probe",NotificationManager.IMPORTANCE_LOW));
        startForeground(1,new Notification.Builder(this,"probe").setContentTitle("Disposable UID probe").setSmallIcon(android.R.drawable.stat_sys_warning).build());
        if(tunnel!=null)return START_NOT_STICKY;
        try {
            tunnel=new Builder().setBlocking(true).setSession("UID attribution experiment").setMtu(1280)
                .addAddress("172.31.255.1",30).addDnsServer("172.31.255.2").addRoute("0.0.0.0",0)
                .addAllowedApplication("org.amnezia.uidprobe.a").addAllowedApplication("org.amnezia.uidprobe.b").establish();
            if(tunnel==null)throw new IllegalStateException("VPN establish returned null");
            new Thread(this::capture,"uid-packet-probe").start();
        }catch(Exception error){android.util.Log.e("UidProbe","start failed",error);stopSelf();}
        return START_NOT_STICKY;
    }
    private static int u16(byte[] p,int o){return ((p[o]&255)<<8)|(p[o+1]&255);}
    private void capture(){
        try(FileInputStream input=new FileInputStream(tunnel.getFileDescriptor());
            FileOutputStream output=openFileOutput("events.jsonl",MODE_PRIVATE)){
            byte[] packet=new byte[65535];int length;
            while((length=input.read(packet))>0){
                if(length<28 || (packet[0]>>4)!=4)continue;
                int header=(packet[0]&15)*4,protocol=packet[9]&255;
                if(header<20 || length<header+8 || (protocol!=6 && protocol!=17))continue;
                String name="";
                int destination=u16(packet,header+2);
                if(protocol==17 && destination==53){
                    int pos=header+8+12;
                    StringBuilder label=new StringBuilder();
                    while(pos<length && packet[pos]!=0){
                        int count=packet[pos++]&255;
                        if(count>63 || pos+count>length)break;
                        label.append(new String(packet,pos,count,java.nio.charset.StandardCharsets.US_ASCII)).append('.');pos+=count;
                    }
                    name=label.toString();
                    if(!name.endsWith(".uid.test."))continue;
                }else if(destination!=18081 && destination!=18082)continue;
                InetAddress local=InetAddress.getByAddress(java.util.Arrays.copyOfRange(packet,12,16));
                InetAddress remote=InetAddress.getByAddress(java.util.Arrays.copyOfRange(packet,16,20));
                int uid=getSystemService(ConnectivityManager.class).getConnectionOwnerUid(protocol,
                    new InetSocketAddress(local,u16(packet,header)),new InetSocketAddress(remote,destination));
                JSONObject event=new JSONObject().put("uid",uid).put("protocol",protocol).put("source_port",u16(packet,header))
                    .put("destination_port",destination).put("dns_name",name);
                output.write((event.toString()+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));output.flush();
            }
        }catch(Exception error){android.util.Log.e("UidProbe","capture failed",error);}
    }
    @Override public void onDestroy(){try{if(tunnel!=null)tunnel.close();}catch(Exception ignored){}super.onDestroy();}
}
