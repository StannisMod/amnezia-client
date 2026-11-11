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
            FileOutputStream output=openFileOutput("events.jsonl",MODE_PRIVATE);
            FileOutputStream replies=new FileOutputStream(tunnel.getFileDescriptor())){
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
                }else if(destination!=18081 && destination!=18082 && destination!=18083)continue;
                InetAddress local=InetAddress.getByAddress(java.util.Arrays.copyOfRange(packet,12,16));
                InetAddress remote=InetAddress.getByAddress(java.util.Arrays.copyOfRange(packet,16,20));
                int uid=getSystemService(ConnectivityManager.class).getConnectionOwnerUid(protocol,
                    new InetSocketAddress(local,u16(packet,header)),new InetSocketAddress(remote,destination));
                JSONObject event=new JSONObject().put("uid",uid).put("protocol",protocol).put("source_port",u16(packet,header))
                    .put("destination_port",destination).put("destination_address",remote.getHostAddress()).put("dns_name",name);
                output.write((event.toString()+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));output.flush();
                if(destination==53) replyDns(packet,header,length,uid,replies);
            }
        }catch(Exception error){android.util.Log.e("UidProbe","capture failed",error);}
    }
    private void replyDns(byte[] request,int header,int length,int uid,FileOutputStream output)throws Exception {
        int dns=header+8,pos=dns+12;
        while(pos<length && request[pos]!=0){int count=request[pos]&255;if(count>63)return;pos+=count+1;}
        if(pos+5>length)return;
        int questionEnd=pos+5,type=u16(request,pos+1);
        boolean address=type==1;
        byte[] response=new byte[20+8+questionEnd-dns+(address?16:0)];
        response[0]=0x45;put16(response,2,response.length);response[8]=64;response[9]=17;
        System.arraycopy(request,16,response,12,4);System.arraycopy(request,12,response,16,4);
        put16(response,20,53);put16(response,22,u16(request,header));put16(response,24,response.length-20);
        System.arraycopy(request,dns,response,28,questionEnd-dns);
        put16(response,30,0x8180);put16(response,32,1);put16(response,34,address?1:0);put16(response,36,0);put16(response,38,0);
        if(address){
            int start=28+questionEnd-dns;put16(response,start,0xc00c);put16(response,start+2,1);put16(response,start+4,1);
            put16(response,start+8,60);put16(response,start+10,4);
            response[start+12]=(byte)198;response[start+13]=18;
            int appA=getPackageManager().getApplicationInfo("org.amnezia.uidprobe.a",0).uid;
            response[start+15]=(byte)(uid==appA?10:11);
        }
        int checksum=0;for(int n=0;n<20;n+=2)checksum+=u16(response,n);
        while((checksum>>16)!=0)checksum=(checksum&65535)+(checksum>>16);
        put16(response,10,(~checksum)&65535);output.write(response);output.flush();
    }
    private static void put16(byte[] packet,int offset,int value){packet[offset]=(byte)(value>>8);packet[offset+1]=(byte)value;}
    @Override public void onDestroy(){try{if(tunnel!=null)tunnel.close();}catch(Exception ignored){}super.onDestroy();}
}
