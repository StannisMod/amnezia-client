package org.amnezia.uidprobe;
import android.app.Instrumentation;
import android.os.Bundle;
import android.content.Intent;
public class Starter extends Instrumentation {
    private int durationMs;
    @Override public void onCreate(Bundle args){super.onCreate(args);durationMs=Integer.parseInt(args.getString("duration_ms","20000"));start();}
    @Override public void onStart(){
        if(android.net.VpnService.prepare(getTargetContext())!=null) {
            Bundle error=new Bundle();error.putString("failure","VPN consent unavailable");finish(-1,error);return;
        }
        getTargetContext().startForegroundService(new Intent(getTargetContext(),OwnerService.class));
        try{Thread.sleep(durationMs);}catch(InterruptedException ignored){}
        getTargetContext().stopService(new Intent(getTargetContext(),OwnerService.class));
        finish(0,new Bundle());
    }
}
