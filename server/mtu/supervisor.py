"""Discover recently active AWG IPv4 host peers and supervise MTU workers."""
import ctypes
import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, text=True, timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', default='awg0')
    parser.add_argument('--command', default='awg')
    parser.add_argument('--interval',type=float,default=30)
    args = parser.parse_args()
    if args.interval<1: parser.error('interval must be >= 1')
    if not args.interface or '/' in args.interface:
        parser.error('invalid interface')
    import fcntl
    lock=open('/run/awg-mtu-supervisor-'+args.interface+'.lock','w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if not args.interface or "/" in args.interface:
        parser.error("invalid interface")
    workers = {}
    parent_pid=os.getpid()
    def child_lifetime():
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(1,signal.SIGTERM,0,0,0)!=0:
            os._exit(127)
        if os.getppid()!=parent_pid:
            os._exit(127)
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    def retire(peer):
        process, owned, original = workers.pop(peer)
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        # Delete only the route created by this supervisor.
        current=run('ip','-o','-4','route','show','exact',peer+'/32').strip()
        if owned and current==original:
            subprocess.run(['ip', '-4', 'route', 'del', peer+'/32', 'dev', args.interface, 'proto', '186'], check=False)
    try:
        while not stopped:
            try:
                addresses=json.loads(run('ip','-j','-4','addr','show','dev',args.interface))[0]['addr_info']
                source=next(a['local'] for a in addresses if a['family']=='inet')
                handshakes={key:int(value) for key,value in (line.split() for line in run(args.command,'show',args.interface,'latest-handshakes').splitlines())}
                peers=set()
                for line in run(args.command,'show',args.interface,'allowed-ips').splitlines():
                    key,raw=line.split(None,1)
                    if time.time()-handshakes.get(key,0)>180: continue
                    for prefix in raw.replace(',',' ').split():
                        net=ipaddress.ip_network(prefix,strict=False)
                        if net.version==4 and net.prefixlen==32: peers.add(str(net.network_address))
                for peer in list(workers):
                    if peer not in peers or workers[peer][0].poll() is not None: retire(peer)
                for peer in sorted(peers-set(workers)):
                    existing=run('ip','-o','-4','route','show','exact',peer+'/32').strip()
                    owned=False
                    recovery=Path('/run/awg-mtu')/(args.interface+'-'+peer+'.json')
                    saved_original=None
                    if 'proto 186' in existing and recovery.exists():
                        saved_original=json.loads(recovery.read_text())['original']
                        owned=True
                    if not existing:
                        subprocess.run(['ip','-4','route','add',peer+'/32','dev',args.interface,'proto','186'],check=True)
                        owned=True
                    original=saved_original or run('ip','-o','-4','route','show','exact',peer+'/32').strip()
                    process=subprocess.Popen([sys.executable,str(Path(__file__).resolve().with_name('controller.py')),'--interface',args.interface,'--source',source,'--peer',peer,'--interval',str(args.interval)],preexec_fn=child_lifetime)
                    workers[peer]=(process,owned,original)
            except (subprocess.SubprocessError,ValueError,IndexError,StopIteration,OSError) as error:
                print(json.dumps({'event':'mtu-supervisor-error','error':str(error)}),flush=True)
            until=time.monotonic()+min(10,args.interval)
            while not stopped and time.monotonic()<until: time.sleep(.2)
    finally:
        for peer in list(workers): retire(peer)

if __name__=='__main__': main()
