"""IPv4 echo sizing prototype. Run inside the isolated AWG server namespace."""
import json
import os
import secrets
import socket
import struct
import subprocess
import time

def discover(peer, source, maximum=1280):
    history = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, 10, 3)  # Linux IP_MTU_DISCOVER / IP_PMTUDISC_DO
    sock.bind((source, 0))
    ident = secrets.randbelow(65536)
    def echo(size):
        seq = len(history) + 1
        payload = secrets.token_bytes(size - 28)
        dat = struct.pack('!BBHHH', 8, 0, 0, ident, seq) + payload
        padded = dat + bytes(len(dat) % 2)
        c = sum(x[0] for x in struct.iter_unpack('!H', padded))
        while c >> 16:
            c = (c & 65535) + (c >> 16)
        try:
            sock.sendto(dat[:2] + struct.pack('!H', ~c & 65535) + dat[4:], (peer, 0))
        except OSError:
            history.append((size, False))
            return False
        end = time.monotonic() + .25
        while time.monotonic() < end:
            sock.settimeout(max(.001, end - time.monotonic()))
            try: data, addr = sock.recvfrom(65535)
            except socket.timeout: break
            off = 4*(data[0]&15)
            if len(data)>=off+8 and addr[0]==peer and data[off]==0 and data[off+4:off+8]==dat[4:8] and data[off+8:]==payload:
                history.append((size, True))
                return True
        history.append((size, False))
        return False
    def passes(size):
        return sum(echo(size) for _ in range(3)) >= 2
    try:
        if not passes(128):
            return {'state':'inconclusive','history':history}
        if passes(maximum):
            return {'state':'unchanged','mtu':maximum,'history':history}
        low, high = 36, (maximum+15)//16  # steps of 16 bytes, lower bound 576
        if not passes(576):
            return {'state':'inconclusive','history':history}
        while high-low > 1:
            mid=(high+low)//2
            if passes(mid*16): low=mid
            elif passes(128): high=mid
            else: return {'state':'inconclusive','history':history}
        mtu=max(576,low*16-16)
        if not passes(mtu) or passes(high*16) or not passes(128):
            return {'state':'inconclusive','history':history}
        return {'state':'reduced','mtu':mtu,'history':history}
    finally: sock.close()


from pathlib import Path
import argparse
import fcntl
import signal
import shlex

def route(peer):
    return subprocess.check_output(['ip','-o','-4','route','show','exact',peer+'/32'],text=True).strip()

def interface_mtu(name):
    return json.loads(subprocess.check_output(["ip","-j","link","show","dev",name],text=True))[0]["mtu"]

def main():
    parser=argparse.ArgumentParser(description="IPv4 AWG per-peer MTU prototype")
    parser.add_argument('--interface',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--peer',action='append',required=True)
    parser.add_argument('--maximum',type=int,default=0)
    parser.add_argument('--interval',type=float,default=30)
    parser.add_argument('--state-dir',type=Path,default=Path('/run/awg-mtu'))
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    import ipaddress
    args.peer=list(dict.fromkeys(str(ipaddress.IPv4Address(p)) for p in args.peer))
    ipaddress.IPv4Address(args.source)
    if (args.maximum and not 576 <= args.maximum <= 65535) or args.interval<1:
        parser.error('maximum must be 0 (interface MTU) or 576..65535; interval >= 1')
    if '/' in args.interface or not args.interface:
        parser.error('invalid interface name')
    socket.if_nametoindex(args.interface)
    native_mtu=interface_mtu(args.interface)
    args.maximum=min(args.maximum or native_mtu,native_mtu)
    lock=open('/run/awg-mtu-'+args.interface+'-'+ '-'.join(args.peer)+'.lock','w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    args.state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    journals={peer:args.state_dir/(args.interface+'-'+peer+'.json') for peer in args.peer}
    def without_mtu(text):
        tokens=shlex.split(text)
        if 'mtu' in tokens:
            idx=tokens.index('mtu')
            del tokens[idx:idx+2]
        return tokens
    def record(peer, original, mtu):
        path=journals[peer]
        temporary=path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'original':original,'mtu':mtu}))
        os.replace(temporary,path)
    for peer,path in journals.items():
        if path.exists():
            saved=json.loads(path.read_text())
            current=route(peer)
            tokens=shlex.split(current)
            mtu=int(tokens[tokens.index('mtu')+1]) if 'mtu' in tokens else args.maximum
            if current==saved['original']:
                path.unlink()
            elif without_mtu(current)==without_mtu(saved['original']) and mtu==saved['mtu']:
                subprocess.run(['ip','-4','route','replace',*shlex.split(saved['original'])],check=True)
                path.unlink()
            else:
                raise RuntimeError('unreconciled external route change: '+peer)
    baseline={}
    expected={}
    candidates={}
    for peer in args.peer:
        text=route(peer)
        tokens=shlex.split(text)
        if len(text.splitlines())!=1 or tokens[:1]!=[peer] or 'dev' not in tokens or tokens[tokens.index('dev')+1]!=args.interface:
            parser.error('requires an existing direct /32 route on selected interface for '+peer)
        if 'mtu' in tokens:
            parser.error('prototype requires a /32 route without an explicit MTU metric: '+peer)
        baseline[peer]=text
        expected[peer]=text
    stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    try:
        while not stopping:
            for peer in args.peer:
                if stopping: break
                if route(peer)!=expected[peer]:
                    raise RuntimeError('route changed by another owner: '+peer)
                result=discover(peer,args.source,args.maximum)
                if route(peer)!=expected[peer]:
                    raise RuntimeError('route changed during probing: '+peer)
                current_tokens=shlex.split(expected[peer])
                current=int(current_tokens[current_tokens.index('mtu')+1]) if 'mtu' in current_tokens else native_mtu
                target=result.get('mtu',current)
                if target>current:
                    previous,count=candidates.get(peer,(None,0))
                    count=count+1 if previous==target else 1
                    candidates[peer]=(target,count)
                    if count<3: target=current
                else: candidates.pop(peer,None)
                if result['state']!='inconclusive' and target!=current:
                    tokens=shlex.split(baseline[peer])
                    if 'mtu' in tokens:
                        idx=tokens.index('mtu')
                        del tokens[idx:idx+2]
                    if target!=native_mtu: tokens+=['mtu',str(target)]
                    record(peer,baseline[peer],target)
                    subprocess.run(['ip','-4','route','replace',*tokens],check=True)
                    expected[peer]=route(peer)
                print(json.dumps(dict(at=time.time(),peer=peer,applied_mtu=target,**result)),flush=True)
            if args.once: break
            end=time.monotonic()+args.interval
            while not stopping and time.monotonic()<end: time.sleep(.1)
    finally:
        for peer,original in baseline.items():
            if route(peer)==expected[peer] and route(peer)!=original:
                subprocess.run(['ip','-4','route','replace',*shlex.split(original)],check=True)
            if route(peer)==original and journals[peer].exists():
                journals[peer].unlink()

if __name__=='__main__': main()
