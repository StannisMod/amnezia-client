#!/usr/bin/env python3
"""Only invoked by an engine test in a fresh mount+network namespace."""
import json,os,pathlib,subprocess,sys,time

def run(*args, peer=False, check=True):
    prefix=['ip','netns','exec','stability-peer'] if peer else []
    r=subprocess.run(prefix+list(args),check=check,text=True,capture_output=True,timeout=10)
    if r.returncode and check: raise RuntimeError(r.stderr)
    return r.stdout

def nft(text):
    subprocess.run(['nft','-f','-'],input=text,text=True,check=True,capture_output=True,timeout=10)

NETEM={
 'delay':['delay','200ms','100ms','25%'],
 'loss':['loss','10%'],
 'burst-loss':['loss','10%','75%'],
 'duplicate':['duplicate','10%'],
 'reorder':['delay','60ms','20ms','reorder','25%','50%'],
 'corrupt':['corrupt','2%'],
 'rate':['delay','50ms','rate','512kbit'],
 'queue-overflow':['limit','8','delay','100ms','rate','256kbit'],
 'mixed':['limit','128','delay','80ms','40ms','loss','5%','duplicate','2%','reorder','10%','25%'],
 'uplink-loss':['loss','15%'], 'downlink-loss':['loss','15%'],
}
PROFILES=set(NETEM)|{'blackhole','uplink-blackhole','downlink-blackhole','link-down','flap','address-gap','route-blackhole','mtu','mtu-blackhole','nat-rebind'}

def main():
    action,profile=sys.argv[1:]
    assert action in ('apply','witness','clear') and profile in PROFILES
    assert os.environ.get('AMNEZIA_STABILITY_LAB')=='isolated-namespace'
    assert pathlib.Path('/.dockerenv').exists(), 'Docker wrapper required'
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'fresh child network namespace required'
    assert pathlib.Path('/run/netns/stability-peer').exists()
    run('ip','link','show','dev','stb-underlay')
    state=pathlib.Path('/tmp/chaos-fault-state.json')
    def snapshot():
        return {'ip':run('ip','-j','addr'),'routes':run('ip','-j','route'),'tc':run('tc','-s','-j','qdisc','show','dev','stb-underlay'),'peer_tc':run('tc','-s','-j','qdisc','show','dev','eth0',peer=True),'conntrack':run('conntrack','-L','-p','udp',check=False),'nft':run('nft','-j','list','table','inet','chaos',check=False)}
    if action=='clear':
        run('nft','delete','table','inet','chaos',check=False)
        for peer,dev in ((False,'stb-underlay'),(True,'eth0')):
            run('tc','qdisc','del','dev',dev,'root',peer=peer,check=False)
        run('ip','link','set','stb-underlay','up')
        if profile in ('mtu','mtu-blackhole'): run('ip','link','set','dev','stb-underlay','mtu','1500')
        if profile=='address-gap':
            run('ip','addr','replace','203.0.113.1/24','dev','stb-underlay')
            run('ip','route','replace','default','via','203.0.113.2','dev','stb-underlay')
        if profile=='route-blackhole': run('ip','route','del','blackhole','203.0.113.2/32',check=False)
        if profile=='nat-rebind':
            run('conntrack','-D','-p','udp','--dst','203.0.113.2',check=False)
            run('ip','addr','del','203.0.113.3/24','dev','stb-underlay',check=False)
        return
    if action=='witness':
        before=json.loads(state.read_text());after=snapshot()
        evidence={'before':before,'during':after,'profile':profile}
        out=pathlib.Path(os.environ['AMNEZIA_STABILITY_TRACE'])/'fault-evidence.json'
        out.write_text(json.dumps(evidence,indent=2)+'\n')
        if 'blackhole' in profile and profile != 'route-blackhole':
            rules=json.loads(after['nft'])['nftables']
            counters=[expr['counter']['packets'] for row in rules if 'rule' in row for expr in row['rule']['expr'] if 'counter' in expr]
            assert sum(counters)>0, 'blackhole affected no encrypted packets'
            evidence['dropped_outer_packets']=sum(counters)
        if profile=='nat-rebind':
            rules=json.loads(after['nft'])['nftables']
            packets=sum(expr['counter']['packets'] for row in rules if 'rule' in row for expr in row['rule']['expr'] if 'counter' in expr)
            assert packets>0, 'NAT rule translated no new UDP flow'
            evidence['translated_outer_flows']=packets
        if profile in NETEM:
            active=json.loads(after['tc'])+json.loads(after['peer_tc'])
            assert any(q['kind']=='netem' and q.get('packets',0)>0 for q in active), 'netem affected no packets'
        out=pathlib.Path(os.environ['AMNEZIA_STABILITY_TRACE'])/'fault-evidence.json'
        out.write_text(json.dumps(evidence,indent=2)+'\n')
        return
    state.write_text(json.dumps(snapshot()))
    if profile in NETEM:
        for peer,dev in ((False,'stb-underlay'),(True,'eth0')):
            if profile=='uplink-loss' and peer or profile=='downlink-loss' and not peer: continue
            options=NETEM[profile]
            if 'limit' not in options: options=['limit','256']+options
            run('tc','qdisc','replace','dev',dev,'root','netem',*options,peer=peer)
    elif profile in ('blackhole','uplink-blackhole','downlink-blackhole'):
        text='add table inet chaos\n'
        for chain,match in [('output','ip daddr 203.0.113.2'),('input','ip saddr 203.0.113.2')]:
            if profile=='uplink-blackhole' and chain=='input' or profile=='downlink-blackhole' and chain=='output': continue
            text+=f'add chain inet chaos {chain} {{ type filter hook {chain} priority -10; policy accept; }}\nadd rule inet chaos {chain} {match} meta l4proto udp counter drop\n'
        nft(text)
    elif profile=='link-down': run('ip','link','set','stb-underlay','down')
    elif profile=='flap':
        for _ in range(4):
            run('ip','link','set','stb-underlay','down');time.sleep(.25)
            run('ip','link','set','stb-underlay','up');time.sleep(.25)
    elif profile=='address-gap': run('ip','addr','del','203.0.113.1/24','dev','stb-underlay')
    elif profile=='route-blackhole': run('ip','route','add','blackhole','203.0.113.2/32')
    elif profile=='mtu':
        run('ip','link','set','dev','stb-underlay','mtu','576')
    elif profile=='mtu-blackhole':
        # An invisible reduced path MTU: keep the local link unchanged and
        # silently drop large encrypted datagrams, allowing small handshakes.
        nft('add table inet chaos\n'
            'add chain inet chaos input { type filter hook input priority -10; policy accept; }\n'
            'add chain inet chaos output { type filter hook output priority -10; policy accept; }\n'
            'add rule inet chaos input ip saddr 203.0.113.2 meta l4proto udp ip length > 900 counter drop\n'
            'add rule inet chaos output ip daddr 203.0.113.2 meta l4proto udp ip length > 900 counter drop\n')
    elif profile=='nat-rebind':
        run('ip','addr','add','203.0.113.3/24','dev','stb-underlay')
        nft('add table inet chaos\n'
            'add chain inet chaos hold_in { type filter hook prerouting priority -301; policy accept; }\n'
            'add chain inet chaos hold_out { type filter hook output priority -301; policy accept; }\n'
            'add rule inet chaos hold_in ip saddr 203.0.113.2 meta l4proto udp drop\n'
            'add rule inet chaos hold_out ip daddr 203.0.113.2 meta l4proto udp drop\n'
            'add chain inet chaos postrouting { type nat hook postrouting priority srcnat; policy accept; }\n'
            'add rule inet chaos postrouting ip daddr 203.0.113.2 meta l4proto udp counter snat ip to 203.0.113.3:45000\n')
        # With a busy download an incoming UDP packet can otherwise create a
        # reverse conntrack entry before the first outbound packet, bypassing
        # SNAT. Hold ingress until the client establishes the new mapping.
        run('conntrack','-F')  # Only this fresh test network namespace.
        nft('flush chain inet chaos hold_out\ndelete chain inet chaos hold_out\n')
        time.sleep(.5)
        nft('flush chain inet chaos hold_in\ndelete chain inet chaos hold_in\n')

if __name__=='__main__':main()
