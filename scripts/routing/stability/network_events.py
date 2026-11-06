#!/usr/bin/env python3
"""Private NetworkManager + exact production watcher, disposable container only."""
import json, os, pathlib, subprocess, sys, threading, time
from datetime import datetime, timezone

if os.environ.get('AMNEZIA_STABILITY_LAB') != 'isolated-container':
    raise SystemExit('Use the isolated lab container; never run this on the desktop')
output = pathlib.Path(sys.argv[1]); output.mkdir(parents=True,exist_ok=True)
def run(*args):
    result = subprocess.run(args,capture_output=True,text=True,timeout=20)
    if result.returncode: raise RuntimeError(f'{args}: {result.stdout} {result.stderr}')
    return result.stdout
phases = (output/'phases.jsonl').open('w')
def phase(name):
    row={'at':datetime.now(timezone.utc).isoformat(),'phase':name}
    phases.write(json.dumps(row)+'\n');phases.flush();print(row,flush=True)
pathlib.Path('/run/dbus').mkdir(parents=True,exist_ok=True)
run('dbus-daemon','--system','--fork','--nopidfile')
config=output/'NetworkManager.conf'
config.write_text('[main]\nplugins=keyfile\nno-auto-default=*\n[keyfile]\nunmanaged-devices=\n[connectivity]\nenabled=false\n[device-stability]\nmatch-device=interface-name:stb-*\nmanaged=1\n')
nm_log=(output/'NetworkManager.log').open('w')
# Private /run and a private netns: initialize only the synthetic network
# device, without triggering any unrelated device or mounting the host bus.
udev_log=(output/'udev.log').open('w')
udev=subprocess.Popen(['/usr/lib/systemd/systemd-udevd','--resolve-names=never','--children-max=1'],stdout=udev_log,stderr=subprocess.STDOUT)
time.sleep(.3)
run('ip','link','add','stb-net','type','dummy')
run('udevadm','trigger','--action=add','--subsystem-match=net','--sysname-match=stb-net')
run('udevadm','settle','--timeout=5')
empty=output/'empty-config';empty.mkdir(exist_ok=True)
nm=subprocess.Popen(['NetworkManager','--no-daemon','--debug','--log-level=TRACE','--log-domains=ALL','--config',str(config),'--config-dir',str(empty),'--system-config-dir',str(empty),'--pid-file','/tmp/stability-nm.pid'],stdout=nm_log,stderr=subprocess.STDOUT)
watcher=None
try:
    for _ in range(80):
        check=subprocess.run(['nmcli','general','status'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode==0:break
        time.sleep(.1)
    else:raise RuntimeError('private NetworkManager not ready')
    run('nmcli','device','set','stb-net','managed','yes')
    run('nmcli','connection','add','type','dummy','ifname','stb-net','con-name','stability-net','ipv4.method','manual','ipv4.addresses','192.0.2.1/24','ipv4.gateway','192.0.2.2','ipv6.method','disabled')
    (output/'device-before.txt').write_text(run('nmcli','-f','GENERAL','device','show','stb-net'))
    run('nmcli','connection','up','stability-net')
    watcher_log=(output/'watcher.jsonl').open('w'); watcher_err=(output/'watcher.stderr').open('w')
    watcher=subprocess.Popen(['/output/network-events'],stdin=subprocess.PIPE,stdout=watcher_log,stderr=watcher_err,text=True)
    time.sleep(1)
    phase('baseline-connected');time.sleep(1)
    phase('blackhole-start');run('tc','qdisc','add','dev','stb-net','root','netem','loss','100%');time.sleep(3)
    run('tc','qdisc','del','dev','stb-net','root');phase('blackhole-end');time.sleep(1)
    phase('create-tun-and-policy-route')
    run('ip','tuntap','add','dev','amnrouting0','mode','tun');run('ip','addr','add','172.19.0.1/30','dev','amnrouting0');run('ip','link','set','amnrouting0','up')
    run('ip','route','add','blackhole','default','table','20313');run('ip','rule','add','pref','1','fwmark','0x20000000/0x20000000','lookup','20313');time.sleep(2)
    run('ip','rule','del','pref','1');run('ip','route','flush','table','20313');run('ip','link','del','amnrouting0');phase('tun-removed');time.sleep(2)
    phase('gateway-change-same-interface');run('ip','route','replace','default','via','192.0.2.3','dev','stb-net');time.sleep(2)
    phase('duplicate-identical-callback');watcher.stdin.write('duplicate\n');watcher.stdin.flush();time.sleep(1)
    phase('connection-down');run('nmcli','connection','down','stability-net');time.sleep(2)
    phase('connection-up');run('nmcli','connection','up','stability-net');time.sleep(2)
    phase('networking-off');run('nmcli','networking','off');time.sleep(2)
    phase('networking-on');run('nmcli','networking','on');time.sleep(1);run('nmcli','connection','up','stability-net');time.sleep(2)
    phase('complete')
finally:
    if watcher:
        watcher.stdin.close()
        try:watcher.wait(timeout=5)
        except subprocess.TimeoutExpired:watcher.kill();watcher.wait()
    nm.terminate()
    try:nm.wait(timeout=5)
    except subprocess.TimeoutExpired:nm.kill();nm.wait()
    udev.terminate()
    try:udev.wait(timeout=5)
    except subprocess.TimeoutExpired:udev.kill();udev.wait()
    udev_log.close();nm_log.close();phases.close()

# Compare the exact production worker with the raw private D-Bus events.
rows=[json.loads(line) for line in (output/'watcher.jsonl').read_text().splitlines()]
raw70=sum(r.get('state')==70 for r in rows if r['event']=='dbus-StateChanged')
raw10=sum(r.get('state')==10 for r in rows if r['event']=='dbus-StateChanged')
changed=sum(r['event']=='production-networkChanged' for r in rows)
wakeup=sum(r['event']=='production-wakeup' for r in rows)
ph=[json.loads(line) for line in (output/'phases.jsonl').read_text().splitlines()]
start=next(datetime.fromisoformat(r['at']) for r in ph if r['phase']=='blackhole-start')
end=next(datetime.fromisoformat(r['at']) for r in ph if r['phase']=='duplicate-identical-callback')
quiet=[r for r in rows if r['event'].startswith('production-') and start<=datetime.fromisoformat(r['at'].replace('Z','+00:00'))<end]
report={'raw_global_connected_events':raw70,'raw_asleep_events':raw10,'production_network_changed':changed,'production_wakeup':wakeup,'injected_identical_callbacks':2,'callbacks_during_blackhole_tun_gateway_phases':quiet}
assert raw70>=1 and raw10>=1
assert changed==raw70+2 and wakeup==raw10
assert not quiet
(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
