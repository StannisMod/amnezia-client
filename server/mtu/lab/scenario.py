"""Called only after the isolated engine fixture establishes two original flows."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

out=Path(os.environ['AMNEZIA_STABILITY_TRACE'])
assert Path('/.dockerenv').exists()
assert Path('/run/netns/stability-peer').exists()
assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net')


def peer(*args):
    return subprocess.check_output(['ip','netns','exec','stability-peer',*args],text=True,timeout=5)


def flows():
    return json.loads((out/'flows.json').read_text())


def routes():
    return peer('ip','-o','-4','route','show')


def wait_for(test, timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if test(): return
        time.sleep(.2)
    raise AssertionError('condition timed out')


command=['ip','netns','exec','stability-peer','python3','/controller/supervisor.py',
         '--interface','stb-peer','--command','/lab/status','--interval','1']
process=None
try:
    upload=os.environ.get('AMNEZIA_STABILITY_UPLOAD')=='1'
    chain='output' if upload else 'input'
    match='daddr' if upload else 'saddr'
    rules=f'add table inet mtu_lab\nadd chain inet mtu_lab {chain} {{ type filter hook {chain} priority -10; }}\nadd rule inet mtu_lab {chain} ip {match} 203.0.113.2 meta l4proto udp ip length > 1200 counter drop\n'
    subprocess.run(['nft','-f','-'],input=rules,text=True,check=True)
    time.sleep(2)
    frozen=flows()
    time.sleep(2)
    assert flows()['chunks']==frozen['chunks'], 'download did not stall'
    assert flows()['messages']>frozen['messages'], 'short messages did not pass'
    initial=routes()
    healthy=int((out/'healthy-records').read_text())
    with (out/'supervisor.jsonl').open('w') as log:
        process=subprocess.Popen(command,stdout=log,stderr=log)
        wait_for(lambda:'mtu 1104' in routes())
        if upload:
            time.sleep(3)
            upload_recovered=flows()['chunks']>frozen['chunks']
            subprocess.run(['nft','delete','table','inet','mtu_lab'],check=True)
            process.terminate();process.wait(timeout=12);process=None
            (out/'mtu-result.json').write_text(json.dumps({'upload_server_only_recovery':upload_recovered,'old_tcp':'checked by engine after path restore'}))
            raise SystemExit(0)
        wait_for(lambda:flows()['chunks']>frozen['chunks']+3)
        reduced=routes()
        assert '10.77.0.3 dev stb-peer scope link mtu' not in reduced
        assert int((out/'healthy-records').read_text())>healthy+10
        process.kill();process.wait();process=None
        wait_for(lambda:routes()==initial)
        process=subprocess.Popen(command,stdout=log,stderr=log)
        wait_for(lambda:'mtu 1104' in routes())
        (out/'remove-peer1').touch()
        wait_for(lambda:routes()==initial)
        (out/'remove-peer1').unlink()
        wait_for(lambda:'mtu 1104' in routes())
        subprocess.run(['nft','delete','table','inet','mtu_lab'],check=True)
        wait_for(lambda:routes()==initial)
        process.terminate();process.wait(timeout=12);process=None
        assert routes()==initial
    (out/'mtu-result.json').write_text(json.dumps({'old_tcp':'retained','healthy_peer':'progressing','reduction':1104,'parent_kill':'restored','restart':'PASS','peer_removal':'PASS','raise':'PASS'}))
finally:
    if process is not None:
        process.terminate();process.wait(timeout=12)
    subprocess.run(['nft','delete','table','inet','mtu_lab'],stderr=subprocess.DEVNULL)
