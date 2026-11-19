#!/usr/bin/env python3
"""Run both local OpenVPN server modes through the existing APK service suite.

Only an owned Docker emulator namespace or a disposable GitHub-hosted runner
is supported. Requires root, Android SDK/JDK17 and a local OpenVPN executable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('apk','work'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--policies',type=Path,default=Path(__file__).resolve().parents[2]/'client/tests/data/openvpn-tun-builder-policies.json')
    parser.add_argument('--source-sha')
    parser.add_argument('--scope-cycles', type=int, default=1,
                        help='repeat the complete scope transition sequence in one live fixture (1..8)')
    parser.add_argument('--tcp-probes', type=int, default=1,
                        help='assert each independent IPv6 TCP connection, failing on the first mismatch (1..16)')
    parser.add_argument('--case',choices=('full','include','exclude'),help='focused local diagnosis; default includes every case')
    parser.add_argument('--apk-source-sha',help='known packaged source commit; omit only when unknown')
    args=parser.parse_args()
    assert 1 <= args.scope_cycles <= 8, 'scope cycles must be between 1 and 8'
    assert 1 <= args.tcp_probes <= 16, 'TCP probes must be between 1 and 16'
    assert os.geteuid()==0, 'run only inside the root-owned isolated test environment'
    container=Path('/.dockerenv').exists()
    assert container or (os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted')
    env=dict(os.environ,AMNEZIA_ANDROID_OPENVPN_FIXTURE='owned-container' if container else 'github-hosted')
    repo=Path(__file__).resolve().parents[2]
    work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    report={'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),
            'policies_sha256':hashlib.sha256(args.policies.read_bytes()).hexdigest(),
             'apk_source_sha':args.apk_source_sha,'focused_case':args.case,'scope_cycles':args.scope_cycles,'tcp_probes':args.tcp_probes,'cases':{},'status':'FAIL',
            'harness_files_sha256':{name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in
                ('scripts/routing/run_android_openvpn_acceptance.py','scripts/routing/run_android_acceptance.py',
                 'scripts/routing/android/RoutingInstrumentation.java','scripts/routing/android-openvpn/local_server.py')},
            'not_proven':['physical device','DNS routing','MTU recovery','other VPN protocols']}
    try:
        for mode in ('ipv4-only','dual-stack'):
            fixture=work/('private-'+mode+'.json')
            assert not fixture.exists(), 'stale private fixture must not be reused'
            log=(work/(mode+'-server.log')).open('w')
            server=subprocess.Popen([sys.executable,'-u',str(repo/'scripts/routing/android-openvpn/local_server.py'),
                '--policies',str(args.policies.resolve()),'--output',str(fixture),'--scope-cycles',str(args.scope_cycles),'--tcp-probes',str(args.tcp_probes),*(['--ipv6'] if mode=='dual-stack' else []),
                *(['--case',args.case] if args.case else [])],
                stdout=log,stderr=subprocess.STDOUT,env=env)
            try:
                until=time.monotonic()+30
                while not fixture.exists():
                    assert server.poll() is None and time.monotonic()<until, 'fixture startup failed; see '+log.name
                    time.sleep(.05)
                command=[sys.executable,str(repo/'scripts/routing/run_android_acceptance.py'),'--openvpn-ipv6-only',
                    '--apk',str(args.apk.resolve()),'--fixture',str(fixture),'--work',str(work/mode)]
                if args.apk_source_sha: command+=['--apk-source-sha',args.apk_source_sha]
                if args.source_sha: command+=['--source-sha',args.source_sha]
                subprocess.run(command,check=True,timeout=300*args.scope_cycles)
                observed=json.loads((work/mode/'android-acceptance.json').read_text())['openvpn_ipv6']
                expected_names=[args.case] if args.case else ['full','include','exclude']+(['stale-full'] if mode=='ipv4-only' else [])
                expected_names *= args.scope_cycles
                assert [row['name'] for row in observed['cases']]==expected_names
                assert observed['server_ipv6']==(mode=='dual-stack')
                report['cases'][mode]=observed
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    server.kill();server.wait()
                    raise RuntimeError('fixture did not stop cleanly; inspect its namespace before reuse')
                finally: log.close();fixture.unlink(missing_ok=True)
                assert server.returncode==0, 'fixture cleanup failed; see '+log.name
        assert hashlib.sha256(args.apk.read_bytes()).hexdigest()==report['apk_sha256'], 'input APK modified'
        report['status']='PASS_FOCUSED' if args.case else 'PASS'
        print(report['status']+': real Android OpenVPN '+(args.case+' ' if args.case else '')+
              'IPv6 scope, GUA/ULA/NAT64 TCP/UDP and original IPv4 TCP',flush=True)
    finally:
        (work/'openvpn-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
