#!/usr/bin/env python3
"""One isolated namespace/process per case; no app reconnect loop."""
import argparse,itertools,json,os,pathlib,re,signal,subprocess,sys,time,xml.etree.ElementTree as ET
from fault import PROFILES

def main():
 p=argparse.ArgumentParser()
 p.add_argument('--suite',choices=('smoke','full','soak'),default='smoke')
 p.add_argument('--profiles',help='Comma-separated fault names; see --list')
 p.add_argument('--protocols',default='awg,wireguard')
 p.add_argument('--families',help='IPv4,IPv6; full defaults to both (inner TCP; outer UDP is IPv4)')
 p.add_argument('--directions',help='download,upload; full defaults to both')
 p.add_argument('--repeat',type=int,default=1)
 p.add_argument('--seconds',type=int)
 p.add_argument('--recovery-seconds',type=int)
 p.add_argument('--output',default='/results')
 p.add_argument('--binaries',default='/opt/lab/bin')
 p.add_argument('--list',action='store_true')
 a=p.parse_args()
 names=PROFILES|{'handover','domain-move','address-move','default-removal','idle-blackhole','blackhole-1s','blackhole-10s','blackhole-30s'}
 if a.list: print('\n'.join(sorted(names)));return
 if not pathlib.Path('/.dockerenv').exists():p.error('run through the isolated Docker wrapper')
 links=json.loads(subprocess.check_output(['ip','-j','link','show'],text=True))
 if {link['ifname'] for link in links}!={'lo'}:p.error('outer container must use --network none; refusing host/shared networking')
 if a.profiles: profiles=a.profiles.split(',')
 elif a.suite=='smoke': profiles=['blackhole','uplink-blackhole','downlink-blackhole','loss','link-down','address-gap','nat-rebind','mtu-blackhole','handover','domain-move']
 elif a.suite=='soak': profiles=['blackhole','link-down','address-gap']
 else: profiles=sorted(names)
 if not set(profiles)<=names:p.error('unknown fault profile')
 protocols=a.protocols.split(',');families=(a.families or ('IPv4' if a.suite=='smoke' else 'IPv4,IPv6')).split(',')
 directions=(a.directions or ('download' if a.suite=='smoke' else 'download,upload')).split(',')
 if not set(protocols)<={'awg','wireguard'} or not set(families)<={'IPv4','IPv6'} or not set(directions)<={'download','upload'}:p.error('invalid matrix')
 seconds=a.seconds or {'smoke':3,'full':8,'soak':120}[a.suite]
 recovery=a.recovery_seconds or (150 if a.suite=='soak' else 30)
 if not 1<=a.repeat<=100 or not 1<=seconds<=600 or not 1<=recovery<=600:p.error('duration/repeat out of range')
 out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
 binaries=pathlib.Path(a.binaries).resolve()
 for name in ('engine.test','amnezia-routing'):
  if not (binaries/name).is_file():p.error('missing '+str(binaries/name))
 script=pathlib.Path(__file__).with_name('fault.py').resolve()
 cases=[]
 root=ET.Element('testsuite',name='Linux tunnel TCP chaos')
 report={'suite':a.suite,'outer_family':'IPv4','seconds':seconds,'recovery_budget_seconds':recovery,'cases':cases,'not_covered':['real Wi-Fi radio/driver/firmware','physical suspend/resume','remote peer state loss or server restart','application-specific timeouts shorter than outage','outer IPv6/NAT64','full GUI in this core-only Docker image']}
 (out/'environment.json').write_text(json.dumps({'uname':os.uname()[:],'args':vars(a),'kernel_shared_with_host':True},indent=2)+'\n')
 matrix=list(itertools.product(protocols,families,directions,profiles,range(a.repeat)))
 print(f'{len(matrix)} cases; outage {seconds}s; recovery budget {recovery}s',flush=True)
 for index,(protocol,family,direction,profile,iteration) in enumerate(matrix,1):
  name=f'{index:03d}-{protocol}-{family}-{direction}-{profile}-{iteration+1}'
  directory=out/name;directory.mkdir(exist_ok=True)
  case_seconds={'blackhole-1s':1,'blackhole-10s':10,'blackhole-30s':30}.get(profile,seconds)
  env=dict(os.environ,AMNEZIA_STABILITY_REPRO='1',AMNEZIA_STABILITY_SEQUENCE='1',AMNEZIA_STABILITY_NO_OUTAGES='1',AMNEZIA_STABILITY_KERNEL_PEER='1',AMNEZIA_STABILITY_LAB='isolated-namespace',AMNEZIA_STABILITY_HELPER=str(binaries/'amnezia-routing'),AMNEZIA_STABILITY_TRACE=str(directory),AMNEZIA_STABILITY_UPLOAD=str(int(direction=='upload')),AMNEZIA_CHAOS_SCRIPT=str(script),AMNEZIA_CHAOS_SECONDS=str(case_seconds),AMNEZIA_CHAOS_RECOVERY_SECONDS=str(recovery))
  # Explicitly clear caller-supplied fault knobs: each row describes its own case.
  for key in list(env):
   if key.startswith(('AMNEZIA_STABILITY_','AMNEZIA_CHAOS_')) and key not in {'AMNEZIA_STABILITY_REPRO','AMNEZIA_STABILITY_SEQUENCE','AMNEZIA_STABILITY_NO_OUTAGES','AMNEZIA_STABILITY_KERNEL_PEER','AMNEZIA_STABILITY_LAB','AMNEZIA_STABILITY_HELPER','AMNEZIA_STABILITY_TRACE','AMNEZIA_STABILITY_UPLOAD','AMNEZIA_CHAOS_SCRIPT','AMNEZIA_CHAOS_SECONDS','AMNEZIA_CHAOS_RECOVERY_SECONDS'}:env.pop(key)
  automatic={'handover':'INTERFACE_MOVE','domain-move':'DOMAIN_MOVE','address-move':'ADDRESS_MOVE','default-removal':'REMOVE_DEFAULT'}
  if profile in automatic:
   env['AMNEZIA_STABILITY_AUTOMATIC']='1';env['AMNEZIA_STABILITY_'+automatic[profile]]='1'
  else:
   env['AMNEZIA_CHAOS_PROFILE']='blackhole' if profile in ('idle-blackhole','blackhole-1s','blackhole-10s','blackhole-30s') else profile
   if profile=='idle-blackhole':env['AMNEZIA_CHAOS_IDLE']='1'
   if profile in ('loss','burst-loss','delay','duplicate','reorder','rate','uplink-loss','downlink-loss','nat-rebind','mixed'):
    env['AMNEZIA_CHAOS_PROGRESS_DURING']='1'
  protocol_test='amneziawg' if protocol=='awg' else 'amnezia-wireguard'
  test=f'^TestConnectionStabilityReproduction$/^{protocol_test}$/^{family}$/'
  # No host network calls: every fault runs after unshare and synthetic setup.
  command=['unshare','--mount','--net','--fork','bash','-ec','mount --make-rprivate /; ip link set lo up; mkdir -p /run/netns; mount -t tmpfs tmpfs /run/netns; exec "$@"','chaos',str(binaries/'engine.test'),'-test.run',test,'-test.count','1','-test.v','-test.timeout',f'{case_seconds+2*recovery+180}s']
  started=time.monotonic();text='';failure=None
  process=subprocess.Popen(command,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  try:
   text,_=process.communicate(timeout=case_seconds+2*recovery+200)
   if process.returncode:failure=f'test exit {process.returncode}'
   elif 'availability restored with NEW WS-ID=2' not in text:failure='missing destructive teardown control; test may not have run'
   elif profile not in automatic and 'CHAOS_RESULT ' not in text:failure='fault result missing'
   if not failure and profile in automatic:
    markers={'handover':'same WSS and bulk TCP survived deletion','domain-move':'same WSS and bulk TCP survived domain','address-move':'same WSS and bulk TCP survived removal','default-removal':'same WSS and bulk TCP survive with only'}
    if markers[profile] not in text:failure='automatic migration witness missing'
  except subprocess.TimeoutExpired:
   # Kill the namespace child, helper and tcpdump too, not just unshare.
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   text,_=process.communicate(timeout=10);failure='case timed out'
  elapsed=round(time.monotonic()-started,3)
  (directory/'run.log').write_text(text)
  metrics=[json.loads(x) for x in re.findall(r'CHAOS_RESULT (\{[^\n]*\})',text)]
  row={'name':name,'protocol':protocol,'inner_family':family,'direction':direction,'profile':profile,'status':'FAIL' if failure else 'PASS','duration_seconds':elapsed,'metrics':metrics,'error':failure}
  cases.append(row)
  case=ET.SubElement(root,'testcase',name=name,classname='linux.tunnel.preservation',time=str(elapsed))
  if failure:ET.SubElement(case,'failure',message=failure).text=text[-16000:]
  ET.SubElement(case,'system-out').text=str(directory/'run.log')
  root.set('tests',str(len(cases)));root.set('failures',str(sum(c['status']=='FAIL' for c in cases)))
  ET.ElementTree(root).write(out/'junit.xml',encoding='unicode',xml_declaration=True)
  report['expected_cases']=len(matrix)
  report['completed']=len(cases)==len(matrix)
  report['status']='FAIL' if any(c['status']=='FAIL' for c in cases) else ('PASS' if report['completed'] else 'RUNNING')
  (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
  print(f'[{index}/{len(matrix)}] {row["status"]} {name} {elapsed}s'+(' '+failure if failure else ''),flush=True)
  if failure:print(text[-2000:],flush=True)
 print(f'{report["status"]}: {len(cases)} cases; results {out}',flush=True)
 if report['status']!='PASS':sys.exit(1)

if __name__=='__main__':main()
