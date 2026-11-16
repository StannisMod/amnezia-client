"""Actual installed-service OpenVPN regression on a disposable Windows VM.

The companion Linux fixture must share only the owned VM's isolated network.
Private synthetic TLS profiles are deleted on exit; no host networking is used.
"""
import argparse,ipaddress,json,os,platform,queue,socket,subprocess,tempfile,threading,time,urllib.parse,urllib.request
from collections import Counter
from pathlib import Path
if not __debug__:
 raise SystemExit('Native acceptance requires Python assertions enabled')
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture-url',required=True)
parser.add_argument('--ipc-driver',required=True,type=Path)
parser.add_argument('--work',required=True,type=Path)
parser.add_argument('--owned-vm-name',required=True)
parser.add_argument('--case',required=True,choices=('full','include','exclude','api-full','legacy-full','legacy-include','legacy-exclude','legacy-export','legacy-api','stale-full'))
parser.add_argument('--route-updates',action='store_true')
parser.add_argument('--native-ipv6-preference',action='store_true')
args=parser.parse_args()
assert not args.native_ipv6_preference or (args.case=='full' and not args.route_updates)
assert platform.system()=='Windows' and os.environ.get('COMPUTERNAME')==args.owned_vm_name
assert os.environ.get('AMNEZIA_IPV6_LAB')=='owned-windows-vm','requires an explicitly owned disposable VM'
url=urllib.parse.urlsplit(args.fixture_url)
assert url.scheme=='http' and url.hostname in ('127.0.0.1','10.0.2.2') and not url.username and not url.password
assert args.ipc_driver.is_file()
args.work.mkdir(parents=True,exist_ok=True)
root=Path(tempfile.mkdtemp(prefix=args.case+'-',dir=args.work)).resolve()
assert not any(c in str(root) for c in ('\n','\r','"'))
profile=root/'client.ovpn';log=root/'client.log'
report={'result':'FAIL','case':args.case,'route_updates':args.route_updates}
expected_origins=Counter()
sockets=[];driver=None;management=None;management_listener=None;messages=queue.Queue()
def read_exact(s,n):
 data=b''
 while len(data)<n:
  chunk=s.recv(n-len(data));assert chunk,'original TCP closed';data+=chunk
 return data
def connect(address,port,tag=None):
 s=socket.create_connection((address,port),timeout=5);sockets.append(s)
 if tag:
  assert read_exact(s,len(tag)+1)==(tag+'\n').encode(),address
  expected_origins['TCP|'+address+'|'+tag]+=1
 return s
def echo(s):
 value=os.urandom(19);s.sendall(value);assert read_exact(s,len(value))==value

def ps(command):return subprocess.check_output(['powershell','-NoProfile','-Command',"$ErrorActionPreference='Stop';"+command],text=True,timeout=15).strip()
def snapshot():
 value=json.loads(ps("@(Get-NetRoute | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore) | ConvertTo-Json -Compress"))
 return sorted(value,key=lambda x:json.dumps(x,sort_keys=True))
def rpc(value,expected='OK'):
 driver.stdin.write(json.dumps(value)+'\n');driver.stdin.flush()
 reply=messages.get(timeout=20);assert reply==expected,('unexpected service IPC result',value.get('operation','route'),reply)
def server_origins():
 with urllib.request.urlopen('http://10.0.2.2:21945/origins',timeout=5) as response:
  return Counter(json.load(response))
try:
 origins_before=server_origins()
 native4=connect('10.0.2.2',18080);echo(native4)
 native6=connect('2001:db8:42::4',21944,'NATIVE');echo(native6)
 fixture=json.loads(urllib.request.urlopen(args.fixture_url,timeout=5).read())
 cases=[case for case in fixture['openvpn_cases'] if case['name']==args.case];assert len(cases)==1
 case=cases[0];expected=case['expected']
 assert set(expected)=={'fd99::4','fd99::5','2001:db8:42::4','64:ff9b::c000:201'}
 assert all(origin in ('VPN','NATIVE','BLOCKED') for origin in expected.values())
 if args.route_updates:
  assert args.case=='include' and fixture['server_ipv6']
 else:
  native6.close();sockets.remove(native6)
  for address in expected:
   baseline=connect(address,21944,'NATIVE');echo(baseline);baseline.close();sockets.remove(baseline)
   with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as udp:
    udp.settimeout(2);udp.sendto(b'baseline',(address,21944));assert udp.recv(32)==b'NATIVE',address
    expected_origins['UDP|'+address+'|NATIVE']+=1
  report['all_native_baselines']=True
 config=cases[0]['config']['openvpn_config_data']['config']
 management_listener=socket.socket();management_listener.bind(('127.0.0.1',0));management_listener.listen();management_listener.settimeout(10)
 port=management_listener.getsockname()[1]
 profile.write_text(config+f'\nverb 3\nmanagement 127.0.0.1 {port}\nmanagement-client\nlog "{log.as_posix()}"\n')
 log.unlink(missing_ok=True)
 env=dict(os.environ,AMNEZIA_IPV6_LAB='owned-windows-vm')
 stderr=(root/'openvpn-route-case-ipc-stderr.log').open('w')
 driver=subprocess.Popen([str(args.ipc_driver),'--ipc-process'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True,env=env)
 def reader():
  for line in driver.stdout:messages.put(line.strip())
  messages.put('EXITED')
 threading.Thread(target=reader,daemon=True).start()
 assert messages.get(timeout=90)=='READY','installed service IPC unavailable'
 before=snapshot()
 rpc({'operation':'start','config':str(profile)})
 management,_=management_listener.accept()
 def drain_management():
  try:
   while management.recv(8192):pass
  except OSError:pass
 threading.Thread(target=drain_management,daemon=True).start()
 until=time.monotonic()+45
 while True:
  text=log.read_text(errors='replace') if log.exists() else ''
  if 'Initialization Sequence Completed' in text:break
  assert 'Exiting due to fatal error' not in text,'see private client.log in the owned VM'
  assert time.monotonic()<until,'OpenVPN did not become ready: '+'see private client.log in the owned VM'
  time.sleep(.2)
 if args.route_updates:
  echo(native4);echo(native6)
  vpn4=connect('10.76.0.1',18080);echo(vpn4)
  vpn6=connect('fd99::4',21944,'VPN');echo(vpn6)
  baseline6=connect('2001:db8:42::4',21944,'NATIVE');echo(baseline6)
  baseline6.close();sockets.remove(baseline6)
  report['fresh_native_ipv6_before_route']=True
  addresses=json.loads(ps("@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like '10.76.0.*'} | Select-Object IPAddress) | ConvertTo-Json -Compress"))
  if isinstance(addresses,dict):addresses=[addresses]
  assert len(addresses)==1,addresses
  local=addresses[0]['IPAddress'];assert ipaddress.ip_address(local) in ipaddress.ip_network('10.76.0.0/24')
  rpc({'local_ipv4':local,'hosts':['2001:db8:42::4'],'through_vpn':True})
  for s in (native4,native6,vpn4,vpn6):echo(s)
  new6=connect('2001:db8:42::4',21944,'VPN');echo(new6)
  rpc({'local_ipv4':local,'hosts':['2001:db8:42::4'],'through_vpn':False})
  for s in (native4,native6,vpn4,vpn6,new6):echo(s)
  direct6=connect('2001:db8:42::4',21944,'NATIVE');echo(direct6)
  for through_vpn in (True,False):
   rpc({'local_ipv4':local,'hosts':['2001:db8:42::4'],'through_vpn':through_vpn})
   for s in (native4,native6,vpn4,vpn6,new6,direct6):echo(s)
   fresh=connect('2001:db8:42::4',21944,'VPN' if through_vpn else 'NATIVE');echo(fresh)
   fresh.close();sockets.remove(fresh)
  # A separately owned native host route must reject a conflicting VPN
  # update and survive this service process's eventual route cleanup.
  native_source=str(ipaddress.IPv6Address(native6.getsockname()[0]))
  physical=json.loads(ps("$entries=@(Get-NetIPAddress -AddressFamily IPv6 | Where-Object {[BitConverter]::ToString(([System.Net.IPAddress]::Parse($_.IPAddress)).GetAddressBytes()) -eq [BitConverter]::ToString(([System.Net.IPAddress]::Parse('"+native_source+"')).GetAddressBytes())}); if($entries.Count -ne 1){throw 'ambiguous native source interface'}; $index=$entries[0].InterfaceIndex; @(Get-NetRoute -DestinationPrefix '::/0' -InterfaceIndex $index | Select-Object InterfaceIndex,NextHop) | ConvertTo-Json -Compress"))
  if isinstance(physical,dict):physical=[physical]
  assert len(physical)==1,'ambiguous native gateway'
  native_index=int(physical[0]['InterfaceIndex']);assert native_index>0
  native_gateway=str(ipaddress.IPv6Address(physical[0]['NextHop']))
  foreign_selector="Get-NetRoute -DestinationPrefix '64:ff9b::c000:201/128' -InterfaceIndex "+str(native_index)+" -ErrorAction SilentlyContinue"
  ps("if("+foreign_selector+"){throw 'refusing an existing host route'}")
  ps("New-NetRoute -DestinationPrefix '64:ff9b::c000:201/128' -InterfaceIndex "+str(native_index)+" -NextHop '"+native_gateway+"' -RouteMetric 17 -PolicyStore ActiveStore | Out-Null")
  foreign_created=True
  rpc({'local_ipv4':local,'hosts':['64:ff9b::c000:201'],'through_vpn':True},expected='FAIL')
  for opened in (native4,native6,vpn4,vpn6,new6,direct6):echo(opened)
  foreign_probe=connect('64:ff9b::c000:201',21944,'NATIVE');echo(foreign_probe)
  report.update(result='PASS',old_tcp_count=6,new_vpn_and_native_ipv6=True,repeated_direction_changes=2,foreign_route_collision_rejected=True)
 else:
  echo(native4)
  vpn4=connect('10.76.0.1',18080);echo(vpn4)
  report['ipv6_origins']={}
  for address,origin in expected.items():
   assert origin in ('VPN','NATIVE','BLOCKED')
   if origin=='BLOCKED':
    try:
     blocked=socket.create_connection((address,21944),timeout=2)
    except OSError:
     tcp='BLOCKED'
    else:
     blocked.close();raise AssertionError('IPv6 TCP escaped blocked profile: '+address)
   else:
    current=connect(address,21944,origin);echo(current)
    current.close();sockets.remove(current);tcp=origin
   with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as udp:
    udp.settimeout(2);udp.sendto(b'profile-origin',(address,21944))
    try:reply=udp.recv(32).decode('ascii')
    except (TimeoutError,ConnectionRefusedError,ConnectionResetError):reply='BLOCKED'
    assert reply==origin,('IPv6 UDP origin mismatch',address,origin,reply)
    if origin!='BLOCKED':expected_origins['UDP|'+address+'|'+origin]+=1
   report['ipv6_origins'][address]={'tcp':tcp,'udp':reply}
   echo(native4);echo(vpn4)
   report.update(result='PASS',ipv4_native_and_vpn_echo=True)
   if args.native_ipv6_preference:
    native_policy_pending=True
    rpc({'operation':'native_ipv6','blocked':True,'endpoints':[]})
    # Turning KillSwitch off must not remove the independent IPv6 preference.
    rpc({'operation':'disable_kill_switch'})
    for address in expected:
     try:
      escaped=socket.create_connection((address,21944),timeout=2)
     except OSError:pass
     else:
      escaped.close();raise AssertionError('native IPv6 preference leaked TCP: '+address)
     with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as udp:
      udp.settimeout(2)
      try:
       udp.sendto(b'disabled-ipv6-preference',(address,21944))
       udp.recv(32)
      except OSError:pass
      else:raise AssertionError('native IPv6 preference leaked UDP: '+address)
    echo(native4);echo(vpn4)
    rpc({'operation':'native_ipv6','blocked':False,'endpoints':[]})
    native_policy_pending=False
    for address,origin in expected.items():
     assert origin!='BLOCKED'
     restored=connect(address,21944,origin);echo(restored)
     restored.close();sockets.remove(restored)
    report['native_ipv6_preference']={'blocked_tcp_udp':8,'survived_killswitch_disable':True,
      'ipv4_native_and_vpn_preserved':True,'ipv6_restored':True}

finally:
 if report['result']!='PASS' and driver is not None:
  try:
   report['selected_route']=json.loads(ps("@(Get-NetRoute -DestinationPrefix '2001:db8:42::4/128' -ErrorAction SilentlyContinue | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric) | ConvertTo-Json -Compress") or '[]')
   report['neighbor']=json.loads(ps("@(Get-NetNeighbor -IPAddress '2001:db8:42::4' -ErrorAction SilentlyContinue | Select-Object InterfaceIndex,IPAddress,State) | ConvertTo-Json -Compress") or '[]')
   report['adapter_types']=json.loads(ps("@(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter | Select-Object Name,InterfaceIndex,InterfaceType) | ConvertTo-Json -Compress") or '[]')
  except Exception as error:report['diagnostics_error']=type(error).__name__
 cleanup_errors=[]
 def cleanup(name,action):
  try:action()
  except Exception as error:cleanup_errors.append(name+': '+type(error).__name__)
 for opened in sockets:cleanup('socket',opened.close)
 if management is not None:
  def stop_openvpn():
   management.sendall(b'signal SIGTERM\n')
   until=time.monotonic()+8
   while time.monotonic()<until:
    if log.exists() and 'SIGTERM[hard,' in log.read_text(errors='replace'):return
    time.sleep(.1)
   raise TimeoutError('normal OpenVPN shutdown was not observed')
  cleanup('management shutdown',stop_openvpn)
  cleanup('management socket',management.close)
 if management_listener is not None:cleanup('management listener',management_listener.close)
 if driver is not None:
  if locals().get('native_policy_pending',False):
   cleanup('native IPv6 preference release',lambda:rpc({'operation':'native_ipv6','blocked':False,'endpoints':[]}))
  cleanup('service process release',lambda:rpc({'operation':'stop'}))
  cleanup('IPC input',driver.stdin.close)
  try:driver.wait(timeout=10)
  except subprocess.TimeoutExpired:
   cleanup_errors.append('IPC driver did not exit')
   cleanup('IPC driver kill',driver.kill)
   cleanup('IPC driver wait',lambda:driver.wait(timeout=5))
 if 'stderr' in locals():cleanup('stderr file',stderr.close)
 cleanup('private profile removal',lambda:profile.unlink(missing_ok=True))
 if 'foreign_created' in locals():
  def remove_foreign_fixture():
   # Remove only the exact route this test created, after verifying that the
   # real service's destruction left the foreign row untouched.
   ps("$rows=@("+foreign_selector+"); if($rows.Count -ne 1 -or $rows[0].NextHop -ne '"+native_gateway+"' -or $rows[0].RouteMetric -ne 17){throw 'foreign route changed or deleted'}; $rows[0] | Remove-NetRoute -Confirm:$false")
   report['foreign_route_survived_service_cleanup']=True
  cleanup('foreign fixture route',remove_foreign_fixture)
 if 'before' in locals():
  def verify_restoration():
   end=time.monotonic()+15
   while time.monotonic()<end:
    if snapshot()==before:break
    time.sleep(.25)
   after=snapshot();report['os_routes_restored']=after==before
   if after!=before:
    old={json.dumps(x,sort_keys=True) for x in before};new={json.dumps(x,sort_keys=True) for x in after}
    report['route_delta']={'removed':[json.loads(x) for x in sorted(old-new)],'added':[json.loads(x) for x in sorted(new-old)]}
    raise RuntimeError('OS routes were not restored')
  cleanup('OS restoration',verify_restoration)
 if 'origins_before' in locals():
  def verify_origins():
   after=server_origins()
   delivered=Counter({key:after[key]-origins_before[key] for key in after if after[key]!=origins_before[key]})
   report['server_origin_delta']=dict(delivered)
   assert delivered==expected_origins,('independent origin counts differ',dict(expected_origins),dict(delivered))
  cleanup('independent server delivery',verify_origins)
 if cleanup_errors:
  report['cleanup_errors']=cleanup_errors;report['result']='FAIL'
 (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report),flush=True)
assert report['result']=='PASS',report
