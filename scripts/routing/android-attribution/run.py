from pathlib import Path
import argparse,os,subprocess,zipfile,json,time,re
parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True);args=parser.parse_args()
sdk=Path(os.environ['ANDROID_HOME']);tools=sdk/'build-tools/36.0.0';android=sdk/'platforms/android-36/android.jar'
source=Path(__file__).resolve().parent;work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
def run(*args): return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True).stdout
def adb(*args): return run(sdk/'platform-tools/adb',*args).strip()
assert adb('shell','getprop','ro.kernel.qemu')=='1', 'requires disposable Android emulator'
assert int(adb('shell','getprop','ro.build.version.sdk'))>=29
classes=work/'classes';classes.mkdir(exist_ok=True)
run('javac','-source','8','-target','8','-classpath',android,'-d',classes,*source.glob('*.java'))
dex=work/'dex';dex.mkdir(exist_ok=True);run(tools/'d8','--min-api','29','--lib',android,'--output',dex,*classes.rglob('*.class'))
key=work/'test.jks'
if not key.exists():run('keytool','-genkeypair','-keystore',key,'-alias','test','-storepass','android','-keypass','android','-dname','CN=Disposable UID test','-keyalg','RSA','-validity','2')
packages=['org.amnezia.uidprobe','org.amnezia.uidprobe.a','org.amnezia.uidprobe.b']
try:
 for package in packages:
  subprocess.run([str(sdk/'platform-tools/adb'),'uninstall',package],capture_output=True)
  entry='Starter' if package==packages[0] else 'Probe'
  service='<service android:name="org.amnezia.uidprobe.OwnerService" android:permission="android.permission.BIND_VPN_SERVICE" android:exported="true"><intent-filter><action android:name="android.net.VpnService"/></intent-filter></service>' if entry=='Starter' else ''
  manifest=work/(package+'.xml');manifest.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}"><uses-sdk android:minSdkVersion="29" android:targetSdkVersion="28"/><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.FOREGROUND_SERVICE"/><application android:debuggable="true" android:testOnly="true">{service}</application><instrumentation android:name="org.amnezia.uidprobe.{entry}" android:targetPackage="{package}"/></manifest>')
  unsigned=work/(package+'-unsigned.apk');run(tools/'aapt2','link','-I',android,'--manifest',manifest,'-o',unsigned)
  with zipfile.ZipFile(unsigned,'a') as apk:apk.write(dex/'classes.dex','classes.dex')
  aligned=work/(package+'-aligned.apk');apk=work/(package+'.apk');run(tools/'zipalign','-f','4',unsigned,aligned)
  run(tools/'apksigner','sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned)
  adb('install','-r','-t',apk)
 adb('shell','appops','set',packages[0],'ACTIVATE_VPN','allow')
 owner=subprocess.Popen([str(sdk/'platform-tools/adb'),'shell','am','instrument','-w',packages[0]+'/org.amnezia.uidprobe.Starter'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 time.sleep(3)
 children=[subprocess.Popen([str(sdk/'platform-tools/adb'),'shell','am','instrument','-w',p+'/org.amnezia.uidprobe.Probe'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True) for p in packages[1:]]
 for child in children: print(child.communicate(timeout=25)[0])
 print(owner.communicate(timeout=30)[0])
 uids=adb('shell','pm','list','packages','-U','org.amnezia.uidprobe');print('UIDS',uids)
 events=adb('shell','run-as','org.amnezia.uidprobe','cat','files/events.jsonl')
 (work/'events.jsonl').write_text(events+'\n')
 rows=[json.loads(line) for line in events.splitlines() if line.strip()]
 expected=dict(re.findall(r'package:(\S+) uid:(\d+)',uids))
 observed={}
 for label in ('a','b'):
  uid=int(expected['org.amnezia.uidprobe.'+label])
  for kind in ('system','raw'):
   values=sorted({r['uid'] for r in rows if r['dns_name'].startswith(kind+'-'+label+'-')})
   assert values==[uid], (label,kind,values,uid)
   observed[kind+'-'+label]=values
  assert any(r['uid']==uid and r['protocol']==6 for r in rows), 'TCP owner missing'
  assert any(r['uid']==uid and r['destination_port']==18082 for r in rows), 'UDP owner missing'
 (work/'report.json').write_text(json.dumps({'api':int(adb('shell','getprop','ro.build.version.sdk')),'expected':expected,'observed':observed,'status':'PASS_BASIC_ATTRIBUTION'},indent=2))
 print(json.dumps(observed))

finally:
 for package in packages:
  subprocess.run([str(sdk/'platform-tools/adb'),'shell','am','force-stop',package],capture_output=True)
  subprocess.run([str(sdk/'platform-tools/adb'),'uninstall',package],capture_output=True)
