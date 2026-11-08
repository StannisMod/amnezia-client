#!/usr/bin/env python3
"""Build private, pinned gVisor TCP experiments; never edit GOMODCACHE/go.mod.

Backports for comparison, not an automatically approved production dependency:
  https://github.com/google/gvisor/pull/16081 (timeout-state guards)
  https://github.com/google/gvisor/pull/15432 (RACK flight accounting)
Upstream code is Apache-2.0; source files retain their copyright/license headers.
"""
import argparse, difflib, os, pathlib, shutil, subprocess
parser=argparse.ArgumentParser()
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--candidate',choices=['all','stock','guard','pipe','combined'],default='all')
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[3]/'native/routing'
version='v0.0.0-20231202080848-1f7806d17489'
if 'gvisor.dev/gvisor '+version not in (root/'go.mod').read_text():raise RuntimeError('review TCP experiments for the changed module pin')
cache=pathlib.Path(os.environ['GOMODCACHE'])
source=cache/('gvisor.dev/gvisor@'+version)
if not source.is_dir():raise RuntimeError('pinned module is not available in GOMODCACHE')
subprocess.run(['go','mod','verify'],cwd=root,check=True,stdout=subprocess.PIPE)
args.output.mkdir(parents=True,exist_ok=True)

def replace(text,old,new):
    if text.count(old)!=1:raise RuntimeError('pinned source context changed: '+old[:100])
    return text.replace(old,new,1)

def edit_guard(files):
    files['snd.go']=replace(files['snd.go'],'func (s *sender) detectLoss(seg *segment) (fastRetransmit bool) {','''func (s *sender) detectLoss(seg *segment) (fastRetransmit bool) {
	// Preserve timeout recovery while the pre-RTO flight is unacknowledged.
	if s.state == tcpip.RTORecovery {
		return false
	}''')
    files['snd.go']=replace(files['snd.go'],'numLost > 0 && !s.FastRecovery.Active {','numLost > 0 && !s.FastRecovery.Active && s.state != tcpip.RTORecovery {')
    files['rack.go']=replace(files['rack.go'],'if numLost == 0 {','if numLost == 0 || rc.snd.state == tcpip.RTORecovery {')

def edit_pipe(files):
    files['rack.go']=replace(files['rack.go'],'''func (rc *rackControl) DoRecovery(_ *segment, fastRetransmit bool) {
	snd := rc.snd''','''func (rc *rackControl) DoRecovery(_ *segment, fastRetransmit bool) {
	snd := rc.snd
	// Loss detection has updated RACK marks since the ACK's first SetPipe.
	snd.SetPipe()''')
    files['segment.go']=replace(files['segment.go'],'\tt.xmitCount = s.xmitCount','\tt.xmitCount = s.xmitCount\n\tt.acked = s.acked\n\tt.lost = s.lost')
    files['snd.go']=replace(files['snd.go'],'''s.sendSegment(seg)
		s.ep.stack.Stats().TCP.FastRetransmit''','''s.sendSegment(seg)
		if s.writeNext == seg {
			s.updateWriteNext(seg.Next())
		}
		s.ep.stack.Stats().TCP.FastRetransmit''')
    files['snd.go']=replace(files['snd.go'],'if !s.ep.scoreboard.IsRangeLost(sb) {','if !s1.lost && !s.ep.scoreboard.IsRangeLost(sb) {')

for name in (['stock','guard','pipe','combined'] if args.candidate=='all' else [args.candidate]):
    destination=args.output/name
    if destination.exists():raise SystemExit('output already exists: '+str(destination))
    shutil.copytree(source,destination)
    originals={file:(source/'pkg/tcpip/transport/tcp'/file).read_text() for file in ['snd.go','rack.go','segment.go']}
    files=originals.copy()
    if name in ['guard','combined']:edit_guard(files)
    if name in ['pipe','combined']:edit_pipe(files)
    notice='// Amnezia stability experiment: modified TCP recovery code; see the\n// Amnezia native/routing/patches attribution and comparison report.\n\n'
    for file,content in files.items():
        if content!=originals[file]:files[file]=replace(content,'package tcp\n',notice+'package tcp\n')
    patch=[]
    for file,content in files.items():
        if content==originals[file]:continue
        path=destination/'pkg/tcpip/transport/tcp'/file
        path.chmod(0o644);path.write_text(content)
        patch.extend(difflib.unified_diff(originals[file].splitlines(True),content.splitlines(True),fromfile='a/pkg/tcpip/transport/tcp/'+file,tofile='b/pkg/tcpip/transport/tcp/'+file))
    patch_text=''.join(patch)
    if name=='pipe':
        reviewed=root/'patches/gvisor-rack-flight.patch'
        if patch_text!=reviewed.read_text():raise RuntimeError('generated candidate differs from the reviewed backport')
    (args.output/(name+'.patch')).write_text(patch_text)
    mod=args.output/(name+'.mod')
    mod.write_text((root/'go.mod').read_text())
    shutil.copyfile(root/'go.sum',mod.with_suffix('.sum'))
    subprocess.run(['go','mod','edit','-modfile='+str(mod),'-replace=gvisor.dev/gvisor='+str(destination.resolve())],cwd=root,check=True)
    print(mod.resolve())
