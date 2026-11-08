#!/usr/bin/env python3
"""Summarize ACK-to-retransmission gaps from header-only fixture traces."""
import argparse, collections, datetime, json, pathlib, re
parser=argparse.ArgumentParser()
parser.add_argument('trace',type=pathlib.Path)
parser.add_argument('--sender',choices=['server','client'],default='server')
args=parser.parse_args()
rows=[]
probes=[]
if args.trace.suffix=='.jsonl':
    for line in args.trace.read_text().splitlines():
        r=json.loads(line)
        if 'rto_s' in r: probes.append(r); continue
        if 'direction' not in r:continue
        r['time']=datetime.datetime.fromisoformat(r['at'].replace('Z','+00:00')).timestamp()
        rows.append(r)
else:
    # This parser intentionally accepts only the fixture's inner IPv4 addresses.
    pattern=re.compile(r'^(\d+\.\d+) IP (10\.77\.0\.[12])\.(\d+) > (10\.77\.0\.[12])\.(\d+):.*?length (\d+)')
    for line in args.trace.read_text().splitlines():
        match=pattern.search(line)
        if not match:continue
        at,src,sport,dst,dport,length=match.groups()
        seq=re.search(r'\bseq (\d+)(?::(\d+))?',line)
        ack=re.search(r'\back (\d+)',line);window=re.search(r'\bwin (\d+)',line)
        if not ack:continue
        rows.append({'time':float(at),'at':datetime.datetime.fromtimestamp(float(at),datetime.timezone.utc).isoformat(),
          'direction':'server_tx' if src=='10.77.0.2' else 'server_rx','sport':int(sport),'dport':int(dport),
          'seq':int(seq[1]) if seq else 0,'ack':int(ack[1]),'window':int(window[1]) if window else 0,'length':int(length)})
if args.sender=='client':
    for r in rows:r['direction']='server_rx' if r['direction']=='server_tx' else 'server_tx'
if probes:
    constrained=[r for r in probes if r['rto_s']>2 and r['outstanding']>r['cwnd'] and r['wnd']>0]
    print(json.dumps({'probe_records':len(probes),'max_rto_s':max(r['rto_s'] for r in probes),'open_window_constrained_recovery_samples':constrained[:16]},indent=2))
    raise SystemExit(0)
latest_ack={};first_sent={};gaps=[];last_data={};bursts=[]
for r in rows:
    port=r['dport'] if r['direction']=='server_tx' else r['sport']
    # With client as sender the fixed server port is the destination.
    if args.sender=='client':port=r['sport'] if r['direction']=='server_tx' else r['dport']
    if r['direction']=='server_rx':
        latest_ack[port]=r
    elif r['length']:
        previous=last_data.get(port)
        if previous and r['time']-previous['time']>1:
            bursts.append({'port':port,'previous_data_at':previous['at'],'next_data_at':r['at'],'data_gap_s':round(r['time']-previous['time'],6),'latest_ack_at':latest_ack.get(port,{}).get('at')})
        last_data[port]=r
        key=(port,r['seq']);ack=latest_ack.get(port)
        if ack and ack['window'] and ack['ack']==r['seq'] and key in first_sent and first_sent[key]<ack['time']:
            gap=r['time']-ack['time']
            if gap>1:gaps.append({'port':port,'ack_at':ack['at'],'retransmit_at':r['at'],'ack_to_retransmit_s':round(gap,6),'seq':r['seq'],'payload_bytes':r['length'],'advertised_window_unscaled':ack['window']})
        first_sent.setdefault(key,r['time'])
print(json.dumps({'sender':args.sender,'header_records':len(rows),'data_burst_gaps':sorted(bursts,key=lambda r:r['data_gap_s'],reverse=True)[:12],'ack_to_retransmission_gaps':sorted(gaps,key=lambda r:r['ack_to_retransmit_s'],reverse=True)[:12]},indent=2))
