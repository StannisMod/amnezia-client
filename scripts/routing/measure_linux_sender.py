"""Run in a disposable, network-none Linux container with NET_ADMIN and NET_RAW."""
import argparse
import concurrent.futures
import json
import os
import socket
import struct
import subprocess
import threading
import time

def now():
    return time.monotonic_ns() / 1e6

def nft(*args):
    subprocess.run(['nft', *args], check=True, stdout=subprocess.DEVNULL)

def trial(case):
    mode, seconds = case
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    def pair():
        receiver = socket.create_connection(listener.getsockname())
        sender, _ = listener.accept()
        receiver.settimeout(150)
        sender.settimeout(150)
        return sender, receiver
    bulk, sink = pair()
    chat, inbox = pair()
    peer = sink.getsockname()[1]
    packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    packet.bind(('lo', 0))
    packet.settimeout(.1)
    table = 'sender_' + str(port)
    stop = threading.Event()
    packets = []
    def capture():
        while not stop.is_set():
            try:
                frame = packet.recv(65535)
            except socket.timeout:
                continue
            offset = 14 + (frame[14] & 15)*4
            if frame[23] != 6:
                continue
            src, dst, seq, ack = struct.unpack_from('!HHII', frame, offset)
            if {src,dst} == {port,peer}:
                packets.append((now(),src,seq,ack,len(frame)))
    t = threading.Thread(target=capture)
    t.start()
    def info():
        data = bulk.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
        return dict(rto_ms=struct.unpack_from('=I',data,8)[0]/1000,
                    backoff=data[4], retrans=struct.unpack_from('=I',data,100)[0])
    payload = bytes(4096)
    try:
        bulk.sendall(payload)
        sink.recv(len(payload),socket.MSG_WAITALL)
        time.sleep(125)
        nft('add','table','inet',table)
        nft('add','chain','inet',table,'out','{ type filter hook input priority 0; }')
        if mode != 'clean':
            rule = ['tcp','sport',str(port)]
            if mode == 'size':
                rule += ['ip','length','>','1200']
            nft('add','rule','inet',table,'out',*rule,'drop')
        initial = info()
        bulk.sendall(payload)
        chat.sendall(b'x')
        inbox.settimeout(.1)
        try:
            small = inbox.recv(1) == b'x'
        except socket.timeout:
            small = False
        if small != (mode != 'all'):
            raise AssertionError('unexpected short-message delivery')
        time.sleep(seconds)
        before = info()
        nft('flush','chain','inet',table,'out')
        cleared = now()
        probe, reader = pair()
        probe.sendall(payload)
        assert reader.recv(len(payload),socket.MSG_WAITALL) == payload
        verified = now()
        assert sink.recv(len(payload),socket.MSG_WAITALL) == payload
        done = now()
        time.sleep(.1)
        probe.close()
        reader.close()
        after = info()
        data = next((p for p in packets if p[0]>=cleared and p[1]==port and p[4]>1200),None)
        ack = next((p for p in packets if data and p[0]>=data[0] and p[1]==peer and p[3]==(data[2]+len(payload))%2**32),None)
        if mode != 'clean' and (data is None or ack is None or before['backoff'] == 0):
            raise AssertionError('missing retransmission, ACK, or sender backoff')
        return dict(mode=mode,seconds=seconds,small=small,initial=initial,before=before,after=after,
                    control_ms=round(verified-cleared,2),read_ms=round(done-cleared,2),
                    first_data_ms=round(data[0]-cleared,2) if data else None,
                    ack_ms=round(ack[0]-cleared,2) if ack else None)
    finally:
        stop.set()
        t.join()
        nft('delete','table','inet',table)
        for s in (packet,bulk,sink,chat,inbox,listener):
            s.close()

if __name__=='__main__':
    if not os.path.isfile('/.dockerenv') or socket.if_nameindex()!=[(1,'lo')]:
        raise SystemExit('requires isolated Docker loopback')
    parser = argparse.ArgumentParser()
    parser.add_argument('--extended', action='store_true')
    args = parser.parse_args()
    cases = ([('size', s) for s in (30, 60, 112)] if args.extended else
             [('clean', 1), ('all', 3.1)] + [('size', s) for s in (1, 3.1, 6.5, 10, 14)])
    with concurrent.futures.ThreadPoolExecutor(len(cases)) as pool:
        for row in pool.map(trial,cases):
            print(json.dumps(row),flush=True)
