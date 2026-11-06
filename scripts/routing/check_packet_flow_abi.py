#!/usr/bin/env python3
"""Exercise the actual C ABI and packet path, without claiming Apple OS runtime."""
import argparse
import base64
import ctypes as c
import ipaddress
import json
import os
import queue
import struct
import sys
import tempfile
from pathlib import Path


def dns_packet():
    question = b"\x06packet\x04test\x00" + struct.pack("!HH", 1, 1)
    dns = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + question
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                                  ipaddress.ip_address("172.19.0.10").packed, ipaddress.ip_address("172.19.0.2").packed))
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    struct.pack_into("!H", header, 10, ~total & 65535)
    return bytes(header) + udp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path)
    args = parser.parse_args()
    library = c.CDLL(str(args.library.resolve()))
    # Read the actual shared Go payload, not a separately compiled probe.
    import importlib.util
    verifier_path=Path(__file__).resolve().parents[2]/'native/routing/internal/builddeps/verify.py'
    spec=importlib.util.spec_from_file_location('routing_builddeps',verifier_path)
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    library.AmneziaRoutingBuildInfo.argtypes=[]
    library.AmneziaRoutingBuildInfo.restype=c.c_void_p
    pointer=library.AmneziaRoutingBuildInfo()
    assert pointer, 'missing Apple backend build identity'
    release_build_info=c.CDLL(None).free
    release_build_info.argtypes=[c.c_void_p]
    release_build_info.restype=None
    try:
        verifier.verify_info(json.loads(c.string_at(pointer)), 'apple')
    finally:
        release_build_info(pointer)
    print('PASS: actual Apple bridge uses the locked TCP recovery fork')
    if sys.platform == "darwin":
        # Exercise the real public resolver API, not just a cross-compiled
        # declaration. Do not log the host's DNS addresses.
        library.AmneziaRoutingSystemDNS.argtypes = []
        library.AmneziaRoutingSystemDNS.restype = c.c_void_p
        pointer = library.AmneziaRoutingSystemDNS()
        assert pointer, "public Apple DNS snapshot failed"
        release = c.CDLL(None).free
        release.argtypes = [c.c_void_p]
        release.restype = None
        try:
            servers = json.loads(c.string_at(pointer))
        finally:
            release(pointer)
        assert 1 <= len(servers) <= 16, "public Apple DNS snapshot is empty or oversized"
        for server in servers:
            ipaddress.ip_address(server["address"].split("%", 1)[0])
            assert 1 <= server["port"] <= 65535
        print("PASS: public Apple DNS snapshot returns numeric servers and ports")
    writer_type = c.CFUNCTYPE(c.c_int32, c.c_void_p, c.c_void_p, c.c_int32)
    release_type = c.CFUNCTYPE(None, c.c_void_p)
    library.AmneziaRoutingStart.argtypes = [c.c_char_p, c.c_int32, c.c_void_p, writer_type, release_type]
    library.AmneziaRoutingStart.restype = c.c_int64
    library.AmneziaRoutingStop.argtypes = [c.c_int64]
    library.AmneziaRoutingFeed.argtypes = [c.c_int64, c.c_char_p, c.c_int32]
    library.AmneziaRoutingFeed.restype = c.c_int32
    library.AmneziaRoutingStats.argtypes = [c.c_int64] + [c.POINTER(c.c_uint64)] * 3
    library.AmneziaRoutingStats.restype = c.c_int32
    packets = queue.Queue()
    releases = []

    @writer_type
    def writer(host, packet, length):
        packets.put(c.string_at(packet, length))
        return 1

    @release_type
    def release(host):
        releases.append(host)

    assert library.AmneziaRoutingStart(b"{}", 2, 1, writer, release) < 0
    assert releases == [1], "failed start leaked retained host"
    with tempfile.TemporaryDirectory() as directory:
        config = {
            "rules": {"version": 1, "default": "vpn", "rules": []},
            "resolver": "1.1.1.1:53", "resolver_action": "vpn",
            "cache_path": str(Path(directory) / "fakeip.db"),
            "awg": {"address": ["10.77.0.1"], "private_key": base64.b64encode(os.urandom(32)).decode(),
                    "public_key": base64.b64encode(b"\x09" + bytes(31)).decode(),
                    "endpoint": "127.0.0.1:9", "allowed_ips": ["0.0.0.0/0"]},
        }
        raw = json.dumps(config).encode()
        previous = None
        for host in (2, 3, 4):
            handle = library.AmneziaRoutingStart(raw, len(raw), host, writer, release)
            assert handle > 0, "C ABI startup failed"
            try:
                packet = dns_packet()
                assert library.AmneziaRoutingFeed(handle, packet, len(packet)) == 0
                reply = packets.get(timeout=3)
                assert len(reply) >= 44 and reply[9] == 17
                transaction, flags = struct.unpack_from("!HH", reply, 28)
                assert transaction == 7 and flags & 0x800F == 0x8000, "unexpected DNS response"
                fake = ipaddress.ip_address(reply[-4:])
                assert fake in ipaddress.ip_network("198.18.0.0/15")
                assert previous is None or previous == fake, "FakeIP changed across restart"
                previous = fake
                counters = [c.c_uint64() for _ in range(3)]
                assert library.AmneziaRoutingStats(handle, *map(c.byref, counters)) == 0
            finally:
                library.AmneziaRoutingStop(handle)
            library.AmneziaRoutingStop(handle)
            assert releases.count(host) == 1, "host not released exactly once"
            assert library.AmneziaRoutingFeed(handle, packet, len(packet)) == -1
    print("PASS: C ABI start, packet DNS/FakeIP, restart identity, stats, failed start and stop lifetime")


if __name__ == "__main__":
    main()
