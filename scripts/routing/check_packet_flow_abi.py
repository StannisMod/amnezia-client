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
