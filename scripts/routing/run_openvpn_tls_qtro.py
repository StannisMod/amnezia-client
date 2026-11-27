#!/usr/bin/env python3
"""Real TLS and QtRO process-loss fixture; run only in a private container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument("--openvpn", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exercise-reconnect", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--native-ipv6-block", action="store_true")
    args = parser.parse_args()
    if os.environ.get("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace":
        raise RuntimeError("requires isolated namespace")
    links = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True))
    if {x["ifname"] for x in links} != {"lo"}:
        raise RuntimeError("requires --network none")
    quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
    memory = int(Path("/sys/fs/cgroup/memory.max").read_text())
    swap = int(Path("/sys/fs/cgroup/memory.swap.max").read_text())
    if quota > 2 * period or memory > 4 * 1024**3 or swap != 0:
        raise RuntimeError("requires 2 CPU / 4 GiB / zero extra swap")
    print(f"Measured fixture cgroup: cpu={quota}/{period}, memory={memory}, swap={swap}", flush=True)
    root = Path(__file__).resolve().parents[2]
    out = args.output
    out.mkdir(exist_ok=False)
    processes = []
    logs = []

    def run(*command):
        subprocess.run(list(map(str, command)), check=True)

    def launch(name, *command):
        log = (out / (name + ".log")).open("w")
        logs.append(log)
        process = subprocess.Popen(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def wait(predicate, description, seconds=25):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            if any(process.poll() is not None for process in processes):
                raise RuntimeError("process exited before " + description)
            time.sleep(.1)
        raise RuntimeError("deadline: " + description)

    try:
        run("ip", "link", "set", "lo", "up")
        run("cmake", "-S", root / "tests/openvpn-service-tls", "-B", out / "peer-build",
            "-DCMAKE_PREFIX_PATH=/opt/Qt/6.10.1/gcc_64")
        run("cmake", "--build", out / "peer-build", "--parallel", "2")
        for name in ("ca", "server", "client"):
            run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=" + name, "-keyout", out / (name + ".key"),
                "-out", out / (name + ".csr"))
        (out / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\n"
                                   "keyUsage=critical,keyCertSign,cRLSign\n")
        run("openssl", "x509", "-req", "-in", out / "ca.csr", "-signkey", out / "ca.key",
            "-days", "2", "-extfile", out / "ca.ext", "-out", out / "ca.crt")
        for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
            ext = out / (name + ".ext")
            ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                           "extendedKeyUsage=" + usage + "\n")
            run("openssl", "x509", "-req", "-in", out / (name + ".csr"), "-CA", out / "ca.crt",
                "-CAkey", out / "ca.key", "-CAcreateserial", "-days", "2",
                "-extfile", ext, "-out", out / (name + ".crt"))
        common = f"proto udp\nca {out}/ca.crt\ndisable-dco\nverb 4\n"
        server = out / "server.conf"
        server.write_text(common + f"dev tun-server\nlocal 127.0.0.1\nport 11940\n"
            f"server 10.89.0.0 255.255.255.0\ntopology subnet\ndh none\n"
            f"cert {out}/server.crt\nkey {out}/server.key\n"
            'push "dns server 1 address 2001:db8::53"\n'
            'push "dns server 1 resolve-domains route.example"\n'
            'push "dns search-domains search.example"\n')
        client = out / "client.conf"
        client.write_text(common + f"client\ndev tun\nremote 127.0.0.1 11940\nnobind\n"
            f"cert {out}/client.crt\nkey {out}/client.key\nremote-cert-tls server\n"
            f"connect-retry-max 1\nlog {out}/native.log\n")
        if args.exercise_reconnect:
            with client.open("a") as config:
                config.write("persist-tun\npersist-key\n")
        if args.native_ipv6_block:
            directives = subprocess.check_output(
                [str(out / "peer-build/openvpn_qtro_peer"), "--blocking-directives"], text=True)
            with client.open("a") as config:
                config.write(directives)
        # Copy the measured bytes beside one another for production exec lookup.
        bin_dir = out / "bin"
        bin_dir.mkdir()
        shutil.copy2(args.service, bin_dir / "AmneziaVPN-service")
        shutil.copy2(args.openvpn, bin_dir / "openvpn")
        print("SERVICE_SHA256", hashlib.sha256(args.service.read_bytes()).hexdigest(), flush=True)
        print("OPENVPN_SHA256", hashlib.sha256(args.openvpn.read_bytes()).hexdigest(), flush=True)
        if args.prepare_only:
            print("PASS: cached TLS credentials/configs/QtRO peer prepared; no native process launched", flush=True)
            return
        native_server = launch("server", bin_dir / "openvpn", "--config", server)
        wait(lambda: "Initialization Sequence Completed" in (out / "server.log").read_text(),
             "TLS server initialization")
        service = launch("service", bin_dir / "AmneziaVPN-service", "--console")
        wait(lambda: Path("/tmp/local:AmneziaVpnIpcInterface").exists(), "QtRO service socket")
        peer = out / "peer-build/openvpn_qtro_peer"
        descriptor = out / "descriptor"
        gui = launch("gui", peer, "start", client, descriptor)
        wait(lambda: ",CONNECTED,SUCCESS" in (out / "gui.log").read_text(),
             "native TLS CONNECTED")
        if gui.poll() is not None or service.poll() is not None or native_server.poll() is not None:
            raise RuntimeError("unexpected process exit")
        journals = list(Path(os.environ["XDG_CONFIG_HOME"]).rglob("owned-*.json"))
        if len(journals) != 1:
            raise RuntimeError("expected one durable DNS journal")
        record = json.loads(journals[0].read_text())
        (out / "published-journal.json").write_text(json.dumps(record, indent=2))
        def dns_queries():
            for endpoint in record["installed"]:
                for tcp in (False, True):
                    for qtype, rcode in ((28, 0), (1, 2)):
                        query = struct.pack("!6H", 291, 256, 1, 0, 0, 0)
                        query += b"\x05probe\x05route\x07example\x00" + struct.pack("!2H", qtype, 1)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
                            sock.settimeout(2)
                            sock.connect((endpoint, 53))
                            if tcp:
                                sock.sendall(struct.pack("!H", len(query)) + query)
                                length = sock.recv(2)
                                if len(length) != 2:
                                    raise RuntimeError("short TCP DNS length")
                                remaining = struct.unpack("!H", length)[0]
                                reply = b""
                                while len(reply) < remaining:
                                    chunk = sock.recv(remaining - len(reply))
                                    if not chunk:
                                        raise RuntimeError("short TCP DNS body")
                                    reply += chunk
                            else:
                                sock.send(query)
                                reply = sock.recv(4096)
                        ident, flags, questions, answers, _, _ = struct.unpack("!6H", reply[:12])
                        if ident != 291 or not flags & 32768 or flags & 15 != rcode or answers != 0 or questions != 1:
                            raise RuntimeError("unexpected DNS answer")
        dns_queries()
        gui.kill()
        gui.wait(timeout=5)
        processes.remove(gui)
        # A new process attaches after actual SIGKILL of the original replica.
        # Native session must remain published and owned by the service.
        if service.poll() is not None or not journals[0].exists():
            raise RuntimeError("GUI loss destroyed service ownership")
        dns_queries()
        if args.exercise_reconnect:
            children = Path(f"/proc/{service.pid}/task/{service.pid}/children").read_text().split()
            native_children = [int(pid) for pid in children
                if Path(f"/proc/{pid}/exe").resolve() == (bin_dir / "openvpn").resolve()]
            if len(native_children) != 1:
                raise RuntimeError("cannot identify service-owned native child")
            native_pid = native_children[0]
            os.kill(native_pid, signal.SIGUSR1)
            wait(lambda: (out / "native.log").read_text().count("CONNECTED,SUCCESS") >= 2,
                 "persist-tun reconnect without GUI")
            updated = json.loads(journals[0].read_text())
            if (updated["owner"] != record["owner"]
                    or updated["interface_index"] != record["interface_index"]
                    or updated["installed"] != record["installed"]):
                raise RuntimeError("persist-tun reconnect lost DNS/interface ownership")
            dns_queries()
            if not Path(f"/proc/{native_pid}").exists():
                raise RuntimeError("native process replaced during soft reconnect")
            print("PASS: native SIGUSR1/persist-tun reconnect without GUI; same owner/interface/aliases; "
                  "UDP/TCP NODATA/SERVFAIL retained", flush=True)
        stop = launch("reattached-stop", peer, "stop", client, descriptor.read_text())
        if stop.wait(timeout=20) != 0:
            raise RuntimeError("reattached stop failed")
        if journals[0].exists():
            raise RuntimeError("finished emitted before journal retirement")
        native_log = (out / "native.log").read_text()
        ack = native_log.find("MANAGEMENT: CMD 'needok 'AMNEZIA-DNS-RESTORE:")
        closed = native_log.lower().find("closing tun/tap interface")
        if ack < 0 or closed < ack:
            raise RuntimeError("missing native restore ACK before TUN teardown")
        current_links = json.loads(subprocess.check_output(["ip", "-j", "address"], text=True))
        addresses = {a["local"] for link in current_links for a in link.get("addr_info", [])}
        if set(record["installed"]) & addresses:
            raise RuntimeError("alias retained after confirmed finish")
        print("PASS: real TLS CONNECTED; UDP/TCP NODATA/SERVFAIL before/after QtRO replica SIGKILL; "
              "reattach; restore ACK before native TUN teardown; aliases/journal retired", flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
