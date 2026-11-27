#!/usr/bin/env python3
"""Compile changed production TUs using existing Ninja/Conan build flags offline.

This is a compile check, not a link, installed-service, or native VPN acceptance.
The existing build/cache remains read-only.
"""
import argparse
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--native-include", type=Path, required=True)
    parser.add_argument("--only", action="append", help="Limit to named production source paths")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    service = "service/server/CMakeFiles/AmneziaVPN-service.dir/"
    client = "client/CMakeFiles/AmneziaVPN.dir/"
    entries = [
        (service + "__/__/ipc/ipcserverprocess.cpp.o", "ipc/ipcserverprocess.cpp"),
        (service + "__/__/ipc/ipcserver.cpp.o", "ipc/ipcserver.cpp"),
        (service + "router.cpp.o", "service/server/router.cpp"),
        (service + "__/__/ipc/ipcserverprocess.cpp.o", "service/server/nativednsservice.cpp"),
        (service + "__/__/ipc/ipcserverprocess.cpp.o", "service/server/openvpndnssession.cpp"),
        (service + "__/__/ipc/ipcserverprocess.cpp.o", "service/server/openvpndnsselection.cpp"),
        (client + "core/protocols/openVpnProtocol.cpp.o", "client/core/protocols/openVpnProtocol.cpp"),
        (client + "core/configurators/openVpnConfigurator.cpp.o", "client/core/configurators/openVpnConfigurator.cpp"),
        (client + "core/protocols/xrayProtocol.cpp.o", "client/core/protocols/xrayProtocol.cpp"),
    ]
    if args.only:
        entries = [entry for entry in entries if entry[1] in args.only]
        if {entry[1] for entry in entries} != set(args.only):
            parser.error("Unknown production source in --only")
    with tempfile.TemporaryDirectory(prefix="openvpn-production-compile-") as temporary:
        output = Path(temporary)
        repc = Path("/opt/Qt/6.10.1/gcc_64/libexec/repc")
        for name in ("ipc_process_interface", "ipc_interface"):
            for kind in ("source", "replica"):
                subprocess.run([str(repc), "-i", "rep", "-o", kind,
                    str(source / "ipc" / f"{name}.rep"), str(output / f"rep_{name}_{kind}.h")], check=True)
        for index, (target, relative) in enumerate(entries):
            lines = subprocess.check_output(
                ["ninja", "-C", str(args.build), "-t", "commands", target], text=True).splitlines()
            command = shlex.split(lines[-1])
            if command[0] == "ccache":
                command.pop(0)
            command = [part.replace("/work/src", str(source)) for part in command]
            command[1:1] = [f"-I{output}", f"-I{args.native_include}"]
            command[command.index("-c") + 1] = str(source / relative)
            command[command.index("-o") + 1] = str(output / f"{index}.o")
            if "-MF" in command:
                command[command.index("-MF") + 1] = str(output / f"{index}.d")
            subprocess.run(command, cwd=args.build, check=True)
            print(f"PASS: production compile with regenerated current RPC headers: {relative}", flush=True)


if __name__ == "__main__":
    main()
