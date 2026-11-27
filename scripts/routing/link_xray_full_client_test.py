#!/usr/bin/env python3
"""Link an actual-class GUI test against the completed desktop client's objects."""
import argparse
from pathlib import Path
import shlex
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--build", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--test-source", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.output
out.mkdir(exist_ok=False)
qt = Path("/opt/Qt/6.10.1/gcc_64")
source = args.test_source or root / "tests/xray-service-stop/testFullClient.cpp"
subprocess.run([str(qt / "libexec/moc"), str(source), "-o", str(out / (source.stem + ".moc"))], check=True)
command = shlex.split(subprocess.check_output([
    "ninja", "-C", str(args.build), "-t", "commands",
    "client/CMakeFiles/AmneziaVPN.dir/core/protocols/xrayProtocol.cpp.o"], text=True).splitlines()[-1])
if command[0] == "ccache":
    command.pop(0)
command[1:1] = [f"-I{out}", f"-I{qt}/include/QtTest",
                f"-I{root}/client/platforms/linux/daemon"]
command[command.index("-c") + 1] = str(source)
command[command.index("-o") + 1] = str(out / "test.o")
if "-MF" in command:
    command[command.index("-MF") + 1] = str(out / "test.d")
subprocess.run(command, cwd=args.build, check=True)
tokens = shlex.split(subprocess.check_output(
    ["ninja", "-C", str(args.build), "-t", "commands", "client/AmneziaVPN"], text=True).splitlines()[-1])
start = next(i for i, token in enumerate(tokens) if token.endswith("/c++"))
end = tokens.index("&&", start) if "&&" in tokens[start:] else len(tokens)
link = tokens[start:end]
main = "client/CMakeFiles/AmneziaVPN.dir/main.cpp.o"
if link.count(main) != 1:
    raise RuntimeError("unexpected completed desktop-client link command")
link[link.index(main)] = str(out / "test.o")
link[link.index("-o") + 1] = str(out / "test_full_client_xray_stop")
link += [str(qt / "lib/libQt6Test.so"), str(qt / "lib/libQt6DBus.so"),
         str(args.build / "service/server/CMakeFiles/AmneziaVPN-service.dir/__/__/client/platforms/linux/daemon/linuxdnsrecovery.cpp.o")]
subprocess.run(link, cwd=args.build, check=True)
print("PASS: actual full-client objects linked with GUI acceptance test main; no protocol body substitution", flush=True)
