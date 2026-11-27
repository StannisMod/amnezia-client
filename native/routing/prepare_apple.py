"""Prepare the single existing AWG/XRay archive with the pinned routing core."""
from pathlib import Path
import shutil


LEGACY_XRAY_CALLBACK = """func LibXraySetSockCallback(cb C.libxray_sockcallback, ctx unsafe.Pointer) *C.char {
	err := internet.RegisterDialerController(func(net, addr string, conn syscall.RawConn) error {
		conn.Control(func(fd uintptr) {
			C.libxray_invokesockcallback(cb, C.uintptr_t(fd), ctx)
		})
		return nil
	})

	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}"""


def prepare_xray(text):
    if text.count(LEGACY_XRAY_CALLBACK) != 1:
        raise RuntimeError("Unexpected legacy Xray socket callback")
    text = text.replace(LEGACY_XRAY_CALLBACK, """func LibXraySetSockCallback(cb C.libxray_sockcallback, ctx unsafe.Pointer) *C.char {
	return C.CString("legacy socket callbacks are disabled; use owned native socket scope")
}

func init() {
	amneziaXrayRegisterController = func(controller func(string, string, syscall.RawConn) error) error {
		return internet.RegisterDialerController(controller)
	}
}""")
    return text


def prepare_module(core, destination):
    core, destination = Path(core).resolve(), Path(destination).resolve()
    local = destination / "amnezia-routing"
    if local.exists():
        shutil.rmtree(local)
    shutil.copytree(core, local, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    bridge = core / "applebridge"
    for source, target in (("module.mod", "go.mod"), ("module.sum", "go.sum"),
                            ("routing_apple.go", "routing_apple.go"),
                             ("native_dns_apple.go", "native_dns_apple.go"),
                             ("native_filter_apple.go", "native_filter_apple.go"),
                             ("native_xray_apple.go", "native_xray_apple.go"),
                           ("amnezia_routing.h", "amnezia_routing.h")):
        shutil.copy2(bridge / source, destination / target)
    xray = destination / "api-xray.go"
    xray.write_text(prepare_xray(xray.read_text()))
    api = destination / "api-apple.go"
    text = api.read_text()
    original = "dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)"
    if text.count(original) != 1:
        raise RuntimeError("Unexpected native AWG TUN ownership entry point")
    api.write_text(text.replace(original, "dev := device.NewDevice(amneziaNativeFilterTUN(tun), conn.NewStdNetBind(), logger)"))
    makefile = destination / "Makefile"
    text = makefile.read_text()
    original = "go build -ldflags=-w"
    if text.count(original) != 1:
        raise RuntimeError("Unexpected AWG Apple build entry point")
    text = text.replace(original, "python3 amnezia-routing/internal/builddeps/verify.py --module . --scope apple --output routing-tcp-provenance.json && go build -mod=readonly -tags with_gvisor,amnezia_apple_bridge -ldflags=-w")
    makefile.write_text(text)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--module", type=Path, required=True)
    args = parser.parse_args()
    prepare_module(args.core, args.module)
