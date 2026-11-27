"""Checked Android-only overlay of the existing libXray/tun2socks owners.

No requirement versions or sums are changed. The caller supplies the exact
cached tun2socks source and a private build copy of libXray.
"""
import hashlib
import json
import shutil
from pathlib import Path


def downloaded_engine(output):
    """Require the actual frozen module body, not an empty go-list .Dir."""
    record = json.loads(output)
    if not isinstance(record, dict) or record.get("Error") or (
        record.get("Path") != "github.com/amnezia-vpn/amnezia-tun2socks/v2"
        or record.get("Version") != "v2.5.6"
    ):
        raise ValueError("Unexpected selected native tun2socks download")
    directory = record.get("Dir")
    if not isinstance(directory, str) or not directory or not Path(directory).is_absolute():
        raise ValueError("Selected native tun2socks download has no absolute source directory")
    path = Path(directory)
    if not (path / "engine/engine.go").is_file() or not (path / "go.mod").is_file():
        raise ValueError("Selected native tun2socks module body is unavailable")
    return path


def checked(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f"Unexpected native Android source: {path.name}")
    return data.decode()


def replace(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("Native Android DNS insertion point changed")
    return text.replace(old, new, 1)


def apply(source, tun2socks, support, dns):
    source, tun2socks, support, dns = map(Path, (source, tun2socks, support, dns))
    # Work on a private local replacement; never mutate a shared Go cache.
    target = source / "amnezia-native-tun2socks"
    if target.exists():
        raise RuntimeError("Refusing an already modified native engine")
    engine = checked(tun2socks / "engine/engine.go",
                     "4b6e5fda823c13be7a3baa4c1c7611114e804e2eca18479fc8700b0e93ffd179")
    socks = checked(tun2socks / "proxy/socks5/socks5.go",
                    "844d3a0a8aacde262234f1eaab644a54992c0a216432e6cd6629649f7f4cd2bf")
    wrapper = checked(source / "tun2socks_wrapper.go",
                      "0d1e408acbcd27762ca62f1d8bfbe725b12906b02db6e94053550df224a7cb3a")
    controller = checked(source / "controller_android.go",
                         "506454480a062c89cc1d3bb9aef640c4da6b4ab6df3c7ab2769271741cefb4bd")
    original_mod = (source / "go.mod").read_text()
    if "replace github.com/amnezia-vpn/amnezia-tun2socks/v2" in original_mod:
        raise RuntimeError("Native engine replacement already configured")
    engine = replace(engine, "\t_icmpHandler adapter.NetworkHandler",
                     "\t_icmpHandler adapter.NetworkHandler\n"
                     "\t_nativeDNSProxy func(proxy.Proxy) (proxy.Proxy, error)")
    engine = replace(engine, "func start() error {", """// SetNativeDNSProxy decorates only the existing native proxy. It creates no
// reader, stack or second forwarding engine. Set before StartTun2Socks.
func SetNativeDNSProxy(prepare func(proxy.Proxy) (proxy.Proxy, error)) {
	_engineMu.Lock()
	defer _engineMu.Unlock()
	_nativeDNSProxy = prepare
}

func start() error {""")
    engine = replace(engine, "\ttunnel.T().SetProxy(_defaultProxy)", """	if _nativeDNSProxy != nil {
		if _defaultProxy, err = _nativeDNSProxy(_defaultProxy); err != nil {
			return err
		}
	}
	tunnel.T().SetProxy(_defaultProxy)""")
    # Native DNS cancellation must include SOCKS UDP ASSOCIATE establishment,
    # not just the later UDP socket. Ordinary UDP keeps its original timeout.
    socks = replace(socks, "\tdefer cancel()\n\n\tc, err := dialer.DialContext(ctx, \"tcp\", ss.addr)", """	defer cancel()
	return ss.DialUDPContext(ctx)
}

func (ss *Socks5) DialUDPContext(ctx context.Context) (_ net.PacketConn, err error) {
	if ss.unix {
		return nil, errors.ErrUnsupported
	}
	c, err := dialer.DialContext(ctx, "tcp", ss.addr)""")
    socks = replace(socks, "\tutils.SetKeepAlive(c)\n\n\tdefer func() {", """	utils.SetKeepAlive(c)
	cancelHandshake := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer cancelHandshake()
	if deadline, ok := ctx.Deadline(); ok {
		if err = c.SetDeadline(deadline); err != nil { _ = c.Close(); return nil, err }
	}

	defer func() {""")
    socks = replace(socks, "\treturn &socksPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: c}, nil", """	if ctx.Err() != nil {
		_ = pc.Close()
		_ = c.Close()
		return nil, ctx.Err()
	}
	if err = c.SetDeadline(time.Time{}); err != nil {
		_ = pc.Close()
		_ = c.Close()
		return nil, err
	}
	return &socksPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: c}, nil""")
    socks = replace(socks, '\t"net/url"', '\t"net/url"\n\t"time"')
    # The TCP handshake has the same cancellation boundary.
    socks = replace(socks, "\tutils.SetKeepAlive(c)\n\n\tdefer func(c net.Conn)", """	utils.SetKeepAlive(c)
	cancelHandshake := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer cancelHandshake()
	if deadline, ok := ctx.Deadline(); ok {
		if err = c.SetDeadline(deadline); err != nil { _ = c.Close(); return nil, err }
	}

	defer func(c net.Conn)""")
    socks = replace(socks, "\treturn c, err\n}", """	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = c.SetDeadline(time.Time{})
	}
	return c, err
}""")
    wrapper = replace(wrapper, "\tengine.Insert((*engine.Key)(conf))",
                      "\tengine.SetNativeDNSProxy(nativeDNSProxy)\n\tengine.Insert((*engine.Key)(conf))")
    wrapper = replace(wrapper, "\terr := engine.StopTun2Socks()", """	quiesceNativeDNS()
	err := engine.StopTun2Socks()
	if err == nil { closeNativeDNS() }""")
    controller = controller.replace(
        "func(network, address string, conn syscall.RawConn) error {\n",
        "func(network, address string, conn syscall.RawConn) error {\n"
        "\t\tif err := nativeDNSControl(network, address); err != nil { return err }\n")
    if controller.count("nativeDNSControl(network, address)") != 2:
        raise RuntimeError("Native Android socket protection hooks changed")
    shutil.copytree(tun2socks, target)
    # Go module-cache sources are read-only. Only the private copy is writable.
    for path in target.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (target / "engine/engine.go").write_text(engine)
    (target / "proxy/socks5/socks5.go").write_text(socks)
    shutil.copy2(support / "native_dns_socks_test.go", target / "proxy/socks5/native_dns_test.go")
    (source / "tun2socks_wrapper.go").write_text(wrapper)
    (source / "controller_android.go").write_text(controller)
    (source / "go.mod").write_text(original_mod +
        "\nreplace github.com/amnezia-vpn/amnezia-tun2socks/v2 => ./amnezia-native-tun2socks\n")
    package = source / "amnezianativedns"
    package.mkdir()
    for path in dns.glob("*.go"):
        if not path.name.endswith("_test.go"):
            shutil.copy2(path, package / path.name)
    shutil.copy2(support / "native_dns_android.go", source / "native_dns_android.go")
    shutil.copy2(support / "native_dns_android_test.go", source / "native_dns_android_test.go")
