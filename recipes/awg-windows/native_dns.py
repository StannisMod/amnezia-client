"""Checked external-DNS ownership overlay for the pinned native Windows driver."""
from pathlib import Path


def replace(text, before, after, name):
    if text.count(after) == 1:
        return text
    if text.count(before) != 1:
        raise RuntimeError("Unexpected native Windows DNS entry: " + name)
    return text.replace(before, after)


FIELD = ("\tTableOff   bool\n",
         "\tTableOff   bool\n\tNativeDNSManaged bool\n")
PARSER = ('\t\t\tcase "preup":',
          '''\t\t\tcase "amnezianativedns":
\t\t\t\tmanaged, err := strconv.ParseBool(val)
\t\t\t\tif err != nil {
\t\t\t\t\treturn nil, &ParseError{l18n.Sprintf("Invalid native DNS ownership value"), val}
\t\t\t\t}
\t\t\t\tconf.Interface.NativeDNSManaged = managed
\t\t\tcase "preup":''')
COPY = ("\t\t\tTableOff:                   existingConfig.Interface.TableOff,\n",
        "\t\t\tTableOff:                   existingConfig.Interface.TableOff,\n"
        "\t\t\tNativeDNSManaged: existingConfig.Interface.NativeDNSManaged,\n")
VALIDATE = ("\treturn &conf, nil\n}\n\nfunc FromWgQuickWithUnknownEncoding",
            '''\tif conf.Interface.NativeDNSManaged && (!conf.Interface.TableOff ||
\t\tlen(conf.Interface.DNS) != 0 || len(conf.Interface.DNSSearch) != 0) {
\t\treturn nil, &ParseError{l18n.Sprintf("Native DNS ownership requires external routing and DNS"), "AmneziaNativeDNS"}
\t}
\treturn &conf, nil
}

func FromWgQuickWithUnknownEncoding''')
WRITER = ('\tif conf.Interface.TableOff {\n\t\toutput.WriteString("Table = off\\n")\n\t}\n',
          '\tif conf.Interface.TableOff {\n\t\toutput.WriteString("Table = off\\n")\n\t}\n'
          '\tif conf.Interface.NativeDNSManaged {\n\t\toutput.WriteString("AmneziaNativeDNS = true\\n")\n\t}\n')
ADDRESSES = ('''	err := luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}''',
'''	var err error
	if conf.Interface.NativeDNSManaged {
		// The service owns DNS aliases. Never flush/recreate them on an
		// interface notification; retain their SkipAsSource and active sockets.
		err = luid.SetIPAddressesForFamilyWithNativeDNS(family, addresses)
	} else {
		err = luid.SetIPAddressesForFamily(family, addresses)
		if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
			cleanupAddressesOnDisconnectedInterfaces(family, addresses)
			err = luid.SetIPAddressesForFamily(family, addresses)
		}
	}''')
DNS = ('\treturn luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)',
       '''\tif conf.Interface.NativeDNSManaged {
\t\treturn nil // DNS publication/restoration belongs to the checked service transaction.
\t}
\treturn luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)''')


def prepare(source, helper):
    source, helper = Path(source), Path(helper)
    changes = {
        "conf/config.go": [FIELD],
        "conf/parser.go": [PARSER, COPY, VALIDATE],
        "conf/writer.go": [WRITER],
        "tunnel/addressconfig.go": [ADDRESSES, DNS],
        "addressconfig.go": [ADDRESSES],
    }
    prepared = {}
    root = (source / "addressconfig.go").read_text()
    if root.count("\treturn ipif.Set()\n") != 1 or "luid.SetDNS(" in root:
        raise RuntimeError("Unexpected shipped native Windows DLL DNS ownership")
    for name, replacements in changes.items():
        text = (source / name).read_text()
        for before, after in replacements:
            text = replace(text, before, after, name)
        prepared[name] = text
    destination = source / "tunnel/winipcfg/native_dns_windows.go"
    if destination.exists() and destination.read_bytes() != helper.read_bytes():
        raise RuntimeError("Unexpected preexisting native Windows address helper")
    for name, text in prepared.items():
        (source / name).write_text(text)
    destination.write_bytes(helper.read_bytes())
