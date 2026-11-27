// SPDX-License-Identifier: MPL-2.0
// Project overlay: reconcile native addresses without flushing service DNS
// aliases. This file is built inside the existing native Windows Go runtime.
package winipcfg

import (
	"net"
	"strconv"

	"golang.org/x/sys/windows"
)

func nativeDNSAlias(ip net.IP, prefix uint8) bool {
	v4 := ip.To4()
	return prefix == 32 && v4 != nil && v4[0] == 198 && v4[1] == 19 && v4[2] == 255
}

func nativeDNSAddressKey(ip net.IP, prefix uint8) string {
	return ip.String() + "/" + strconv.Itoa(int(prefix))
}

func (luid LUID) SetIPAddressesForFamilyWithNativeDNS(family AddressFamily, addresses []net.IPNet) error {
	wanted := make(map[string]net.IPNet)
	var order []string
	for _, address := range addresses {
		v4 := address.IP.To4()
		if (v4 == nil && family == windows.AF_INET) || (v4 != nil && family == windows.AF_INET6) {
			continue
		}
		prefix, _ := address.Mask.Size()
		key := nativeDNSAddressKey(address.IP, uint8(prefix))
		if _, exists := wanted[key]; !exists {
			order = append(order, key)
		}
		wanted[key] = address
	}
	var table *mibUnicastIPAddressTable
	if err := getUnicastIPAddressTable(family, &table); err != nil {
		return err
	}
	defer table.free()
	existing := make(map[string]bool)
	rows := table.get()
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID != luid {
			continue
		}
		ip := row.Address.IP()
		key := nativeDNSAddressKey(ip, row.OnLinkPrefixLength)
		if _, keep := wanted[key]; keep {
			existing[key] = true
			continue
		}
		if nativeDNSAlias(ip, row.OnLinkPrefixLength) {
			continue
		}
		if err := row.Delete(); err != nil {
			return err
		}
	}
	for _, key := range order {
		if !existing[key] {
			if err := luid.AddIPAddress(wanted[key]); err != nil {
				return err
			}
		}
	}
	return nil
}
