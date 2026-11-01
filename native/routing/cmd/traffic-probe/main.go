//go:build !ios && (!android || amnezia_android_probe)

// traffic-probe is a disposable native application, including Android
// acceptance. It has its own OS process and never joins the VPN host runtime.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/StannisMod/amnezia-client/native/routing/internal/fixturequic"
)

func main() {
	address := flag.String("quic", "", "native QUIC destination")
	ca := flag.String("ca", "", "disposable fixture certificate DER")
	flag.Parse()
	label, err := fixturequic.Probe(*address, *ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(label)
}
