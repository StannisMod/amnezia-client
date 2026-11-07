//go:build linux && !android

package desktop

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
)

const captureMark = uint32(0x20000000)
const captureTableName = "amnezia_route_capture"
const captureOwner = "amnezia-routing:output-capture:v1"
const captureInputOwner = "amnezia-routing:input-capture:v1"
const captureForwardOwner = "amnezia-routing:no-forward:v1"

// Mark only locally emitted packets. An iif lo policy also matches the kernel's
// reverse-source lookup on physical ingress (fib_validate_source), breaking
// strict rp_filter for off-link peers. OUTPUT marks never affect that lookup.
func captureExpressions() []expr.Any {
	word := binaryutil.NativeEndian.PutUint32
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: word(socketMark), Xor: word(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: word(0)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: word(^captureMark), Xor: word(captureMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

func fromCaptureInterface() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(InterfaceName), 0)},
	}
}

func captureInputExpressions() []expr.Any {
	word := binaryutil.NativeEndian.PutUint32
	return append(fromCaptureInterface(),
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: word(^captureMark), Xor: word(captureMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1})
}
func captureForwardExpressions() []expr.Any {
	// The packet tunnel proxies local applications, never a routed LAN. A
	// reply to an address no longer owned by the kernel must not escape onto
	// a physical interface (or be forwarded back into the capture TUN).
	return append(fromCaptureInterface(), &expr.Verdict{Kind: expr.VerdictDrop})
}

func captureTable() *nftables.Table {
	return &nftables.Table{Name: captureTableName, Family: nftables.TableFamilyINet}
}

func findCaptureTable() (*nftables.Table, error) {
	tables, err := (&nftables.Conn{}).ListTables()
	if err != nil {
		return nil, errors.New("native packet marking inventory unavailable")
	}
	for _, table := range tables {
		if table.Name == captureTableName && table.Family == nftables.TableFamilyINet {
			return table, nil
		}
	}
	return nil, nil
}

func installCaptureMark() error {
	table, err := findCaptureTable()
	if err != nil {
		return err
	}
	if table != nil {
		return errors.New("reserved packet marking table is occupied; explicit recovery is required")
	}
	c := &nftables.Conn{}
	table = c.AddTable(captureTable())
	chain := c.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeRoute,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle})
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: captureExpressions(), UserData: []byte(captureOwner)})
	input := c.AddChain(&nftables.Chain{Name: "input_mark", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle})
	c.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: captureInputExpressions(), UserData: []byte(captureInputOwner)})
	forward := c.AddChain(&nftables.Chain{Name: "forward_guard", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: table, Chain: forward, Exprs: captureForwardExpressions(), UserData: []byte(captureForwardOwner)})
	if err := c.Flush(); err != nil {
		return errors.New("capture packet marking installation failed")
	}
	return nil
}

// Validate the entire private table before recovering it. Never flush global
// nftables state or delete a table merely because its name resembles ours.
func ownedCaptureTable() (*nftables.Table, error) {
	table, err := findCaptureTable()
	if err != nil || table == nil {
		return table, err
	}
	c := &nftables.Conn{}
	chains, err := c.ListChains()
	if err != nil {
		return nil, err
	}
	count := 0
	seen := make(map[string]bool)
	for _, chain := range chains {
		if chain.Table.Name != table.Name || chain.Table.Family != table.Family {
			continue
		}
		count++
		var kind nftables.ChainType
		var hook *nftables.ChainHook
		var priority *nftables.ChainPriority
		var owner string
		var expressions []expr.Any
		switch chain.Name {
		case "output":
			kind, hook, priority, owner, expressions = nftables.ChainTypeRoute, nftables.ChainHookOutput, nftables.ChainPriorityMangle, captureOwner, captureExpressions()
		case "input_mark":
			kind, hook, priority, owner, expressions = nftables.ChainTypeFilter, nftables.ChainHookPrerouting, nftables.ChainPriorityMangle, captureInputOwner, captureInputExpressions()
		case "forward_guard":
			kind, hook, priority, owner, expressions = nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter, captureForwardOwner, captureForwardExpressions()
		default:
			return nil, errors.New("refusing recovery of an unrecognized packet marking chain")
		}
		seen[chain.Name] = true
		if chain.Type != kind || chain.Hooknum == nil ||
			*chain.Hooknum != *hook || chain.Priority == nil || *chain.Priority != *priority ||
			(chain.Policy != nil && *chain.Policy != nftables.ChainPolicyAccept) || chain.Device != "" {
			return nil, errors.New("refusing recovery of an unrecognized packet marking chain")
		}
		rules, err := c.GetRules(table, chain)
		if err != nil {
			return nil, err
		}
		if len(rules) != 1 || !bytes.Equal(rules[0].UserData, []byte(owner)) || !reflect.DeepEqual(rules[0].Exprs, expressions) {
			return nil, errors.New("refusing recovery of an unrecognized packet marking rule")
		}
	}
	// Recognize the original output-only schema too, for explicit recovery
	// after upgrade. A partial/new or foreign table is never silently erased.
	if !seen["output"] || (count != 1 && !(count == 3 && seen["input_mark"] && seen["forward_guard"])) {
		return nil, errors.New("refusing recovery of an unrecognized packet marking table")
	}
	return table, nil
}

func removeCaptureTable(table *nftables.Table) error {
	if table == nil {
		return nil
	}
	c := &nftables.Conn{}
	c.DelTable(table)
	return c.Flush()
}
