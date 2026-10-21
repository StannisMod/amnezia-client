//go:build linux && !android

package desktop

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const resolvedService = "org.freedesktop.resolve1"
const resolvedManager = resolvedService + ".Manager"
const resolvedInterface = resolvedService + ".Link"

type resolvedDNS struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Name        string
	RoutingOnly bool
}

// resolvedLink owns only our newly created TUN's resolver settings. Network
// managers may finish initializing that link after SetLinkDNS has returned and
// clear its DNS list. Watch the actual link properties rather than treating
// three successful resolvectl commands as lasting configuration ownership.
type resolvedLink struct {
	conn    *dbus.Conn
	manager dbus.BusObject
	link    dbus.BusObject
	index   int32
	cancel  context.CancelFunc
	done    chan struct{}
	err     error // published by closing done
	once    sync.Once
}

func startResolvedLink(ctx context.Context, index int) (*resolvedLink, error) {
	runCtx, cancel := context.WithCancel(ctx)
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(runCtx))
	if err != nil {
		cancel()
		return nil, errors.New("system resolver bus unavailable")
	}
	r := &resolvedLink{conn: conn, manager: conn.Object(resolvedService, "/org/freedesktop/resolve1"), index: int32(index), cancel: cancel, done: make(chan struct{})}
	setupCtx, setupCancel := context.WithTimeout(runCtx, 5*time.Second)
	defer setupCancel()
	var path dbus.ObjectPath
	// resolved consumes link creation asynchronously. A fresh kernel TUN can
	// exist before its resolver object is exported; wait only for NoSuchLink,
	// never retry permission/bus/configuration failures or DNS queries.
	for {
		err = r.manager.CallWithContext(setupCtx, resolvedManager+".GetLink", 0, r.index).Store(&path)
		var busError dbus.Error
		if !errors.As(err, &busError) || busError.Name != resolvedService+".NoSuchLink" {
			break
		}
		select {
		case <-setupCtx.Done():
			err = setupCtx.Err()
		case <-time.After(20 * time.Millisecond):
			continue
		}
		break
	}
	if err == nil {
		r.link = conn.Object(resolvedService, path)
		err = conn.AddMatchSignalContext(setupCtx, dbus.WithMatchObjectPath(path), dbus.WithMatchInterface("org.freedesktop.DBus.Properties"), dbus.WithMatchMember("PropertiesChanged"))
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	if err == nil {
		err = r.apply(setupCtx)
	}
	if err != nil {
		cancel()
		conn.Close()
		return nil, errors.New("system resolver link configuration failed")
	}
	go func() {
		defer close(r.done)
		defer conn.Close()
		// Signals handle external resets immediately; the timer also covers
		// invalidated/missed properties without spawning resolver processes.
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-signals:
			case <-ticker.C:
			}
			checkCtx, checkCancel := context.WithTimeout(runCtx, 5*time.Second)
			err := r.reconcile(checkCtx)
			checkCancel()
			if err != nil {
				if runCtx.Err() == nil {
					r.err = errors.New("system resolver link configuration lost")
				}
				return
			}
		}
	}()
	return r, nil
}

func (r *resolvedLink) apply(ctx context.Context) error {
	for _, call := range []struct {
		name string
		args []any
	}{
		{"SetLinkDomains", []any{r.index, []resolvedDomain{{".", true}}}},
		{"SetLinkDefaultRoute", []any{r.index, true}},
		{"SetLinkDNS", []any{r.index, []resolvedDNS{{2, []byte{172, 19, 0, 2}}}}},
	} {
		if err := r.manager.CallWithContext(ctx, resolvedManager+"."+call.name, 0, call.args...).Err; err != nil {
			return err
		}
	}
	return nil
}

func (r *resolvedLink) reconcile(ctx context.Context) error {
	var properties map[string]dbus.Variant
	if err := r.link.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, resolvedInterface).Store(&properties); err != nil {
		return err
	}
	var dns []resolvedDNS
	var domains []resolvedDomain
	var defaultRoute bool
	if err := properties["DNS"].Store(&dns); err != nil {
		return err
	}
	if err := properties["Domains"].Store(&domains); err != nil {
		return err
	}
	if err := properties["DefaultRoute"].Store(&defaultRoute); err != nil {
		return err
	}
	if len(dns) == 1 && dns[0].Family == 2 && string(dns[0].Address) == string([]byte{172, 19, 0, 2}) && len(domains) == 1 && domains[0] == (resolvedDomain{".", true}) && defaultRoute {
		return nil
	}
	return r.apply(ctx)
}

func (r *resolvedLink) Err() error {
	select {
	case <-r.done:
		return r.err
	default:
		return nil
	}
}

func (r *resolvedLink) Close() {
	r.once.Do(func() { r.cancel(); <-r.done })
}
