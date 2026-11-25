//go:build darwin

package snapshot

import (
	"context"
	"errors"
	"time"
)

const cmdTimeout = 3 * time.Second

func platformInterfaceKinds(ctx context.Context) map[string]string {
	out, err := runCmd(ctx, cmdTimeout, "/usr/sbin/networksetup", "-listallhardwareports")
	if err != nil {
		return map[string]string{}
	}
	return parseHardwarePorts(out)
}

func platformRoutes(ctx context.Context) (*Route, *Route, error) {
	// `route get` exits non-zero when there is no default route; that's a
	// finding, not a collection error.
	out4, _ := runCmd(ctx, cmdTimeout, "/sbin/route", "-n", "get", "default")
	out6, _ := runCmd(ctx, cmdTimeout, "/sbin/route", "-n", "get", "-inet6", "default")
	return parseRouteGet(out4), parseRouteGet(out6), nil
}

func platformDNS(ctx context.Context) ([]string, string, error) {
	out, err := runCmd(ctx, cmdTimeout, "/usr/sbin/scutil", "--dns")
	if err != nil {
		return nil, "scutil --dns", err
	}
	servers := parseScutilDNS(out)
	if len(servers) == 0 {
		return nil, "scutil --dns", errors.New("no default resolvers configured")
	}
	return servers, "scutil --dns", nil
}

func platformProxy(ctx context.Context) (Proxy, error) {
	out, err := runCmd(ctx, cmdTimeout, "/usr/sbin/scutil", "--proxy")
	if err != nil {
		return Proxy{}, err
	}
	return parseScutilProxy(out), nil
}
