//go:build !darwin && !linux && !windows

package snapshot

import (
	"context"
	"errors"
	"runtime"
)

// Windows and other platforms: interface and address data still come from
// the cross-platform code; these adapters are not written yet.
var errUnsupported = errors.New("not implemented on " + runtime.GOOS + " yet")

func platformInterfaceKinds(ctx context.Context) map[string]string { return map[string]string{} }

func platformRoutes(ctx context.Context) (*Route, *Route, error) { return nil, nil, errUnsupported }

func platformDNS(ctx context.Context) ([]string, string, error) { return nil, "", errUnsupported }

func platformProxy(ctx context.Context) (Proxy, error) { return Proxy{}, nil }

func platformWiFi(ctx context.Context, ifaces []Interface) (*WiFi, error) { return nil, nil }
