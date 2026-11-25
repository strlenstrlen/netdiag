//go:build !darwin

package path

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// On Linux, unprivileged ICMP sockets report "time exceeded" through the
// socket error queue (IP_RECVERR); that isn't implemented yet.
func trace(ctx context.Context, dst net.IP, o Options) ([]reply, map[int]int, error) {
	hint := "tracepath -n"
	if runtime.GOOS == "windows" {
		hint = "tracert -d"
	}
	return nil, nil, fmt.Errorf("not supported on %s yet; try `%s %s`", runtime.GOOS, hint, dst)
}
