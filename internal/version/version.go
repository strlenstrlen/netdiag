// Package version holds the build version. Release builds set it with
//
//	-ldflags "-X github.com/strlenstrlen/netdiag/internal/version.Version=1.2.3"
package version

// Version is "dev" for local builds unless the build sets it.
var Version = "dev"

// UserAgent identifies netdiag to the public test endpoints.
func UserAgent() string { return "netdiag/" + Version + " (+https://github.com/strlenstrlen/netdiag)" }
