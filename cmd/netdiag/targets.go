package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/path"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/target"
)

var errHelp = flag.ErrHelp

// commonFlags are shared by the single-target subcommands.
type commonFlags struct {
	json    *bool
	noColor *bool
	config  *string
}

func newCommand(name, usageLine string) (*flag.FlagSet, commonFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := commonFlags{
		json:    fs.Bool("json", false, "print JSON instead of the summary"),
		noColor: fs.Bool("no-color", false, "disable colored output"),
		config:  fs.String("config", "", "JSON file overriding the default test endpoints"),
	}
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: netdiag %s\n\nFlags:\n", usageLine)
		fs.PrintDefaults()
	}
	return fs, c
}

// parseWithArg parses flags that may come before or after one positional
// argument ("netdiag dns example.com --json" and "netdiag dns --json example.com").
func parseWithArg(fs *flag.FlagSet, args []string) (string, int, bool) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			if err == errHelp {
				return "", exitOK, false
			}
			return "", exitError, false
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	if len(pos) != 1 {
		fs.Usage()
		return "", exitError, false
	}
	return pos[0], 0, true
}

func cmdDNS(args []string) int {
	fs, c := newCommand("dns", "dns <name> [flags]")
	name, code, ok := parseWithArg(fs, args)
	if !ok {
		return code
	}
	cfg, err := config.Load(*c.config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snap := snapshot.Collect(ctx)
	r := target.CheckDNS(ctx, name, snap.DNSServers, cfg.PublicDNS, cfg.ProbeTimeout())
	if *c.json {
		return writeJSON(r, r.Conclusion)
	}
	s := newStyle(!*c.noColor)
	w := os.Stdout
	fmt.Fprintln(w)
	writeConclusion(w, s, "DNS check: "+r.Name, r.Conclusion)
	fmt.Fprintln(w)
	fmt.Fprintln(w, s.bold("Answers"))
	for _, a := range r.Answers {
		who := "this computer"
		switch a.Kind {
		case "configured":
			who = a.Server + " (your DNS)"
		case "public":
			who = a.Server + " (" + target.PublicName(a.Server) + ")"
		}
		res := strings.Join(firstN(a.Addrs, 3), ", ")
		switch {
		case a.Sinkhole:
			res += "  " + s.yellow("← blocked (sinkhole address)")
		case a.NotFound:
			res = "no such name"
		case !a.OK:
			res = s.red(nz(a.ErrKind, "no answer"))
		}
		fmt.Fprintf(w, "  %-28s %6.0f ms  %s\n", who, a.RTTMs, res)
	}
	if r.CNAME != "" {
		fmt.Fprintf(w, "  %s\n", s.dim("alias for "+r.CNAME))
	}
	fmt.Fprintln(w)
	return exitFor(r.Conclusion.Status)
}

func cmdSite(args []string) int {
	fs, c := newCommand("site", "site <url or host> [flags]")
	input, code, ok := parseWithArg(fs, args)
	if !ok {
		return code
	}
	cfg, err := config.Load(*c.config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	snap := snapshot.Collect(ctx)
	r, err := target.CheckSite(ctx, input, snap.DNSServers, cfg.PublicDNS, snap.DefaultRoute6 != nil, cfg.ProbeTimeout())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	if *c.json {
		return writeJSON(r, r.Conclusion)
	}
	s := newStyle(!*c.noColor)
	w := os.Stdout
	fmt.Fprintln(w)
	writeConclusion(w, s, "Site check: "+r.URL, r.Conclusion)
	fmt.Fprintln(w)
	fmt.Fprintln(w, s.bold("Details"))
	sys := ""
	for _, a := range r.DNS.Answers {
		if a.Kind == "system" {
			sys = strings.Join(firstN(a.Addrs, 4), ", ")
			if !a.OK {
				sys = nz(a.ErrKind, "no answer")
			}
		}
	}
	fmt.Fprintf(w, "  %-12s %s\n", "DNS", sys)
	for _, t := range r.Connect {
		res := s.red(nz(t.ErrKind, "failed"))
		switch {
		case t.Connected:
			res = fmt.Sprintf("connected in %.0f ms", t.RTTMs)
		case t.Refused:
			res = s.yellow("refused")
		}
		fmt.Fprintf(w, "  %-12s %-40s %s\n", "Connect", t.Target, res)
	}
	if p := r.Ping; p != nil {
		res := "no reply (many sites block ping; not a problem by itself)"
		if p.OK() {
			res = fmt.Sprintf("%d/%d replies · %.0f ms", p.Received, p.Sent, probe.Median(p.RTTsMs))
		}
		fmt.Fprintf(w, "  %-12s %s\n", "Ping", s.dim(res))
	}
	if h := r.HTTP; h.Status > 0 || h.ErrKind != "" {
		res := fmt.Sprintf("HTTP %d · %.0f ms to first byte", h.Status, h.TotalMs)
		if h.ErrKind != "" {
			res = s.red(h.ErrKind)
		}
		fmt.Fprintf(w, "  %-12s %s\n", "Request", res)
		if h.TLSVersion != "" || h.CertIssuer != "" {
			tls := strings.TrimSpace(h.TLSVersion + " · certificate from " + nz(h.CertIssuer, "?"))
			if h.CertExpiresDays > 0 {
				tls += fmt.Sprintf(", valid %d more days", h.CertExpiresDays)
			}
			fmt.Fprintf(w, "  %-12s %s\n", "Security", tls)
		}
	}
	ref := s.red(nz(r.Reference.ErrKind, "failed"))
	if r.Reference.OK {
		ref = fmt.Sprintf("OK in %.0f ms", r.Reference.TotalMs)
	}
	fmt.Fprintf(w, "  %-12s %s %s\n", "Reference", ref, s.dim("("+target.Reference+")"))
	fmt.Fprintln(w)
	return exitFor(r.Conclusion.Status)
}

func cmdPath(args []string) int {
	fs, c := newCommand("path", "path <host> [flags]")
	rounds := fs.Int("rounds", 15, "probes per hop")
	maxHops := fs.Int("max-hops", 30, "give up after this many hops")
	host, code, ok := parseWithArg(fs, args)
	if !ok {
		return code
	}
	if u, err := target.NormalizeURL(host); err == nil {
		host = u.Hostname() // accept URLs too
	}
	interactive := isTerminal(os.Stdout) && !*c.json
	progress := func(msg string) {
		if interactive {
			fmt.Fprintf(os.Stderr, "\r\x1b[2K%s", msg)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t := path.Run(ctx, host, path.Options{Rounds: *rounds, MaxHops: *maxHops, Progress: progress})
	progress("")
	if *c.json {
		return writeJSON(t, t.Conclusion)
	}
	s := newStyle(!*c.noColor)
	w := os.Stdout
	fmt.Fprintln(w)
	title := "Path to " + t.Target
	if t.Addr != "" && t.Addr != t.Target {
		title += " (" + t.Addr + ")"
	}
	writeConclusion(w, s, title, t.Conclusion)
	if len(t.Hops) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", s.bold(fmt.Sprintf("  %-3s %-46s %-24s %6s %8s %8s %8s", "Hop", "Address", "Where", "Loss", "Median", "Best", "Worst")))
		for i, h := range t.Hops {
			if h.Received == 0 {
				fmt.Fprintf(w, "  %-3d %s\n", h.TTL, s.dim("*  no reply (many routers don't answer these probes)"))
				continue
			}
			addr := h.Addr
			if h.Name != "" {
				addr = h.Name + " (" + h.Addr + ")"
			}
			if len(addr) > 46 {
				addr = addr[:45] + "…"
			}
			best, worst := probe.Percentile(h.RTTsMs, 0), probe.Percentile(h.RTTsMs, 100)
			loss := fmt.Sprintf("%5.0f%%", h.LossPct())
			if h.LossPct() >= 10 {
				loss = s.yellow(loss)
			}
			fmt.Fprintf(w, "  %-3d %-46s %-24s %6s %6.1fms %6.1fms %6.1fms\n", h.TTL, addr, path.Where(h, i), loss, h.P50(), best, worst)
		}
	}
	fmt.Fprintln(w)
	return exitFor(t.Conclusion.Status)
}

func writeConclusion(w io.Writer, s style, title string, c target.Conclusion) {
	badge := map[string]string{"ok": s.green(s.bold("✓ OK")), "warn": s.yellow(s.bold("! WARNING")), "fail": s.red(s.bold("✗ PROBLEM"))}[c.Status]
	fmt.Fprintln(w, s.dim(title))
	fmt.Fprintf(w, "%s\n%s\n", badge, s.bold(c.Headline))
	if c.Owner != "" {
		fmt.Fprintln(w, s.dim("Who can fix it: "+c.Owner))
	}
	if len(c.Evidence) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, s.bold("Why:"))
		for _, e := range c.Evidence {
			fmt.Fprintf(w, "  • %s\n", e)
		}
	}
	if len(c.NextSteps) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, s.bold("What to do:"))
		for i, n := range c.NextSteps {
			fmt.Fprintf(w, "  %d. %s\n", i+1, n)
		}
	}
}

func writeJSON(v any, c target.Conclusion) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}
	return exitFor(c.Status)
}

func exitFor(status string) int {
	switch status {
	case "fail":
		return exitFail
	case "warn":
		return exitDegraded
	}
	return exitOK
}

// style: minimal ANSI colors, off when not a terminal or NO_COLOR is set.
type style struct{ on bool }

func newStyle(want bool) style {
	return style{on: want && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)}
}

func (s style) c(code, t string) string {
	if !s.on {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}
func (s style) bold(t string) string   { return s.c("1", t) }
func (s style) dim(t string) string    { return s.c("2", t) }
func (s style) red(t string) string    { return s.c("31", t) }
func (s style) green(t string) string  { return s.c("32", t) }
func (s style) yellow(t string) string { return s.c("33", t) }

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
