// netdiag: network triage for "the internet is slow" / "the network is broken".
//
// With no subcommand it runs the full triage and prints a plain-English
// verdict. Subcommands (site, dns, path, watch, view) target one question.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/report"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/speed"
	"github.com/strlenstrlen/netdiag/internal/verdict"
	"github.com/strlenstrlen/netdiag/internal/version"
)

// Exit codes let scripts branch on the outcome.
const (
	exitOK       = 0
	exitDegraded = 1
	exitFail     = 2
	exitError    = 3
)

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

var commands = []struct{ name, usage, help string }{
	{"site", "site <url or host>", "is this one website down, or is it my network?"},
	{"dns", "dns <name>", "compare DNS servers' answers; detect blocking and hijacking"},
	{"path", "path <host>", "hop-by-hop latency and loss to a host (macOS)"},
	{"watch", "watch [--for 30m]", "monitor continuously and record drops, with causes"},
	{"view", "view <report.html|.json>", "show a saved report (same as --from)"},
}

func dispatch(args []string) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		rest := args[1:]
		switch args[0] {
		case "site":
			return cmdSite(rest)
		case "dns":
			return cmdDNS(rest)
		case "path":
			return cmdPath(rest)
		case "watch":
			return cmdWatch(rest)
		case "view":
			if len(rest) == 0 {
				fmt.Fprintln(os.Stderr, "usage: netdiag view <report.html|report.json> [-v] [--json]")
				return exitError
			}
			return runTriage(append([]string{"--from", rest[0]}, rest[1:]...))
		case "help":
			usage(nil)
			return exitOK
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
			usage(nil)
			return exitError
		}
	}
	return runTriage(args)
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "netdiag %s: find out why the network isn't working\n\n", version.Version)
	fmt.Fprintf(os.Stderr, "Usage:\n  netdiag %-26s %s\n", "[flags]", "full triage: connectivity, responsiveness, speed")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  netdiag %-26s %s\n", c.usage, c.help)
	}
	if fs != nil {
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		fs.PrintDefaults()
	} else {
		fmt.Fprintf(os.Stderr, "\nRun netdiag -h or netdiag <command> -h for flags.\n")
	}
	fmt.Fprintf(os.Stderr, "\nExit codes: 0 all clear, 1 working with issues, 2 problem found, 3 netdiag error\n")
}

func runTriage(args []string) int {
	flag := flag.NewFlagSet("netdiag", flag.ContinueOnError)
	var (
		jsonOut    = flag.Bool("json", false, "print the full JSON report instead of the summary")
		jsonFile   = flag.String("save", "", "also write the JSON report to this file")
		reportPath = flag.String("report", "", "write the HTML report to this file (interactive runs save one to the Desktop by default)")
		noReport   = flag.Bool("no-report", false, "don't save an HTML report")
		openReport = flag.Bool("open", false, "open the HTML report in the browser when done")
		redact     = flag.Bool("redact", false, "leave the computer name and hardware addresses out of saved reports")
		from       = flag.String("from", "", "show a saved report (.json or .html) instead of running tests")
		verbose    = flag.Bool("v", false, "verbose: show every measurement")
		symptom    = flag.String("symptom", "", "what's wrong: "+symptomIDs())
		noPrompt   = flag.Bool("no-prompt", false, "don't ask what's wrong")
		quick      = flag.Bool("quick", false, "connectivity only: skip responsiveness and speed tests (~1–5 s total)")
		noSpeed    = flag.Bool("no-speed", false, "skip the speed test (uses up to ~1 GB on fast links; use on metered connections)")
		planDown   = flag.Float64("plan-down", 0, "your plan's download speed in Mbps, to compare against")
		planUp     = flag.Float64("plan-up", 0, "your plan's upload speed in Mbps, to compare against")
		noColor    = flag.Bool("no-color", false, "disable colored output")
		configPath = flag.String("config", "", "JSON file overriding the default test endpoints")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() { usage(flag) }
	if err := flag.Parse(args); err != nil {
		if err == errHelp {
			return exitOK
		}
		return exitError
	}

	if *showVer {
		fmt.Println("netdiag", version.Version)
		return exitOK
	}
	if !verdict.ValidSymptom(*symptom) {
		fmt.Fprintf(os.Stderr, "unknown symptom %q; choose one of: %s\n", *symptom, symptomIDs())
		return exitError
	}
	interactive := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)

	var doc report.Document
	if *from != "" {
		loaded, err := report.ReadAny(*from)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		if wd, ok := loaded.(report.WatchDocument); ok {
			return showWatch(wd, *jsonOut, *reportPath, *redact, color)
		}
		doc = loaded.(report.Document)
	} else {
		cfg, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		if *symptom == "" && !*noPrompt && !*jsonOut && interactive {
			*symptom = askSymptom()
		}
		status := func(msg string) {
			if !*jsonOut && interactive {
				fmt.Fprintf(os.Stderr, "\r\x1b[2K%s", msg)
			}
		}
		doc = runTests(cfg, *symptom, *quick, *noSpeed, *planDown, *planUp, status)
		status("")
	}
	if *redact {
		report.Redact(&doc)
	}

	if *jsonFile != "" {
		if err := writeFile(*jsonFile, func(f *os.File) error { return report.WriteJSON(f, doc) }); err != nil {
			fmt.Fprintln(os.Stderr, "saving JSON report:", err)
			return exitError
		}
	}

	// HTML report: when asked for, and by default on interactive test runs
	// so an end user always has a file to send.
	htmlPath := *reportPath
	if htmlPath == "" && !*noReport && interactive && *from == "" && !*jsonOut {
		htmlPath = defaultReportPath(doc.GeneratedAt)
	}
	if htmlPath != "" {
		if err := writeFile(htmlPath, func(f *os.File) error { return report.WriteHTML(f, doc, filepath.Base(htmlPath)) }); err != nil {
			fmt.Fprintln(os.Stderr, "saving HTML report:", err)
			return exitError
		}
	}

	if *jsonOut {
		if err := report.WriteJSON(os.Stdout, doc); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
	} else {
		report.WriteConsole(os.Stdout, doc, color, *verbose)
		if *jsonFile != "" {
			fmt.Printf("JSON report saved to %s\n", *jsonFile)
		}
		if htmlPath != "" {
			fmt.Printf("Report saved to %s\n", htmlPath)
			if *reportPath == "" {
				fmt.Println("If someone is helping you with this problem, send them that file.")
			}
			fmt.Println()
		}
	}
	if *openReport && htmlPath != "" {
		if err := openInBrowser(htmlPath); err != nil {
			fmt.Fprintln(os.Stderr, "opening report:", err)
		}
	}

	switch doc.Verdict.Status {
	case verdict.StatusFail:
		return exitFail
	case verdict.StatusDegraded:
		return exitDegraded
	}
	return exitOK
}

func runTests(cfg config.Config, symptom string, quick, noSpeed bool, planDown, planUp float64, status func(string)) report.Document {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	status("Reading network settings…")
	snap := snapshot.Collect(ctx)
	status("Testing connectivity…")
	res := ladder.Run(ctx, cfg, snap)
	res.Symptom = symptom

	switch ok, why := verdict.ShouldRunQuality(res); {
	case quick:
		res.QualitySkipped = "--quick"
	case !ok:
		res.QualitySkipped = why
	default:
		q := quality.Run(ctx, cfg, res.QualityPlan(cfg), quality.Options{Progress: status})
		res.Quality = &q
	}

	switch {
	case quick:
		res.SpeedSkipped = "--quick"
	case noSpeed:
		res.SpeedSkipped = "--no-speed"
	case res.Quality == nil:
		res.SpeedSkipped = res.QualitySkipped
	default:
		plan := speed.PlanFrom(res.Quality)
		plan.PlanDownMbps, plan.PlanUpMbps = planDown, planUp
		s := speed.Run(ctx, cfg, plan, speed.Options{Progress: status})
		res.Speed = &s
	}
	return report.NewDocument(res, verdict.Evaluate(res))
}

// defaultReportPath puts the report on the Desktop, where a non-technical
// user will find it, falling back to the current directory.
func defaultReportPath(t time.Time) string {
	name := "netdiag-report-" + t.Format("2006-01-02-1504") + ".html"
	if home, err := os.UserHomeDir(); err == nil {
		desk := filepath.Join(home, "Desktop")
		if fi, err := os.Stat(desk); err == nil && fi.IsDir() {
			return filepath.Join(desk, name)
		}
	}
	return name
}

func writeFile(path string, write func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	werr := write(f)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func openInBrowser(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}

func askSymptom() string {
	fmt.Println("What's going on? (press Enter to skip)")
	for i, s := range verdict.Symptoms() {
		fmt.Printf("  %d. %s\n", i+1, s.Label)
	}
	fmt.Print("> ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(verdict.Symptoms()) {
		return ""
	}
	return verdict.Symptoms()[n-1].ID
}

func symptomIDs() string {
	var ids []string
	for _, s := range verdict.Symptoms() {
		ids = append(ids, s.ID)
	}
	return strings.Join(ids, ", ")
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
