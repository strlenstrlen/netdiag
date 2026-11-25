package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/strlenstrlen/netdiag/internal/report"
	"github.com/strlenstrlen/netdiag/internal/watch"
)

func cmdWatch(args []string) int {
	fs, c := newCommand("watch", "watch [flags]")
	dur := fs.Duration("for", 0, "stop after this long, e.g. 30m or 2h (default: until Ctrl-C)")
	every := fs.Duration("every", time.Second, "time between probe rounds")
	reportPath := fs.String("report", "", "write the HTML report to this file (interactive runs save one to the Desktop by default)")
	noReport := fs.Bool("no-report", false, "don't save an HTML report")
	saveJSON := fs.String("save", "", "also write the JSON data to this file")
	redact := fs.Bool("redact", false, "leave the computer name and hardware addresses out of saved reports")
	openReport := fs.Bool("open", false, "open the HTML report in the browser when done")
	if err := fs.Parse(args); err != nil {
		if err == errHelp {
			return exitOK
		}
		return exitError
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitError
	}
	if *every < 200*time.Millisecond {
		fmt.Fprintln(os.Stderr, "--every must be at least 200ms")
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := newStyle(!*c.noColor)
	live := isTerminal(os.Stdout) && !*c.json
	var out sync.Mutex
	line := func(format string, a ...any) {
		if *c.json {
			return
		}
		out.Lock()
		defer out.Unlock()
		if live {
			fmt.Fprint(os.Stdout, "\r\x1b[2K")
		}
		fmt.Fprintf(os.Stdout, format+"\n", a...)
	}
	ms := func(v *float64) string {
		if v == nil {
			return s.red("no reply")
		}
		return fmt.Sprintf("%.0f ms", *v)
	}
	started := time.Now()

	if !*c.json {
		until := "Press Ctrl-C to stop."
		if *dur > 0 {
			until = fmt.Sprintf("Running for %s (Ctrl-C stops early).", *dur)
		}
		fmt.Printf("\n%s\n%s\n\n", s.bold("Watching the connection"), s.dim("Pinging the router and 1.1.1.1 / 8.8.8.8 every "+every.String()+". "+until))
	}
	res := watch.Run(ctx, watch.Options{
		Progress: func(msg string) {
			if live {
				out.Lock()
				fmt.Fprintf(os.Stdout, "\r\x1b[2K%s", s.dim(msg))
				out.Unlock()
			}
		},
		Interval: *every,
		Duration: *dur,
		OnEvent: func(e watch.Event, ended bool) {
			at := e.Start
			mark := s.yellow("!")
			title := e.Title
			switch {
			case ended:
				at, mark = e.End, s.green("✓")
				title = "Back to normal: " + strings.ToLower(e.Title[:1]) + e.Title[1:]
				if e.Detail != "" {
					title += s.dim(" — " + e.Detail)
				}
			case e.Kind == "outage":
				mark = s.red("✗")
			}
			line("%s  %s %s", at.Format("15:04:05"), mark, title)
		},
		OnTick: func(t watch.Tick, sum watch.Summary) {
			if !live {
				return
			}
			out.Lock()
			defer out.Unlock()
			el := time.Since(started).Round(time.Second)
			fmt.Fprintf(os.Stdout, "\r\x1b[2K%s  router %s · internet %s  %s",
				t.At.Format("15:04:05"), ms(t.Router), ms(t.Inet),
				s.dim(fmt.Sprintf("up %.1f%% · %d outages · %d lag · %s elapsed", sum.UptimePct, sum.Outages, sum.LagEpisodes, el)))
		},
	})
	if live {
		fmt.Print("\r\x1b[2K")
	}
	doc := report.NewWatchDocument(res)
	if *redact {
		report.RedactWatch(&doc)
	}
	if len(res.Ticks) == 0 {
		fmt.Fprintln(os.Stderr, "Stopped before any measurements were taken.")
		return exitError
	}
	if *saveJSON != "" {
		if err := writeFile(*saveJSON, func(f *os.File) error {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(doc)
		}); err != nil {
			fmt.Fprintln(os.Stderr, "saving JSON:", err)
			return exitError
		}
	}
	htmlPath := *reportPath
	if htmlPath == "" && !*noReport && isTerminal(os.Stdin) && isTerminal(os.Stdout) && !*c.json {
		htmlPath = strings.Replace(defaultReportPath(doc.GeneratedAt), "netdiag-report-", "netdiag-watch-", 1)
	}
	code := showWatch(doc, *c.json, htmlPath, false, s.on)
	if htmlPath != "" && !*c.json && *reportPath == "" {
		fmt.Println("If someone is helping you with this problem, send them that file.")
		fmt.Println()
	}
	if *openReport && htmlPath != "" {
		_ = openInBrowser(htmlPath)
	}
	return code
}

// showWatch prints a watch document and optionally writes its HTML report.
func showWatch(d report.WatchDocument, jsonOut bool, htmlPath string, redact, color bool) int {
	if redact {
		report.RedactWatch(&d)
	}
	if htmlPath != "" {
		if err := writeFile(htmlPath, func(f *os.File) error { return report.WriteWatchHTML(f, d, filepath.Base(htmlPath)) }); err != nil {
			fmt.Fprintln(os.Stderr, "saving HTML report:", err)
			return exitError
		}
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return exitError
		}
	} else {
		report.WriteWatchConsole(os.Stdout, d, color)
		if htmlPath != "" {
			fmt.Printf("Report saved to %s\n", htmlPath)
		}
	}
	return exitFor(d.Results.Summary.Conclusion.Status)
}
