# netdiag

Network triage for vague complaints like "the internet is slow" or "the network is broken."
Run it on the affected machine while the problem is happening. It reports **where the fault is,
who can fix it, how confident it is, and what to do next**.

```
$ netdiag
! WORKING, WITH ISSUES
Connected, but lag spikes on your local network
Who can fix it: Wi-Fi / local network   Confidence: high

Why:
  • Router replies are usually 6 ms but jumped above 36 ms in 23% of samples (max 156 ms)
  • 23 of 25 internet lag spikes happened at the same moments, so the delay is added before traffic leaves your network
  • The spikes repeat about every 0.9 seconds: something running on a timer, not random interference
...
```

## Install

With Go 1.23 or newer:

```bash
go install github.com/strlenstrlen/netdiag/cmd/netdiag@latest
```

On macOS this needs the Xcode command-line tools (`xcode-select --install`), because Wi-Fi stats come from
CoreWLAN through cgo. Or build from a clone with `make build` (binary in `bin/`), or `make dist` for macOS,
Linux and Windows binaries.

## Usage

```bash
make build            # → bin/netdiag
./bin/netdiag            # asks what's wrong (optional), then runs all stages in ~40 s
./bin/netdiag --quick    # connectivity only, ~1–5 s
./bin/netdiag --no-speed # skip the speed test (metered or hotspot connections)
./bin/netdiag --plan-down 1000 --plan-up 40   # compare speeds with what you pay for
./bin/netdiag --from netdiag-report-2026-11-25-1159.html -v   # re-open a report someone sent you
./bin/netdiag -v      # every measurement
./bin/netdiag --json  # full machine-readable report
./bin/netdiag --save report.json --symptom slow --no-prompt
```

No sudo is needed. Exit codes: `0` all clear, `1` working with issues, `2` problem found, `3` netdiag error.

`--config file.json` overrides any of the test endpoints in [internal/config/config.go](internal/config/config.go)
(fields not in the file keep their defaults).

## Expert commands

Each one answers a narrower question than the full triage:

| Command | Answers | Example conclusion |
|---|---|---|
| `netdiag site <url>` | Is this one site down, or is it my network? | "expired.badssl.com's security certificate has expired · who can fix it: the website's operators" |
| `netdiag dns <name>` | What does each DNS server say about this name? | "Your DNS is blocking example.com" (sinkhole or filter), "doesn't exist", NXDOMAIN hijacking |
| `netdiag path <host>` | Where along the route does loss or delay start? | "Packet loss starts at hop 2 (your provider)". Loss is only blamed on a hop when it persists to the destination, so routers that ignore probes aren't flagged |
| `netdiag watch [--for 2h]` | When does it drop, and where? | "The connection dropped 3 times in 2 h, on your Wi-Fi or local network", with a timeline report |
| `netdiag view <file>` | What did this saved report say? | Re-opens triage and watch reports (`.html` or `.json`) |

`site` checks DNS (system vs. public), TCP to each address, TLS (issuer, expiry, name), the HTTP status and
timing, all compared with a reference site. `watch` pings the router and two internet hosts every second, checks
DNS every 10 s and the network settings every 5 s, and attributes each outage: router unreachable too (local),
Wi-Fi disconnected or changed (Wi-Fi), or router fine (beyond the router). Ctrl-C stops it and saves the report.

All commands take `--json`; exit codes are the same as the triage.

## Reports

Every interactive run saves a self-contained HTML report to the Desktop (or the current folder) and tells
the user to send it to whoever is helping them. The report has the verdict, every check, latency charts on a
shared time axis, and the speed results. It loads nothing from the internet, works in light and dark mode,
and reads well on a phone.

The full measurements are embedded in the file as JSON, so `netdiag --from report.html -v` shows a user's
report in your terminal with every detail (`--json` prints the data). `--from` shows the report as the user
saw it, without running any tests.

| Flag | Effect |
|---|---|
| `--report FILE` | write the HTML report to FILE (works in scripts too) |
| `--no-report` | don't save one |
| `--open` | open it in the browser afterwards |
| `--redact` | leave out the computer name and hardware (MAC) addresses |
| `--save FILE` | also write the raw JSON |

## How it works

| Stage | Package | What it does |
|---|---|---|
| 0. Snapshot | `internal/snapshot` | Interfaces, routes, DNS servers, proxy, Wi-Fi signal, VPN. No traffic sent. |
| 1. Connectivity ladder | `internal/ladder`, `internal/probe` | Router (ICMP + TCP), internet by IP (ICMP + TCP 443), DNS three ways (OS resolver, each configured server, public resolvers), captive-portal check, HTTPS (including one by IP literal), IPv6 if configured, clock skew. All probes run concurrently. |
| 2. Responsiveness | `internal/quality` | Runs when the internet is reachable (skip with `--quick`). 20 s latency series to the router and two internet hosts, sampled together; first-lookup DNS timing (random uncached names) through your DNS vs. public DNS; per-phase page-start timing (DNS, connect, TLS, server); IPv4 vs. IPv6 connect time when IPv6 is present. |
| 3. Speed | `internal/speed` | Download and upload from two providers: Cloudflare (4 HTTPS streams) and M-Lab NDT7 (1 WebSocket stream, via a minimal built-in client). Each transfer runs up to 8 s or 250 MB, so a fast line uses about 1 GB per run and the report shows the data used. Latency to the router and 1.1.1.1 is sampled during every transfer to measure bufferbloat. |
| Verdict | `internal/verdict` | First failing rung becomes the verdict. Otherwise the highest-impact warning becomes the headline; everything else is listed as secondary findings. |
| Report | `internal/report` | Console summary, JSON, and the self-contained HTML report (`report.html.tmpl`). |

Every check runs against a baseline: router vs. internet, your DNS vs. public DNS, by-name vs. by-IP,
so a failure points at one segment, not just "something's wrong."

The latency series are aligned sample by sample, which separates three cases that look identical on a plain ping:
- router and internet spike **at the same moments** → the delay is on the local network (usually Wi-Fi)
- only the internet spikes → the delay is beyond the router (modem or ISP)
- only the router spikes → the router answers ping at low priority; traffic through it is fine

Spikes that recur on a timer are flagged too. On a Mac with AirDrop/Handoff active (`awdl0` up), that pattern
leads to a suggestion to turn them off and re-test, since they move the Wi-Fi radio off-channel on a schedule.

### What it diagnoses today

Wi-Fi off / not joined · DHCP failure (169.254 address) · no default route · captive portal ·
router unreachable · ISP outage · configured DNS down while public DNS works · DNS blocked ·
TLS interception (names the issuer) · clock skew breaking TLS · HTTPS blocked · weak Wi-Fi ·
packet loss local vs. beyond the router · one dead DNS server · slow DNS · broken IPv6 ·
ICMP blocked · VPN / proxy present (detect only).

Responsiveness: lag spikes local vs. upstream (and periodic) · packet loss local vs. upstream · router that
only deprioritizes ping · jitter · high base latency · local network slow · slow or unanswered first-time DNS
lookups vs. public DNS · slow page starts with the dominant phase · IPv6 slower than IPv4.

Speed: slow download/upload (absolute, or under half of `--plan-down`/`--plan-up`) · Wi-Fi link rate as the
likely bottleneck · bufferbloat graded A+–F, and whether the queue is on the Wi-Fi (router latency rises too) or
at the modem (only internet latency rises, so the fix is Smart Queue Management) · providers disagreeing ·
a provider rate-limiting the test.

## Platform support

| | macOS | Linux | Windows |
|---|---|---|---|
| Interfaces, addresses | ✓ | ✓ | ✓ |
| Routes, DNS servers | `route`, `scutil` | `/proc`, `resolv.conf`, `resolvectl` | PowerShell `Get-NetRoute`, `Get-DnsClientServerAddress` (language-independent JSON) |
| Wi-Fi signal | CoreWLAN (cgo) | `/proc/net/wireless`, `iw` | `netsh wlan` (English Windows only; signal % converted to dBm) |
| Proxy | `scutil --proxy` + env | env | registry (Internet Settings) + env |
| ICMP ping | unprivileged socket | unprivileged socket (if `ping_group_range` allows) | `IcmpSendEcho` (IPv4) |
| `path` | ✓ (unprivileged ICMP) | not yet (suggests `tracepath`) | not yet (suggests `tracert`) |

Measurements are done in Go code, not by parsing `ping`/`dig` output, so they behave the same across OSes and locales.
Only configuration collection is OS-specific (`platform_*.go`).

macOS Wi-Fi stats use CoreWLAN through cgo, so macOS builds must be made on a Mac (`make dist`).
Signal, noise, channel and rate don't need Location Services; the network name (SSID) would, so it isn't collected.

## Public endpoints

Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and the Apple, Google and Microsoft
connectivity-check URLs. Each check uses at least two providers so one provider's outage can't cause a false verdict.
Speed tests use Cloudflare's speed endpoints and M-Lab's NDT7 servers (found through M-Lab's Locate API).
Cloudflare rate-limits a connection after many back-to-back tests (HTTP 429); the report says so, and the other provider still answers.

## Roadmap

1. ~~Snapshot, connectivity ladder, verdict engine~~
2. ~~Responsiveness stage: latency series with spike correlation, DNS timing, page-start timing, IPv4 vs. IPv6~~
3. ~~Throughput and latency under load (Cloudflare + M-Lab NDT7, bufferbloat localization)~~
4. ~~Self-contained HTML report for end users to send, re-openable with `--from`~~
5. ~~Expert subcommands (`site`, `dns`, `path`, `view`), watch mode, Windows adapters~~

Not yet verified on real hardware: everything on Linux and Windows (built and unit-tested only).
Next candidates: `path` on Linux (IP_RECVERR) and Windows, IPv6 ping on Windows, code signing and notarization for distribution.

## License

MIT. See [LICENSE](LICENSE).
