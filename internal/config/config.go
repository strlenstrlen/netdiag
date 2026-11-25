// Package config holds the public endpoints netdiag tests against.
// Every check uses at least two independent providers so a single
// provider outage can't produce a false verdict.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CaptiveCheck is a plain-HTTP URL with a known, fixed response. A captive
// portal intercepts the request and returns something else.
type CaptiveCheck struct {
	URL          string `json:"url"`
	ExpectStatus int    `json:"expect_status"`
	ExpectBody   string `json:"expect_body,omitempty"`
}

type Config struct {
	PingTargets   []string       `json:"ping_targets"`
	PingTargets6  []string       `json:"ping_targets_v6"`
	TCPTargets    []string       `json:"tcp_targets"`
	TCPTargets6   []string       `json:"tcp_targets_v6"`
	PublicDNS     []string       `json:"public_dns"`
	DNSNames      []string       `json:"dns_names"`
	CaptiveChecks []CaptiveCheck `json:"captive_checks"`
	HTTPSChecks   []string       `json:"https_checks"`

	GatewayPingCount  int `json:"gateway_ping_count"`
	InternetPingCount int `json:"internet_ping_count"`
	PingIntervalMs    int `json:"ping_interval_ms"`
	ProbeTimeoutMs    int `json:"probe_timeout_ms"`

	// Stage 2: responsiveness.
	QualitySeconds    int      `json:"quality_seconds"`     // length of the latency series
	QualityIntervalMs int      `json:"quality_interval_ms"` // spacing between samples
	QualityTargets    []string `json:"quality_targets"`     // internet hosts sampled alongside the router
	ColdDNSDomains    []string `json:"cold_dns_domains"`    // random names under these force uncached lookups
	ColdDNSQueries    int      `json:"cold_dns_queries"`    // per resolver
	TimingURLs        []string `json:"timing_urls"`         // pages for HTTP phase timing
	TimingRounds      int      `json:"timing_rounds"`

	// Stage 3: speed.
	SpeedSeconds      int    `json:"speed_seconds"`       // per transfer (provider × direction)
	SpeedMaxMB        int    `json:"speed_max_mb"`        // per transfer; caps data use on fast links
	CloudflareStreams int    `json:"cloudflare_streams"`  // parallel connections
	CloudflareDownURL string `json:"cloudflare_down_url"` // %d = bytes per request
	CloudflareUpURL   string `json:"cloudflare_up_url"`
	NDT7LocateURL     string `json:"ndt7_locate_url"`
}

func Default() Config {
	return Config{
		PingTargets:  []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		PingTargets6: []string{"2606:4700:4700::1111", "2001:4860:4860::8888"},
		TCPTargets:   []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"},
		TCPTargets6:  []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"},
		PublicDNS:    []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		DNSNames:     []string{"www.google.com", "www.apple.com", "www.microsoft.com"},
		CaptiveChecks: []CaptiveCheck{
			{URL: "http://captive.apple.com/hotspot-detect.html", ExpectStatus: 200, ExpectBody: "Success"},
			{URL: "http://connectivitycheck.gstatic.com/generate_204", ExpectStatus: 204},
			{URL: "http://www.msftconnecttest.com/connecttest.txt", ExpectStatus: 200, ExpectBody: "Microsoft Connect Test"},
		},
		HTTPSChecks: []string{
			"https://www.google.com/generate_204",
			"https://www.apple.com/library/test/success.html",
			// IP literal: works even when DNS is broken, which lets the
			// verdict engine tell "DNS is down" from "HTTPS is blocked".
			"https://1.1.1.1/cdn-cgi/trace",
		},
		GatewayPingCount:  5,
		InternetPingCount: 4,
		PingIntervalMs:    200,
		ProbeTimeoutMs:    2000,

		QualitySeconds:    20,
		QualityIntervalMs: 200,
		QualityTargets:    []string{"1.1.1.1", "8.8.8.8"},
		// Zones without DNSSEC: resolvers can't answer random names from
		// cached NSEC records, so each query really goes to the authority.
		ColdDNSDomains: []string{"google.com", "microsoft.com", "amazon.com"},
		ColdDNSQueries: 6,
		TimingURLs: []string{
			"https://www.google.com/generate_204",
			"https://www.apple.com/library/test/success.html",
			"https://www.cloudflare.com/cdn-cgi/trace",
			"https://www.wikipedia.org/",
		},
		TimingRounds: 2,

		SpeedSeconds:      8,
		SpeedMaxMB:        250,
		CloudflareStreams: 4,
		CloudflareDownURL: "https://speed.cloudflare.com/__down?bytes=%d",
		CloudflareUpURL:   "https://speed.cloudflare.com/__up",
		NDT7LocateURL:     "https://locate.measurementlab.net/v2/nearest/ndt/ndt7?client_name=netdiag&client_version=0.1.0",
	}
}

func (c Config) QualityInterval() time.Duration {
	return time.Duration(c.QualityIntervalMs) * time.Millisecond
}

// QualitySamples is the number of samples in each latency series.
func (c Config) QualitySamples() int {
	if c.QualityIntervalMs <= 0 {
		return 0
	}
	return c.QualitySeconds * 1000 / c.QualityIntervalMs
}

// Load overlays a JSON file on the defaults. Fields present in the file
// replace the defaults; missing fields keep them.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) PingInterval() time.Duration {
	return time.Duration(c.PingIntervalMs) * time.Millisecond
}

func (c Config) ProbeTimeout() time.Duration {
	return time.Duration(c.ProbeTimeoutMs) * time.Millisecond
}
