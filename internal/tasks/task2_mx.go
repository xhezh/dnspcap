package tasks

import (
	"fmt"
	"io"
	"net"
	"sort"

	"dnspcap/internal/config"
	"dnspcap/internal/dnsmsg"
)

// Task2MX implements sub-task 2: given a domain D, perform a two-step lookup
// (MX record → A record for each MX exchange) using the ISP resolver and
// print the results as "D -> IP" lines only.
type Task2MX struct {
	Cfg *config.Config
	Out io.Writer
}

type mxHost struct {
	preference uint16
	exchange   string
}

func (t *Task2MX) Run(domain string) error {
	if domain == "" {
		return fmt.Errorf("usage: mx <domain>")
	}

	// Step 1: MX query (RD=1 so the ISP resolver answers recursively).
	mxMsg, _, err := sendDNSQuery(t.Cfg, t.Cfg.ISPDNS, randUint16(), domain, dnsmsg.TypeMX, true, defaultTimeout)
	if err != nil {
		return fmt.Errorf("MX query for %s: %w", domain, err)
	}
	if rc := mxMsg.Header.RCode(); rc != 0 {
		return fmt.Errorf("MX query for %s returned RCODE=%s", domain, dnsmsg.RCodeNames[rc])
	}
	hosts, preIPs := collectMX(mxMsg)
	if len(hosts) == 0 {
		fmt.Fprintf(t.Out, "no MX records for %s\n", domain)
		return nil
	}

	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].preference < hosts[j].preference })

	// Step 2: resolve A records for each MX exchange (use cached glue if present,
	// otherwise issue a follow-up A query).
	for _, mx := range hosts {
		if ips := preIPs[mx.exchange]; len(ips) > 0 {
			t.printResults(domain, mx.exchange, ips)
			continue
		}
		aMsg, _, err := sendDNSQuery(t.Cfg, t.Cfg.ISPDNS, randUint16(), mx.exchange, dnsmsg.TypeA, true, defaultTimeout)
		if err != nil {
			return fmt.Errorf("A query for %s: %w", mx.exchange, err)
		}
		if rc := aMsg.Header.RCode(); rc != 0 {
			fmt.Fprintf(t.Out, "# A query for %s returned RCODE=%s\n", mx.exchange, dnsmsg.RCodeNames[rc])
			continue
		}
		var ips []net.IP
		for _, rr := range aMsg.Answers {
			if rr.Type == dnsmsg.TypeA {
				ips = append(ips, rr.Data.A)
			}
		}
		if len(ips) == 0 {
			fmt.Fprintf(t.Out, "# no A records for %s\n", mx.exchange)
			continue
		}
		t.printResults(domain, mx.exchange, ips)
	}
	return nil
}

func collectMX(m *dnsmsg.Message) ([]mxHost, map[string][]net.IP) {
	var hosts []mxHost
	preIPs := make(map[string][]net.IP)
	for _, rr := range m.Answers {
		if rr.Type == dnsmsg.TypeMX {
			hosts = append(hosts, mxHost{preference: rr.Data.MXPref, exchange: rr.Data.Name})
		}
	}
	// Some resolvers include A records for MX exchanges in the additional section.
	for _, rr := range m.Additional {
		if rr.Type == dnsmsg.TypeA {
			preIPs[rr.Name] = append(preIPs[rr.Name], rr.Data.A)
		}
	}
	return hosts, preIPs
}

func (t *Task2MX) printResults(domain, exchange string, ips []net.IP) {
	// Spec: print the DNS name of the mail service (if any) and one "D -> IP" line
	// per IP; emit no extra information.
	fmt.Fprintf(t.Out, "%s\n", exchange)
	for _, ip := range ips {
		fmt.Fprintf(t.Out, "%s -> %s\n", domain, ip)
	}
}
