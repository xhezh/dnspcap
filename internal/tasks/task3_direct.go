package tasks

import (
	"fmt"
	"io"
	"net"
	"strings"

	"dnspcap/internal/config"
	"dnspcap/internal/dnsmsg"
)

// Task3Direct implements sub-task 3: send an A query for a user-given domain
// directly to either the selected root DNS server or the ISP resolver, and
// fully dump the response so the user can compare answers (referral vs.
// recursive answer) and attach screenshots to the report.
type Task3Direct struct {
	Cfg *config.Config
	Out io.Writer
}

type Task3Target int

const (
	TargetRoot Task3Target = iota
	TargetISP
)

func (t *Task3Direct) Run(target Task3Target, domain string) error {
	if domain == "" {
		return fmt.Errorf("usage: root|isp <domain>")
	}
	var dst net.IP
	var label string
	rd := false
	switch target {
	case TargetRoot:
		dst = t.Cfg.RootDNS
		label = fmt.Sprintf("root DNS server %s (%s)", t.Cfg.RootDNS, t.Cfg.RootDNSLabel)
		// Root servers never provide recursion; keep RD=0 for honesty.
	case TargetISP:
		dst = t.Cfg.ISPDNS
		label = fmt.Sprintf("ISP resolver %s", t.Cfg.ISPDNS)
		rd = true
	default:
		return fmt.Errorf("unknown target")
	}

	fmt.Fprintf(t.Out, "\n[task3] A query for %s -> %s  (RD=%v)\n", domain, label, rd)
	msg, raw, err := sendDNSQuery(t.Cfg, dst, randUint16(), domain, dnsmsg.TypeA, rd, defaultTimeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(t.Out, "raw reply: %d bytes\n", len(raw))
	fmt.Fprintf(t.Out, "header: %s\n", dnsmsg.FormatHeader(msg.Header))
	if len(msg.Questions) > 0 {
		fmt.Fprintln(t.Out, "questions:")
		for _, q := range msg.Questions {
			fmt.Fprintf(t.Out, "  %s %s %s\n", q.Name, dnsmsg.ClassName(q.Class), dnsmsg.TypeName(q.Type))
		}
	}
	printSection(t.Out, "answer", msg.Answers)
	printSection(t.Out, "authority", msg.Authority)
	printSection(t.Out, "additional", msg.Additional)

	t.summarize(target, msg)
	return nil
}

// summarize prints a short interpretation — this is the "what the server is
// telling us" line the report has to answer with.
func (t *Task3Direct) summarize(target Task3Target, m *dnsmsg.Message) {
	switch target {
	case TargetRoot:
		// A root server returns a referral: empty ANSWER, NS records for the TLD
		// in AUTHORITY, and A/AAAA glue for those NS in ADDITIONAL. No recursion.
		var ns []string
		for _, rr := range m.Authority {
			if rr.Type == dnsmsg.TypeNS {
				ns = append(ns, rr.Data.Name)
			}
		}
		var glue []string
		for _, rr := range m.Additional {
			switch rr.Type {
			case dnsmsg.TypeA:
				glue = append(glue, fmt.Sprintf("%s=%s", rr.Name, rr.Data.A))
			case dnsmsg.TypeAAAA:
				glue = append(glue, fmt.Sprintf("%s=%s", rr.Name, rr.Data.AAAA))
			}
		}
		fmt.Fprintf(t.Out, "=> referral (answer=%d, authority NS=%d, additional glue=%d). ra=%v\n",
			len(m.Answers), len(ns), len(glue), m.Header.RA())
		if len(ns) > 0 {
			fmt.Fprintf(t.Out, "   next hop name servers: %s\n", strings.Join(ns, ", "))
		}
	case TargetISP:
		var ips []string
		for _, rr := range m.Answers {
			if rr.Type == dnsmsg.TypeA {
				ips = append(ips, rr.Data.A.String())
			}
		}
		if len(ips) == 0 {
			fmt.Fprintf(t.Out, "=> ISP returned no A records (answer=%d). ra=%v\n",
				len(m.Answers), m.Header.RA())
			return
		}
		fmt.Fprintf(t.Out, "=> recursive answer: %d A record(s) [%s]. ra=%v\n",
			len(ips), strings.Join(ips, ", "), m.Header.RA())
	}
}
