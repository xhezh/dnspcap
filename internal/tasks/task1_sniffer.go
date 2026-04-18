package tasks

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"dnspcap/internal/config"
	"dnspcap/internal/dnsmsg"
	"dnspcap/internal/l234"
	"dnspcap/internal/netio"
)

// Task1Sniffer implements sub-task 1: capture all DNS packets in PROMISCUOUS
// mode and print a human-readable dump of each one. It only consumes libpcap
// bindings; Ethernet/IPv4/UDP/DNS parsing is done by our own code.
type Task1Sniffer struct {
	Cfg *config.Config
	Out io.Writer
}

func (t *Task1Sniffer) Run(ctx context.Context) error {
	h, err := netio.Open(t.Cfg.Interface, true /* promiscuous */, 65535, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := h.SetFilter("udp port 53"); err != nil {
		return err
	}
	fmt.Fprintf(t.Out, "[task1] sniffing DNS on %s (promiscuous). Press Ctrl+C to stop.\n", t.Cfg.Interface)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(t.Out, "[task1] stopped")
			return nil
		default:
		}
		data, err := h.Read()
		if err != nil {
			return err
		}
		if data == nil {
			continue
		}
		t.handleFrame(data)
	}
}

func (t *Task1Sniffer) handleFrame(frame []byte) {
	eth, err := l234.ParseEthernet(frame)
	if err != nil || eth.EthType != l234.EthTypeIPv4 {
		return
	}
	ip, err := l234.ParseIPv4(eth.Payload)
	if err != nil || ip.Protocol != l234.ProtoUDP {
		return
	}
	udp, err := l234.ParseUDP(ip.Payload)
	if err != nil {
		return
	}
	if udp.SrcPort != dnsPort && udp.DstPort != dnsPort {
		return
	}
	msg, err := dnsmsg.Parse(udp.Payload)
	if err != nil {
		fmt.Fprintf(t.Out, "[dns] %s:%d -> %s:%d parse error: %v\n",
			ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, err)
		return
	}
	t.printMessage(eth.SrcMAC, eth.DstMAC, ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort, msg)
}

func (t *Task1Sniffer) printMessage(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, msg *dnsmsg.Message) {
	ts := time.Now().Format("15:04:05.000")
	direction := "QUERY"
	if msg.Header.QR() {
		direction = "RESPONSE"
	}
	fmt.Fprintf(t.Out, "\n[%s] DNS %s  %s -> %s  (%s:%d -> %s:%d)\n",
		ts, direction, srcMAC, dstMAC, srcIP, srcPort, dstIP, dstPort)
	fmt.Fprintf(t.Out, "  header: %s\n", dnsmsg.FormatHeader(msg.Header))
	if len(msg.Questions) > 0 {
		fmt.Fprintln(t.Out, "  questions:")
		for _, q := range msg.Questions {
			fmt.Fprintf(t.Out, "    %s %s %s\n", q.Name, dnsmsg.ClassName(q.Class), dnsmsg.TypeName(q.Type))
		}
	}
	printSection(t.Out, "answer", msg.Answers)
	printSection(t.Out, "authority", msg.Authority)
	printSection(t.Out, "additional", msg.Additional)
}

func printSection(out io.Writer, label string, rrs []dnsmsg.ResourceRecord) {
	if len(rrs) == 0 {
		return
	}
	fmt.Fprintf(out, "  %s:\n", label)
	for _, rr := range rrs {
		fmt.Fprintf(out, "    %s\n", dnsmsg.FormatRR(rr))
	}
}
