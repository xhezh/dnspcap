package tasks

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"dnspcap/internal/config"
	"dnspcap/internal/dnsmsg"
	"dnspcap/internal/l234"
	"dnspcap/internal/netio"
)

const (
	dnsPort       = 53
	defaultTimeout = 5 * time.Second
)

func randUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// randomEphemeralPort returns a port in the 49152..65535 ephemeral range.
func randomEphemeralPort() uint16 {
	p := randUint16()
	const min = 49152
	return min + (p % (65535 - min + 1))
}

// buildDNSOverEthernet assembles a full DNS-over-UDP-over-IPv4-over-Ethernet frame
// directed at dstIP using the next-hop MAC from cfg.
func buildDNSOverEthernet(cfg *config.Config, dstIP net.IP, srcPort uint16, dnsPayload []byte) ([]byte, error) {
	udp := &l234.UDPDatagram{
		SrcPort: srcPort,
		DstPort: dnsPort,
		Payload: dnsPayload,
	}
	udpBytes, err := udp.Marshal(cfg.SrcIP, dstIP)
	if err != nil {
		return nil, fmt.Errorf("udp marshal: %w", err)
	}
	ip := &l234.IPv4Packet{
		TOS:      0,
		ID:       randUint16(),
		Flags:    0x2, // Don't Fragment
		FragOff:  0,
		TTL:      64,
		Protocol: l234.ProtoUDP,
		SrcIP:    cfg.SrcIP,
		DstIP:    dstIP,
		Payload:  udpBytes,
	}
	ipBytes, err := ip.Marshal()
	if err != nil {
		return nil, fmt.Errorf("ipv4 marshal: %w", err)
	}
	eth := &l234.EthernetFrame{
		DstMAC:  cfg.GatewayMAC,
		SrcMAC:  cfg.SrcMAC,
		EthType: l234.EthTypeIPv4,
		Payload: ipBytes,
	}
	return eth.Marshal()
}

// sendDNSQuery opens a pcap handle, installs a BPF filter tight to the expected
// reply (src=serverIP:53, dst=us:srcPort), injects the frame, and reads until the
// matching DNS reply arrives or the deadline is reached. Returns the parsed DNS
// message and the raw DNS bytes for logging.
func sendDNSQuery(cfg *config.Config, dstIP net.IP, txID uint16, qname string, qtype uint16, rd bool, timeout time.Duration) (*dnsmsg.Message, []byte, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	srcPort := randomEphemeralPort()
	dnsQuery, err := dnsmsg.Query(txID, qname, qtype, rd)
	if err != nil {
		return nil, nil, fmt.Errorf("build DNS query: %w", err)
	}
	frame, err := buildDNSOverEthernet(cfg, dstIP, srcPort, dnsQuery)
	if err != nil {
		return nil, nil, err
	}

	h, err := netio.Open(cfg.Interface, false, 65535, 250*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}
	defer h.Close()

	bpf := fmt.Sprintf("udp and src host %s and src port 53 and dst host %s and dst port %d",
		dstIP.String(), cfg.SrcIP.String(), srcPort)
	if err := h.SetFilter(bpf); err != nil {
		return nil, nil, err
	}
	if err := h.Inject(frame); err != nil {
		return nil, nil, err
	}

	deadline := time.Now().Add(timeout)
	matchFn := func(data []byte) bool {
		msg, ok := extractDNS(data)
		if !ok {
			return false
		}
		parsed, err := dnsmsg.Parse(msg)
		if err != nil || parsed.Header.ID != txID {
			return false
		}
		if !parsed.Header.QR() {
			return false // not a response
		}
		return true
	}

	data, err := h.ReadUntil(deadline, matchFn)
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		return nil, nil, fmt.Errorf("no DNS reply from %s within %s", dstIP, timeout)
	}
	dnsBytes, ok := extractDNS(data)
	if !ok {
		return nil, nil, fmt.Errorf("captured frame did not decode to DNS")
	}
	msg, err := dnsmsg.Parse(dnsBytes)
	if err != nil {
		return nil, dnsBytes, fmt.Errorf("parse DNS reply: %w", err)
	}
	return msg, dnsBytes, nil
}

// extractDNS walks an Ethernet frame down to the DNS payload bytes.
// Returns (dnsBytes, true) if the frame is Ethernet/IPv4/UDP with dst/src port 53.
func extractDNS(frame []byte) ([]byte, bool) {
	eth, err := l234.ParseEthernet(frame)
	if err != nil || eth.EthType != l234.EthTypeIPv4 {
		return nil, false
	}
	ip, err := l234.ParseIPv4(eth.Payload)
	if err != nil || ip.Protocol != l234.ProtoUDP {
		return nil, false
	}
	udp, err := l234.ParseUDP(ip.Payload)
	if err != nil {
		return nil, false
	}
	if udp.SrcPort != dnsPort && udp.DstPort != dnsPort {
		return nil, false
	}
	return udp.Payload, true
}
