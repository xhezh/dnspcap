package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h Header) QR() bool     { return h.Flags&FlagQR != 0 }
func (h Header) AA() bool     { return h.Flags&FlagAA != 0 }
func (h Header) TC() bool     { return h.Flags&FlagTC != 0 }
func (h Header) RD() bool     { return h.Flags&FlagRD != 0 }
func (h Header) RA() bool     { return h.Flags&FlagRA != 0 }
func (h Header) OpCode() int  { return int((h.Flags >> 11) & 0xF) }
func (h Header) RCode() uint8 { return uint8(h.Flags & 0xF) }

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RData holds parsed record data; only fields matching Type are populated.
type RData struct {
	A       net.IP
	AAAA    net.IP
	Name    string  // for NS, CNAME, PTR, MX.exchange
	MXPref  uint16  // for MX
	TXT     []string
	SOA     *SOARecord
	RawHex  string
}

type SOARecord struct {
	MName, RName                          string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  RData
	Raw   []byte
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

// Parse parses a complete DNS message from b.
func Parse(b []byte) (*Message, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("DNS message too short: %d", len(b))
	}
	m := &Message{}
	m.Header = Header{
		ID:      binary.BigEndian.Uint16(b[0:2]),
		Flags:   binary.BigEndian.Uint16(b[2:4]),
		QDCount: binary.BigEndian.Uint16(b[4:6]),
		ANCount: binary.BigEndian.Uint16(b[6:8]),
		NSCount: binary.BigEndian.Uint16(b[8:10]),
		ARCount: binary.BigEndian.Uint16(b[10:12]),
	}
	pos := 12
	var err error
	for i := uint16(0); i < m.Header.QDCount; i++ {
		var q Question
		q.Name, pos, err = parseName(b, pos)
		if err != nil {
			return nil, fmt.Errorf("question %d name: %w", i, err)
		}
		if pos+4 > len(b) {
			return nil, errors.New("truncated question")
		}
		q.Type = binary.BigEndian.Uint16(b[pos : pos+2])
		q.Class = binary.BigEndian.Uint16(b[pos+2 : pos+4])
		pos += 4
		m.Questions = append(m.Questions, q)
	}
	parseSection := func(n uint16) ([]ResourceRecord, error) {
		rrs := make([]ResourceRecord, 0, n)
		for i := uint16(0); i < n; i++ {
			rr, np, err := parseRR(b, pos)
			if err != nil {
				return nil, fmt.Errorf("rr %d: %w", i, err)
			}
			pos = np
			rrs = append(rrs, rr)
		}
		return rrs, nil
	}
	if m.Answers, err = parseSection(m.Header.ANCount); err != nil {
		return nil, err
	}
	if m.Authority, err = parseSection(m.Header.NSCount); err != nil {
		return nil, err
	}
	if m.Additional, err = parseSection(m.Header.ARCount); err != nil {
		return nil, err
	}
	return m, nil
}

func parseRR(msg []byte, pos int) (ResourceRecord, int, error) {
	var rr ResourceRecord
	var err error
	rr.Name, pos, err = parseName(msg, pos)
	if err != nil {
		return rr, 0, fmt.Errorf("rr name: %w", err)
	}
	if pos+10 > len(msg) {
		return rr, 0, errors.New("truncated RR fixed header")
	}
	rr.Type = binary.BigEndian.Uint16(msg[pos : pos+2])
	rr.Class = binary.BigEndian.Uint16(msg[pos+2 : pos+4])
	rr.TTL = binary.BigEndian.Uint32(msg[pos+4 : pos+8])
	rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
	pos += 10
	if pos+rdlen > len(msg) {
		return rr, 0, errors.New("truncated RDATA")
	}
	rdStart := pos
	rdEnd := pos + rdlen
	rr.Raw = append([]byte(nil), msg[rdStart:rdEnd]...)

	switch rr.Type {
	case TypeA:
		if rdlen != 4 {
			return rr, 0, fmt.Errorf("A rdlen=%d", rdlen)
		}
		rr.Data.A = net.IP(append([]byte(nil), msg[rdStart:rdStart+4]...))
	case TypeAAAA:
		if rdlen != 16 {
			return rr, 0, fmt.Errorf("AAAA rdlen=%d", rdlen)
		}
		rr.Data.AAAA = net.IP(append([]byte(nil), msg[rdStart:rdStart+16]...))
	case TypeNS, TypeCNAME, TypePTR:
		name, _, err := parseName(msg, rdStart)
		if err != nil {
			return rr, 0, fmt.Errorf("%s name: %w", TypeName(rr.Type), err)
		}
		rr.Data.Name = name
	case TypeMX:
		if rdlen < 3 {
			return rr, 0, errors.New("MX rdlen too short")
		}
		rr.Data.MXPref = binary.BigEndian.Uint16(msg[rdStart : rdStart+2])
		name, _, err := parseName(msg, rdStart+2)
		if err != nil {
			return rr, 0, fmt.Errorf("MX exchange: %w", err)
		}
		rr.Data.Name = name
	case TypeTXT:
		p := rdStart
		for p < rdEnd {
			l := int(msg[p])
			p++
			if p+l > rdEnd {
				return rr, 0, errors.New("TXT truncated")
			}
			rr.Data.TXT = append(rr.Data.TXT, string(msg[p:p+l]))
			p += l
		}
	case TypeSOA:
		soa := &SOARecord{}
		mname, p, err := parseName(msg, rdStart)
		if err != nil {
			return rr, 0, fmt.Errorf("SOA mname: %w", err)
		}
		soa.MName = mname
		rname, p, err := parseName(msg, p)
		if err != nil {
			return rr, 0, fmt.Errorf("SOA rname: %w", err)
		}
		soa.RName = rname
		if p+20 > len(msg) {
			return rr, 0, errors.New("SOA truncated")
		}
		soa.Serial = binary.BigEndian.Uint32(msg[p : p+4])
		soa.Refresh = binary.BigEndian.Uint32(msg[p+4 : p+8])
		soa.Retry = binary.BigEndian.Uint32(msg[p+8 : p+12])
		soa.Expire = binary.BigEndian.Uint32(msg[p+12 : p+16])
		soa.Minimum = binary.BigEndian.Uint32(msg[p+16 : p+20])
		rr.Data.SOA = soa
	default:
		rr.Data.RawHex = hexBytes(msg[rdStart:rdEnd])
	}
	return rr, rdEnd, nil
}

// parseName parses a potentially compressed DNS name starting at pos.
// Returns the dot-joined name and the position immediately after the *encoded* name
// (i.e., after the first pointer or terminating zero in the original stream).
func parseName(msg []byte, pos int) (string, int, error) {
	var labels []string
	jumped := false
	nextPos := 0
	hops := 0
	const maxHops = 20
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("name out of bounds")
		}
		b := msg[pos]
		if b == 0 {
			pos++
			if !jumped {
				nextPos = pos
			}
			break
		}
		if b&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", 0, errors.New("truncated compression pointer")
			}
			ptr := (int(b)&0x3F)<<8 | int(msg[pos+1])
			if !jumped {
				nextPos = pos + 2
				jumped = true
			}
			pos = ptr
			hops++
			if hops > maxHops {
				return "", 0, errors.New("too many compression hops")
			}
			continue
		}
		if b&0xC0 != 0 {
			return "", 0, fmt.Errorf("invalid label header 0x%02x", b)
		}
		length := int(b)
		pos++
		if pos+length > len(msg) {
			return "", 0, errors.New("label runs past end")
		}
		labels = append(labels, string(msg[pos:pos+length]))
		pos += length
	}
	return strings.Join(labels, "."), nextPos, nil
}

func hexBytes(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexChars[x>>4], hexChars[x&0x0F])
	}
	return string(out)
}

// FormatRR produces a human-readable string for a resource record.
func FormatRR(rr ResourceRecord) string {
	prefix := fmt.Sprintf("%s %ds %s %s", rr.Name, rr.TTL, ClassName(rr.Class), TypeName(rr.Type))
	switch rr.Type {
	case TypeA:
		return fmt.Sprintf("%s %s", prefix, rr.Data.A)
	case TypeAAAA:
		return fmt.Sprintf("%s %s", prefix, rr.Data.AAAA)
	case TypeNS, TypeCNAME, TypePTR:
		return fmt.Sprintf("%s %s", prefix, rr.Data.Name)
	case TypeMX:
		return fmt.Sprintf("%s %d %s", prefix, rr.Data.MXPref, rr.Data.Name)
	case TypeTXT:
		return fmt.Sprintf("%s %q", prefix, strings.Join(rr.Data.TXT, " "))
	case TypeSOA:
		s := rr.Data.SOA
		return fmt.Sprintf("%s %s %s serial=%d refresh=%d retry=%d expire=%d min=%d",
			prefix, s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
	}
	return fmt.Sprintf("%s raw=%s", prefix, rr.Data.RawHex)
}

// FormatHeader renders the DNS header flags in a dig-style one-liner.
func FormatHeader(h Header) string {
	op := "QUERY"
	switch h.OpCode() {
	case OpIQuery:
		op = "IQUERY"
	case OpStatus:
		op = "STATUS"
	}
	rcode, ok := RCodeNames[h.RCode()]
	if !ok {
		rcode = fmt.Sprintf("RCODE%d", h.RCode())
	}
	var flags []string
	if h.QR() {
		flags = append(flags, "qr")
	}
	if h.AA() {
		flags = append(flags, "aa")
	}
	if h.TC() {
		flags = append(flags, "tc")
	}
	if h.RD() {
		flags = append(flags, "rd")
	}
	if h.RA() {
		flags = append(flags, "ra")
	}
	return fmt.Sprintf("id=%d opcode=%s status=%s flags=[%s] qd=%d an=%d ns=%d ar=%d",
		h.ID, op, rcode, strings.Join(flags, " "), h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}
