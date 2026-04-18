package l234

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	IPv4MinHeaderLen = 20
	ProtoUDP         = 17
	ProtoTCP         = 6
	ProtoICMP        = 1
)

type IPv4Packet struct {
	TOS      uint8
	ID       uint16
	Flags    uint8
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

func (p *IPv4Packet) Marshal() ([]byte, error) {
	src := p.SrcIP.To4()
	dst := p.DstIP.To4()
	if src == nil || dst == nil {
		return nil, errors.New("IPv4 addresses must be 4 bytes")
	}
	total := IPv4MinHeaderLen + len(p.Payload)
	if total > 0xFFFF {
		return nil, errors.New("IPv4 packet too large")
	}
	hdr := make([]byte, IPv4MinHeaderLen)
	hdr[0] = 0x45 // version 4, IHL 5
	hdr[1] = p.TOS
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	binary.BigEndian.PutUint16(hdr[4:6], p.ID)
	flagsFrag := (uint16(p.Flags)&0x7)<<13 | (p.FragOff & 0x1FFF)
	binary.BigEndian.PutUint16(hdr[6:8], flagsFrag)
	hdr[8] = p.TTL
	hdr[9] = p.Protocol
	// checksum at 10..12 left zero for computation
	copy(hdr[12:16], src)
	copy(hdr[16:20], dst)
	cs := internetChecksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:12], cs)

	out := make([]byte, 0, total)
	out = append(out, hdr...)
	out = append(out, p.Payload...)
	return out, nil
}

func ParseIPv4(b []byte) (*IPv4Packet, error) {
	if len(b) < IPv4MinHeaderLen {
		return nil, fmt.Errorf("IPv4 too short: %d", len(b))
	}
	verIhl := b[0]
	if verIhl>>4 != 4 {
		return nil, fmt.Errorf("not IPv4 (version=%d)", verIhl>>4)
	}
	ihl := int(verIhl&0x0F) * 4
	if ihl < IPv4MinHeaderLen || len(b) < ihl {
		return nil, fmt.Errorf("bad IHL: %d", ihl)
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total > len(b) {
		total = len(b)
	}
	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	p := &IPv4Packet{
		TOS:      b[1],
		ID:       binary.BigEndian.Uint16(b[4:6]),
		Flags:    uint8(flagsFrag >> 13),
		FragOff:  flagsFrag & 0x1FFF,
		TTL:      b[8],
		Protocol: b[9],
		SrcIP:    net.IP(append([]byte(nil), b[12:16]...)),
		DstIP:    net.IP(append([]byte(nil), b[16:20]...)),
		Payload:  append([]byte(nil), b[ihl:total]...),
	}
	return p, nil
}

// internetChecksum computes the 16-bit one's complement sum used by IPv4/UDP/TCP.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
