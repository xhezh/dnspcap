package l234

import (
	"encoding/binary"
	"fmt"
	"net"
)

const UDPHeaderLen = 8

type UDPDatagram struct {
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// Marshal builds a UDP datagram with a correct checksum (pseudo-header over IPv4).
func (u *UDPDatagram) Marshal(srcIP, dstIP net.IP) ([]byte, error) {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return nil, fmt.Errorf("UDP checksum requires IPv4 addresses")
	}
	length := UDPHeaderLen + len(u.Payload)
	if length > 0xFFFF {
		return nil, fmt.Errorf("UDP payload too large")
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[0:2], u.SrcPort)
	binary.BigEndian.PutUint16(out[2:4], u.DstPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(length))
	// checksum [6:8] starts at zero
	copy(out[8:], u.Payload)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = ProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(length))

	buf := make([]byte, 0, len(pseudo)+length)
	buf = append(buf, pseudo...)
	buf = append(buf, out...)
	cs := internetChecksum(buf)
	if cs == 0 {
		cs = 0xFFFF
	}
	binary.BigEndian.PutUint16(out[6:8], cs)
	return out, nil
}

func ParseUDP(b []byte) (*UDPDatagram, error) {
	if len(b) < UDPHeaderLen {
		return nil, fmt.Errorf("UDP too short: %d", len(b))
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length > len(b) {
		length = len(b)
	}
	if length < UDPHeaderLen {
		return nil, fmt.Errorf("UDP length field invalid: %d", length)
	}
	return &UDPDatagram{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Payload: append([]byte(nil), b[UDPHeaderLen:length]...),
	}, nil
}
