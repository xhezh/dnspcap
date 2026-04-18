package dnsmsg

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Header flags bits (big-endian, 16-bit flags field).
const (
	FlagQR = 1 << 15
	FlagAA = 1 << 10
	FlagTC = 1 << 9
	FlagRD = 1 << 8
	FlagRA = 1 << 7
)

// Query builds a single-question DNS query message.
// If rd is true, sets the Recursion Desired bit (use for ISP resolvers).
// For queries to authoritative or root servers, leave rd=false.
func Query(txID uint16, name string, qtype uint16, rd bool) ([]byte, error) {
	qname, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 12, 12+len(qname)+4)
	binary.BigEndian.PutUint16(buf[0:2], txID)
	var flags uint16 = 0
	if rd {
		flags |= FlagRD
	}
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT
	// ANCOUNT/NSCOUNT/ARCOUNT remain 0
	buf = append(buf, qname...)
	buf = append(buf, 0, 0, 0, 0) // placeholders for QTYPE, QCLASS
	binary.BigEndian.PutUint16(buf[len(buf)-4:len(buf)-2], qtype)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], ClassIN)
	return buf, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return nil, errors.New("empty label in domain name")
		}
		if len(label) > 63 {
			return nil, errors.New("label too long (>63)")
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0)
	return out, nil
}
