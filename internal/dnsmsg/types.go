package dnsmsg

// DNS RR types (RFC 1035 + a few extensions).
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeANY   uint16 = 255
)

const ClassIN uint16 = 1

// OPCODEs
const (
	OpQuery  = 0
	OpIQuery = 1
	OpStatus = 2
)

// RCODEs
var RCodeNames = map[uint8]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}

func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeANY:
		return "ANY"
	}
	return "TYPE?"
}

func ClassName(c uint16) string {
	if c == ClassIN {
		return "IN"
	}
	return "CLASS?"
}
