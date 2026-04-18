package l234

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	EthHeaderLen = 14
	EthTypeIPv4  = 0x0800
	EthTypeARP   = 0x0806
	EthTypeIPv6  = 0x86DD
)

type EthernetFrame struct {
	DstMAC  net.HardwareAddr
	SrcMAC  net.HardwareAddr
	EthType uint16
	Payload []byte
}

func (e *EthernetFrame) Marshal() ([]byte, error) {
	if len(e.DstMAC) != 6 || len(e.SrcMAC) != 6 {
		return nil, errors.New("MAC addresses must be 6 bytes")
	}
	out := make([]byte, EthHeaderLen+len(e.Payload))
	copy(out[0:6], e.DstMAC)
	copy(out[6:12], e.SrcMAC)
	binary.BigEndian.PutUint16(out[12:14], e.EthType)
	copy(out[14:], e.Payload)
	return out, nil
}

func ParseEthernet(b []byte) (*EthernetFrame, error) {
	if len(b) < EthHeaderLen {
		return nil, fmt.Errorf("ethernet frame too short: %d", len(b))
	}
	return &EthernetFrame{
		DstMAC:  net.HardwareAddr(append([]byte(nil), b[0:6]...)),
		SrcMAC:  net.HardwareAddr(append([]byte(nil), b[6:12]...)),
		EthType: binary.BigEndian.Uint16(b[12:14]),
		Payload: b[14:],
	}, nil
}
