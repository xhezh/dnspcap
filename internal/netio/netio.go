// Package netio is a thin wrapper around libpcap (via github.com/google/gopacket/pcap)
// that exposes only low-level operations: open a live handle, set a BPF filter,
// inject a raw Ethernet frame, and read raw Ethernet frames. Every other protocol
// (Ethernet, IPv4, UDP, DNS) is built and parsed by hand in sibling packages.
package netio

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

type Handle struct {
	h *pcap.Handle
}

// Open opens a live capture handle on the given interface.
// promiscuous=true requests promiscuous mode as required for task 1.
func Open(iface string, promiscuous bool, snapLen int, readTimeout time.Duration) (*Handle, error) {
	if iface == "" {
		return nil, errors.New("interface name is empty")
	}
	if snapLen <= 0 {
		snapLen = 65535
	}
	if readTimeout <= 0 {
		readTimeout = 500 * time.Millisecond
	}
	h, err := pcap.OpenLive(iface, int32(snapLen), promiscuous, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("pcap_open_live(%s): %w", iface, err)
	}
	return &Handle{h: h}, nil
}

func (h *Handle) SetFilter(bpf string) error {
	if bpf == "" {
		return nil
	}
	if err := h.h.SetBPFFilter(bpf); err != nil {
		return fmt.Errorf("SetBPFFilter(%q): %w", bpf, err)
	}
	return nil
}

// Inject writes a single raw Ethernet frame to the wire.
func (h *Handle) Inject(frame []byte) error {
	if err := h.h.WritePacketData(frame); err != nil {
		return fmt.Errorf("pcap_inject: %w", err)
	}
	return nil
}

// Read returns the next captured Ethernet frame. It will return an empty slice
// without error when the pcap read timeout fires (useful for polling with a
// deadline); callers should loop until their own deadline expires.
func (h *Handle) Read() ([]byte, error) {
	data, _, err := h.h.ReadPacketData()
	if err != nil {
		// gopacket surfaces the libpcap timeout as this sentinel
		if err == pcap.NextErrorTimeoutExpired {
			return nil, nil
		}
		return nil, fmt.Errorf("pcap_next_ex: %w", err)
	}
	return data, nil
}

// ReadUntil keeps polling until the deadline; returns (nil, nil) if the deadline
// passes without a match. The caller-provided match function decides whether a
// frame is interesting (e.g. matching DNS transaction id).
func (h *Handle) ReadUntil(deadline time.Time, match func([]byte) bool) ([]byte, error) {
	for {
		if time.Now().After(deadline) {
			return nil, nil
		}
		data, err := h.Read()
		if err != nil {
			return nil, err
		}
		if data == nil {
			continue
		}
		if match == nil || match(data) {
			return data, nil
		}
	}
}

func (h *Handle) Close() {
	if h != nil && h.h != nil {
		h.h.Close()
	}
}

// ListInterfaces returns device names visible to libpcap (for diagnostics).
func ListInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}
