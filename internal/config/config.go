// Package config loads network parameters from a plain-text config file
// (so IP / MAC / DNS values live outside the source code, per assignment rules).
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

type Config struct {
	Interface    string           // pcap device name, e.g. "en0"
	SrcIP        net.IP           // our IPv4 address on Interface
	SrcMAC       net.HardwareAddr // our L2 address on Interface
	GatewayMAC   net.HardwareAddr // default router's MAC (next hop)
	ISPDNS       net.IP           // DNS resolver from DHCP / scutil --dns
	RootDNS      net.IP           // root server chosen from root-servers.org
	RootDNSLabel string           // e.g. "a.root-servers.net"
	raw          map[string]string
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	kv := make(map[string]string)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("%s:%d: expected key=value", path, lineNo)
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		kv[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	cfg := &Config{raw: kv}
	get := func(k string, required bool) (string, error) {
		v, ok := kv[k]
		if !ok || v == "" {
			if required {
				return "", fmt.Errorf("config key %q is required but missing/empty", k)
			}
			return "", nil
		}
		return v, nil
	}
	var v string
	if v, err = get("interface", true); err != nil {
		return nil, err
	}
	cfg.Interface = v

	if v, err = get("src_ip", true); err != nil {
		return nil, err
	}
	ip := net.ParseIP(v).To4()
	if ip == nil {
		return nil, fmt.Errorf("src_ip %q is not a valid IPv4 address", v)
	}
	cfg.SrcIP = ip

	if v, err = get("src_mac", true); err != nil {
		return nil, err
	}
	mac, err := net.ParseMAC(v)
	if err != nil {
		return nil, fmt.Errorf("src_mac %q: %w", v, err)
	}
	cfg.SrcMAC = mac

	if v, err = get("gateway_mac", true); err != nil {
		return nil, err
	}
	mac, err = net.ParseMAC(v)
	if err != nil {
		return nil, fmt.Errorf("gateway_mac %q: %w", v, err)
	}
	cfg.GatewayMAC = mac

	if v, err = get("isp_dns", true); err != nil {
		return nil, err
	}
	ip = net.ParseIP(v).To4()
	if ip == nil {
		return nil, fmt.Errorf("isp_dns %q is not a valid IPv4 address", v)
	}
	cfg.ISPDNS = ip

	if v, err = get("root_dns", true); err != nil {
		return nil, err
	}
	ip = net.ParseIP(v).To4()
	if ip == nil {
		return nil, fmt.Errorf("root_dns %q is not a valid IPv4 address", v)
	}
	cfg.RootDNS = ip

	cfg.RootDNSLabel, _ = get("root_dns_label", false)
	if cfg.RootDNSLabel == "" {
		cfg.RootDNSLabel = "root-server"
	}

	return cfg, nil
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"interface=%s src_ip=%s src_mac=%s gateway_mac=%s isp_dns=%s root_dns=%s (%s)",
		c.Interface, c.SrcIP, c.SrcMAC, c.GatewayMAC, c.ISPDNS, c.RootDNS, c.RootDNSLabel,
	)
}
