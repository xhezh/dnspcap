# dnspcap — DNS over PCAP (Go, macOS)

A small console utility that talks to DNS servers directly over libpcap,
bypassing the host's network stack. Ethernet, IPv4, UDP, and DNS headers are
assembled and parsed by hand — the only networking dependency is the
low-level pcap bindings (`github.com/google/gopacket/pcap`).

Handy for seeing how DNS actually works on the wire: the difference between
an iterative response from a root server (a referral with NS + glue) and a
recursive response from an upstream resolver, two-step MX → A lookups, and
promiscuous capture of every DNS packet on the interface.

## Requirements

- macOS (tested on Apple Silicon / darwin 25). Linux should work with minor
  BPF-related tweaks.
- Go 1.21+ (`brew install go`).
- libpcap (ships with macOS; install Wireshark — it configures access to
  BPF devices via the `access_bpf` group).

## Quick start

```bash
# 1. generate a config for your network
./probe.sh > config.txt   # auto-detect; eyeball the values afterwards

# 2. build
go build -o dnspcap

# 3. run
./dnspcap
```

If your user is not in the `access_bpf` group, use `sudo ./dnspcap`.

On launch the program prints a command menu and a `>` prompt.

## Commands

| Command          | What it does                                           |
|------------------|--------------------------------------------------------|
| `help`           | Print the menu again                                   |
| `cfg`            | Show the loaded network configuration                  |
| `sniff`          | Promiscuous capture of all DNS packets (Ctrl+C exits)  |
| `mx <domain>`    | MX → A (two-step lookup), prints `D -> IP`             |
| `root <domain>`  | A-query sent straight to a root server (RD=0)          |
| `isp <domain>`   | A-query sent to your ISP's recursive resolver (RD=1)   |
| `probe`          | List pcap-visible interfaces (diagnostics)             |
| `quit`           | Exit                                                   |

## Project layout

```
main.go                         — interactive console, entry point
config.txt                      — IP/MAC/DNS parameters (not hardcoded)
probe.sh                        — auto-detect config values on macOS
internal/l234/ethernet.go       — Ethernet (14 bytes)
internal/l234/ipv4.go           — IPv4 + Internet Checksum
internal/l234/udp.go            — UDP + pseudo-header for the checksum
internal/dnsmsg/types.go        — constants (RR types, classes, RCODEs)
internal/dnsmsg/builder.go      — DNS query construction
internal/dnsmsg/parser.go       — DNS response parser (+ name compression)
internal/netio/netio.go         — thin libpcap wrapper
internal/config/config.go       — config.txt loader
internal/tasks/common.go        — shared send+recv helper
internal/tasks/task1_sniffer.go — `sniff` command
internal/tasks/task2_mx.go      — `mx` command
internal/tasks/task3_direct.go  — `root` / `isp` commands
```

## Implementation notes

- `RD=1` is only used when talking to a recursive resolver. Queries to a
  root server go out with `RD=0` — root servers don't recurse; the reply is
  a referral with NS records in AUTHORITY and A/AAAA glue in ADDITIONAL.
- The outgoing UDP source port is picked at random from the ephemeral range,
  and the DNS transaction ID is random too. The receive-side BPF filter is
  narrowed to the specific server and port, so unrelated DNS traffic on the
  host doesn't pollute the reply.
- The macOS kernel will see a UDP reply to a port nothing is bound to and
  may send ICMP Port Unreachable back to the server. That doesn't bother us —
  libpcap has already captured the reply before the kernel reacts.
