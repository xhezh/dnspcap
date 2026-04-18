package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"dnspcap/internal/config"
	"dnspcap/internal/netio"
	"dnspcap/internal/tasks"
)

const banner = `
DNS over PCAP — interactive console
Commands:
  help                   — print this menu
  cfg                    — show the loaded network configuration
  sniff                  — capture all DNS packets (Ctrl+C to stop)
  mx <domain>            — resolve MX -> mail server IP (two-step)
  root <domain>          — query the root DNS server from config (RD=0)
  isp <domain>           — query your ISP's DNS resolver from config (RD=1)
  probe                  — list pcap-visible interfaces (diagnostics)
  quit | exit            — leave the program
`

func main() {
	cfgPath := flag.String("config", "config.txt", "path to the network config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Edit %s so it describes your network, then try again.\n", *cfgPath)
		os.Exit(2)
	}

	fmt.Println(strings.TrimSpace(banner))
	fmt.Printf("\nconfig: %s\n", cfg)
	fmt.Println()

	stdin := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !stdin.Scan() {
			return
		}
		line := strings.TrimSpace(stdin.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := strings.ToLower(fields[0])
		args := fields[1:]
		if err := dispatch(cfg, cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}
}

func dispatch(cfg *config.Config, cmd string, args []string) error {
	switch cmd {
	case "help", "?":
		fmt.Println(strings.TrimSpace(banner))
	case "cfg":
		fmt.Println(cfg)
	case "sniff":
		return runSniffer(cfg)
	case "mx":
		if len(args) < 1 {
			return fmt.Errorf("usage: mx <domain>")
		}
		return (&tasks.Task2MX{Cfg: cfg, Out: os.Stdout}).Run(args[0])
	case "root":
		if len(args) < 1 {
			return fmt.Errorf("usage: root <domain>")
		}
		return (&tasks.Task3Direct{Cfg: cfg, Out: os.Stdout}).Run(tasks.TargetRoot, args[0])
	case "isp":
		if len(args) < 1 {
			return fmt.Errorf("usage: isp <domain>")
		}
		return (&tasks.Task3Direct{Cfg: cfg, Out: os.Stdout}).Run(tasks.TargetISP, args[0])
	case "probe":
		return listInterfaces()
	case "quit", "exit", "q":
		os.Exit(0)
	default:
		return fmt.Errorf("unknown command %q (try 'help')", cmd)
	}
	return nil
}

func runSniffer(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT)
	defer signal.Stop(sigC)
	go func() {
		<-sigC
		cancel()
	}()

	return (&tasks.Task1Sniffer{Cfg: cfg, Out: os.Stdout}).Run(ctx)
}

func listInterfaces() error {
	ifaces, err := netio.ListInterfaces()
	if err != nil {
		return err
	}
	for _, ifc := range ifaces {
		var addrs []string
		for _, a := range ifc.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		fmt.Printf("%-10s %s\n", ifc.Name, strings.Join(addrs, ", "))
	}
	return nil
}
