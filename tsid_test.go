package tsid

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTryParseIpOrRange(t *testing.T) {
	var args = [][]string{
		{"127.0.0.1", "!127.0.0.0", "127.0.0.1", "!127.0.0.2"},
		{"192.168.1.12", "!192.168.1.11", "192.168.1.12", "!192.168.1.13", "!192.168.1.255"},
		{"192.168.1.12/28", "192.168.1.0", "192.168.1.12", "192.168.1.15", "!192.168.1.16", "!192.168.1.255"},
		{"192.168.1.0/24", "192.168.1.12", "192.168.1.123", "192.168.1.185", "192.168.1.255"},
	}
	for _, arg := range args {
		parsed, err := parseAsRangeOrIp(arg[0])
		if err != nil {
			t.Fatalf(`Failed to partse ip: %s`, arg)
		}
		for _, ip := range arg[1:] {
			cleanIp, hasPrefix := strings.CutPrefix(ip, "!")
			if hasPrefix != !parsed.Contains(netip.MustParseAddr(cleanIp)) {
				t.Fatalf(`Ip %s should be contained in %s`, ip, arg[0])
			}
		}
	}
}

func TestParseAllowed(t *testing.T) {
	var args = [][]string{
		{"127.0.0.1", "!127.0.0.0", "127.0.0.1", "!127.0.0.2"},
		{"192.168.1.12", "!192.168.1.11", "192.168.1.12", "!192.168.1.13", "!192.168.1.255"},
		{"192.168.1.12/28", "192.168.1.0", "192.168.1.12", "192.168.1.15", "!192.168.1.16", "!192.168.1.255"},
		{"192.168.1.0/24", "192.168.1.12", "192.168.1.123", "192.168.1.185", "192.168.1.255"},
	}
	for _, arg := range args {
		parsed, err := parseAsRangeOrIp(arg[0])
		if err != nil {
			t.Fatalf(`Failed to partse ip: %s`, arg)
		}
		for _, ip := range arg[1:] {
			cleanIp, hasPrefix := strings.CutPrefix(ip, "!")
			if hasPrefix != !parsed.Contains(netip.MustParseAddr(cleanIp)) {
				t.Fatalf(`Ip %s should be contained in %s`, ip, arg[0])
			}
		}
	}
}
