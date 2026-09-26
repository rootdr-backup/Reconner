package scanner

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/projectdiscovery/cdncheck"
)

const MaxNetworkScopeHosts = 65536

// NormalizeNetworkScope accepts the three network forms exposed by the UI:
// one IP, one CIDR, or an inclusive start-end range. It returns a canonical
// representation suitable for storage and rejects ambiguous hostnames.
func NormalizeNetworkScope(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("network scope is empty")
	}
	if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return addr.Unmap().String(), nil
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		prefix = prefix.Masked()
		if _, err := expandNetworkToken(prefix.String(), MaxNetworkScopeHosts); err != nil {
			return "", err
		}
		return prefix.String(), nil
	}
	parts := strings.Split(raw, "-")
	if len(parts) == 2 {
		start, errStart := netip.ParseAddr(strings.TrimSpace(parts[0]))
		end, errEnd := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if errStart == nil && errEnd == nil {
			start, end = start.Unmap(), end.Unmap()
			if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
				return "", fmt.Errorf("network range must use one address family and start before end")
			}
			canonical := start.String() + "-" + end.String()
			if _, err := expandNetworkToken(canonical, MaxNetworkScopeHosts); err != nil {
				return "", err
			}
			return canonical, nil
		}
	}
	return "", fmt.Errorf("network scope must be a single IP, CIDR, or inclusive IP range")
}

// ExpandNetworkScope returns unique addresses in stable order. The hard bound
// prevents a typo such as /8 from turning a single-server deployment into an
// unbounded allocation or an accidental Internet-scale scan.
func ExpandNetworkScope(raw string, maxHosts int) ([]net.IP, error) {
	if maxHosts <= 0 || maxHosts > MaxNetworkScopeHosts {
		maxHosts = MaxNetworkScopeHosts
	}
	seen := map[netip.Addr]bool{}
	out := make([]net.IP, 0)
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		canonical, err := NormalizeNetworkScope(token)
		if err != nil {
			return nil, err
		}
		addrs, err := expandNetworkToken(canonical, maxHosts-len(out))
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, net.IP(addr.AsSlice()))
			if len(out) > maxHosts {
				return nil, fmt.Errorf("network scope exceeds the %d-host safety limit", maxHosts)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("network scope contains no IP addresses")
	}
	return out, nil
}

func expandNetworkToken(token string, limit int) ([]netip.Addr, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("network scope exceeds the host safety limit")
	}
	if addr, err := netip.ParseAddr(token); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	if prefix, err := netip.ParsePrefix(token); err == nil {
		prefix = prefix.Masked()
		out := make([]netip.Addr, 0)
		for addr := prefix.Addr().Unmap(); addr.IsValid() && prefix.Contains(addr); addr = addr.Next() {
			out = append(out, addr)
			if len(out) > limit {
				return nil, fmt.Errorf("network scope %s exceeds the %d-host safety limit", token, limit)
			}
		}
		return out, nil
	}
	parts := strings.Split(token, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid network scope %q", token)
	}
	start, startErr := netip.ParseAddr(parts[0])
	end, endErr := netip.ParseAddr(parts[1])
	if startErr != nil || endErr != nil {
		return nil, fmt.Errorf("invalid network range %q", token)
	}
	start, end = start.Unmap(), end.Unmap()
	out := make([]netip.Addr, 0)
	for addr := start; addr.IsValid() && addr.Compare(end) <= 0; addr = addr.Next() {
		out = append(out, addr)
		if len(out) > limit {
			return nil, fmt.Errorf("network scope %s exceeds the %d-host safety limit", token, limit)
		}
	}
	return out, nil
}

type NetworkProviderMatch struct {
	IP       string
	Provider string
	Kind     string
}

// FilterCDNWAF removes third-party CDN/WAF addresses before port discovery.
// Cloud ranges are reported but retained: many authorised bounty assets are
// hosted on AWS/GCP/Azure, whereas a CDN/WAF edge is not the origin the operator
// intended to scan.
func FilterCDNWAF(ips []net.IP) (kept []string, blocked []NetworkProviderMatch) {
	client := cdncheck.New()
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if matched, provider, err := client.CheckCDN(ip); err == nil && matched {
			blocked = append(blocked, NetworkProviderMatch{IP: ip.String(), Provider: provider, Kind: "cdn"})
			continue
		}
		if matched, provider, err := client.CheckWAF(ip); err == nil && matched {
			blocked = append(blocked, NetworkProviderMatch{IP: ip.String(), Provider: provider, Kind: "waf"})
			continue
		}
		kept = append(kept, ip.String())
	}
	return kept, blocked
}
