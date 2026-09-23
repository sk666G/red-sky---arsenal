// Package scanner provides a fast Go TCP port scanner for redsky-core.
package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseCIDR expands a CIDR (or single IP) into a list of host addresses.
func ParseCIDR(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty cidr")
	}
	if !strings.Contains(spec, "/") {
		// single host
		if net.ParseIP(spec) == nil {
			return nil, fmt.Errorf("bad ip: %s", spec)
		}
		return []string{spec}, nil
	}
	ip, network, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("bad cidr: %w", err)
	}
	_ = ip
	var hosts []string
	for cur := network.IP.Mask(network.Mask); network.Contains(cur); incIP(cur) {
		// skip network + broadcast when possible
		if cur.Equal(network.IP) {
			continue
		}
		// skip broadcast if IPv4
		if v4 := cur.To4(); v4 != nil {
			// broadcast is last address in the block
			bcast := make(net.IP, len(network.IP))
			copy(bcast, network.IP)
			for i := range bcast {
				bcast[i] |= ^network.Mask[i]
			}
			if cur.Equal(bcast) {
				continue
			}
		}
		hosts = append(hosts, cur.String())
		if len(hosts) > 65535 {
			return nil, fmt.Errorf("cidr too large (cap 65535 hosts)")
		}
	}
	return hosts, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ParsePorts parses a port spec like "22,80,443,8000-8100" or "1-1024".
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ends := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(ends[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(ends[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad port range: %s", part)
			}
			if a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("port range out of bounds: %s", part)
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}
