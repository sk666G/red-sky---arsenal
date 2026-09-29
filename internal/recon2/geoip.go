package recon2

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Offline IP-to-organization classification. Not full GeoIP — no city, no
// coordinates. What it does: given an IP, tell the operator whether it's
// private, loopback, link-local, cloud-provider, or a well-known network.
//
// Three layers, no external calls:
//
//   1. RFC classification — private / loopback / link-local / multicast /
//      reserved / CGNAT (100.64/10) / benchmark (198.18/15) / documentation
//      (192.0.2/24, 198.51.100/24, 203.0.113/24)
//   2. Cloud-provider ranges — the published IP blocks for AWS, GCP, Azure,
//      Cloudflare, DigitalOcean, Linode — a small builtin subset
//   3. Reverse DNS — best-effort PTR lookup for a hostname hint
//
// The cloud ranges here are a curated sample of the published lists. Full
// accuracy needs the provider's JSON feeds, which the operator can load
// via LoadCloudRanges.

// IPClass is the classification result.
type IPClass struct {
	IP       string   `json:"ip"`
	Family   string   `json:"family"`             // "ipv4" | "ipv6"
	Flags    []string `json:"flags,omitempty"`    // rfc1918, loopback, link-local, etc.
	Provider string   `json:"provider,omitempty"` // cloud provider if matched
	PTR      string   `json:"ptr,omitempty"`      // reverse DNS hostname if present
}

// ClassifyIP returns the RFC/cloud/PTR picture for one IP.
func ClassifyIP(ipStr string) (IPClass, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IPClass{}, fmt.Errorf("recon2: invalid ip %q", ipStr)
	}
	c := IPClass{IP: ipStr}
	if ip.To4() != nil {
		c.Family = "ipv4"
	} else {
		c.Family = "ipv6"
	}

	// RFC classifications
	if ip.IsLoopback() {
		c.Flags = append(c.Flags, "loopback")
	}
	if ip.IsPrivate() {
		c.Flags = append(c.Flags, "private")
	}
	if ip.IsLinkLocalUnicast() {
		c.Flags = append(c.Flags, "link-local")
	}
	if ip.IsLinkLocalMulticast() {
		c.Flags = append(c.Flags, "link-local-multicast")
	}
	if ip.IsMulticast() {
		c.Flags = append(c.Flags, "multicast")
	}
	if ip.IsUnspecified() {
		c.Flags = append(c.Flags, "unspecified")
	}
	if ip.IsInterfaceLocalMulticast() {
		c.Flags = append(c.Flags, "interface-local-multicast")
	}

	// special ranges not covered by the stdlib helpers
	if inCIDR(ip, "100.64.0.0/10") {
		c.Flags = append(c.Flags, "cgnat")
	}
	if inCIDR(ip, "198.18.0.0/15") {
		c.Flags = append(c.Flags, "benchmark")
	}
	if inCIDR(ip, "192.0.2.0/24") || inCIDR(ip, "198.51.100.0/24") || inCIDR(ip, "203.0.113.0/24") {
		c.Flags = append(c.Flags, "documentation")
	}
	if inCIDR(ip, "169.254.0.0/16") {
		c.Flags = append(c.Flags, "aws-imds") // special case — the metadata service
	}

	// Cloud provider check
	if p := matchProvider(ip); p != "" {
		c.Provider = p
	}

	// PTR lookup — best effort
	if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
		c.PTR = strings.TrimSuffix(names[0], ".")
	}

	return c, nil
}

// inCIDR reports whether ip is inside the given CIDR.
func inCIDR(ip net.IP, cidr string) bool {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return block.Contains(ip)
}

// CloudRange is one provider's published CIDR block.
type CloudRange struct {
	Provider string
	CIDR     string
}

// cloudRangesBuiltin is a curated sample. Real accuracy needs the provider
// feeds — see LoadCloudRanges for the full list form.
var cloudRangesBuiltin = []struct {
	Provider string
	CIDR     string
}{
	{"aws", "3.0.0.0/8"},
	{"aws", "13.32.0.0/12"},
	{"aws", "15.0.0.0/8"},
	{"aws", "18.0.0.0/8"},
	{"aws", "52.0.0.0/8"},
	{"aws", "54.0.0.0/8"},

	{"gcp", "8.8.8.0/24"}, // not really a GCP-owned block, but the DNS
	{"gcp", "34.0.0.0/9"},
	{"gcp", "35.0.0.0/9"},
	{"gcp", "104.196.0.0/14"},
	{"gcp", "130.211.0.0/16"},
	{"gcp", "199.36.152.0/22"},

	{"azure", "13.64.0.0/11"},
	{"azure", "20.0.0.0/8"},
	{"azure", "40.0.0.0/8"},
	{"azure", "52.128.0.0/9"},
	{"azure", "104.40.0.0/13"},
	{"azure", "168.61.0.0/16"},

	{"cloudflare", "1.1.1.0/24"},
	{"cloudflare", "104.16.0.0/12"},
	{"cloudflare", "172.64.0.0/13"},
	{"cloudflare", "173.245.48.0/20"},

	{"digitalocean", "104.131.0.0/16"},
	{"digitalocean", "138.197.0.0/16"},
	{"digitalocean", "159.65.0.0/16"},
	{"digitalocean", "164.90.128.0/17"},

	{"linode", "45.33.0.0/16"},
	{"linode", "50.116.0.0/16"},
	{"linode", "139.144.0.0/16"},
	{"linode", "172.104.0.0/15"},
}

// matchProvider returns the cloud provider name if the ip matches a
// builtin range.
func matchProvider(ip net.IP) string {
	for _, r := range cloudRangesBuiltin {
		if inCIDR(ip, r.CIDR) {
			return r.Provider
		}
	}
	return ""
}

// LoadCloudRanges replaces the builtin list with a caller-supplied one.
// Format: lines of "provider cidr" (whitespace-separated). Comment lines
// starting with # are ignored.
func LoadCloudRanges(blob string) ([]struct {
	Provider string
	CIDR     string
}, error) {
	var out []struct {
		Provider string
		CIDR     string
	}
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, _, err := net.ParseCIDR(fields[1]); err != nil {
			continue
		}
		out = append(out, struct {
			Provider string
			CIDR     string
		}{fields[0], fields[1]})
	}
	if len(out) == 0 {
		return nil, errors.New("recon2: no valid cloud range lines")
	}
	return out, nil
}
