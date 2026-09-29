package recon2

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// Email header analysis. Walks the Received chain (which is built in reverse
// order — newest hop first), spots the originating IP, and flags the common
// spoofing tells. Reads .eml files, raw header blobs, or the output of
// "fetchmail -v" / a maildrop file.
//
// The analysis does not validate SPF/DKIM/DMARC — that requires the sending
// domain's published records and the message body intact. It only looks for
// what's visible in the headers.

// MailTrace is the analysis output.
type MailTrace struct {
	From          string    `json:"from,omitempty"`
	ReturnPath    string    `json:"return_path,omitempty"`
	ReplyTo       string    `json:"reply_to,omitempty"`
	To            []string  `json:"to,omitempty"`
	Cc            []string  `json:"cc,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Date          string    `json:"date,omitempty"`
	MessageID     string    `json:"message_id,omitempty"`
	Received      []RecvHop `json:"received,omitempty"`
	AuthResults   []string  `json:"auth_results,omitempty"`   // Authentication-Results header lines
	ReceivedSPF   string    `json:"received_spf,omitempty"`   // Received-SPF header if present
	DKIMSignature []string  `json:"dkim_signatures,omitempty"`
	Suspect       []string  `json:"suspects,omitempty"`       // heuristic flags
	OriginIP      string    `json:"origin_ip,omitempty"`
}

// RecvHop is one hop in the Received chain.
type RecvHop struct {
	Index int    `json:"index"`           // 0 = most recent
	Raw   string `json:"raw,omitempty"`
	From  string `json:"from,omitempty"`  // "from" clause
	By    string `json:"by,omitempty"`    // "by" clause
	IP    string `json:"ip,omitempty"`    // bracketed ip if present
	When  string `json:"when,omitempty"`  // date portion
}

// ParseMailFile reads an .eml file and runs the analysis.
func ParseMailFile(path string) (MailTrace, error) {
	f, err := os.Open(path)
	if err != nil {
		return MailTrace{}, err
	}
	defer f.Close()
	return ParseMail(f)
}

// ParseMail reads headers from any reader and returns the analysis. Body is
// discarded at the first blank line.
func ParseMail(r io.Reader) (MailTrace, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var t MailTrace
	var curName, curValue string
	flush := func() {
		if curName == "" {
			return
		}
		addHeader(&t, curName, curValue)
		curName, curValue = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			break // headers end at the first blank line
		}
		// continuation line
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			curValue += " " + strings.TrimSpace(line)
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		curName = strings.TrimSpace(line[:colon])
		curValue = strings.TrimSpace(line[colon+1:])
	}
	flush()
	analyze(&t)
	return t, nil
}

// addHeader routes one header to the right struct field.
func addHeader(t *MailTrace, name, value string) {
	switch strings.ToLower(name) {
	case "from":
		t.From = value
	case "return-path":
		t.ReturnPath = value
	case "reply-to":
		t.ReplyTo = value
	case "to":
		t.To = append(t.To, splitAddrList(value)...)
	case "cc":
		t.Cc = append(t.Cc, splitAddrList(value)...)
	case "subject":
		t.Subject = value
	case "date":
		t.Date = value
	case "message-id":
		t.MessageID = value
	case "received":
		t.Received = append(t.Received, parseReceived(value, len(t.Received)))
	case "authentication-results":
		t.AuthResults = append(t.AuthResults, value)
	case "received-spf":
		t.ReceivedSPF = value
	case "dkim-signature":
		t.DKIMSignature = append(t.DKIMSignature, value)
	}
}

// splitAddrList splits a comma-separated address header.
func splitAddrList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseReceived parses one Received: header into hop parts.
//
// Format (RFC 5321 §4.4) is freeform, but a common shape is:
//   from <host> (<helo> [<ip>]) by <host> with <proto> id <id>; <date>
var (
	recvFromRe = regexp.MustCompile(`(?i)from\s+([^\s;]+)`)
	recvByRe   = regexp.MustCompile(`(?i)by\s+([^\s;]+)`)
	recvIPRe   = regexp.MustCompile(`\[(\d{1,3}(?:\.\d{1,3}){3})\]`)
	recvWhenRe = regexp.MustCompile(`;\s*(.+)$`)
)

func parseReceived(v string, idx int) RecvHop {
	h := RecvHop{Index: idx, Raw: v}
	if m := recvFromRe.FindStringSubmatch(v); len(m) > 1 {
		h.From = m[1]
	}
	if m := recvByRe.FindStringSubmatch(v); len(m) > 1 {
		h.By = m[1]
	}
	if m := recvIPRe.FindStringSubmatch(v); len(m) > 1 {
		h.IP = m[1]
	}
	if m := recvWhenRe.FindStringSubmatch(v); len(m) > 1 {
		h.When = strings.TrimSpace(m[1])
	}
	return h
}

// analyze runs the heuristic checks on the parsed structure.
func analyze(t *MailTrace) {
	// Origin IP is in the last hop (oldest). Earlier hops in the file are
	// the most recent by the RFC's "prepend" rule.
	if n := len(t.Received); n > 0 {
		for i := n - 1; i >= 0; i-- {
			if t.Received[i].IP != "" {
				t.OriginIP = t.Received[i].IP
				break
			}
		}
	}

	// From vs Return-Path vs Reply-To mismatch — the classic display-name
	// spoof signal.
	fromAddr := extractAddr(t.From)
	rpAddr := extractAddr(t.ReturnPath)
	rpToAddr := extractAddr(t.ReplyTo)
	if fromAddr != "" && rpAddr != "" && !sameDomain(fromAddr, rpAddr) {
		t.Suspect = append(t.Suspect, "From domain ("+domOf(fromAddr)+") differs from Return-Path domain ("+domOf(rpAddr)+")")
	}
	if fromAddr != "" && rpToAddr != "" && !sameDomain(fromAddr, rpToAddr) {
		t.Suspect = append(t.Suspect, "From domain differs from Reply-To domain ("+domOf(rpToAddr)+")")
	}

	// Auth results present?
	hasSPF, hasDKIM, hasDMARC := false, false, false
	for _, ar := range t.AuthResults {
		low := strings.ToLower(ar)
		if strings.Contains(low, "spf=") {
			hasSPF = true
			if strings.Contains(low, "spf=fail") || strings.Contains(low, "spf=softfail") {
				t.Suspect = append(t.Suspect, "Authentication-Results reports SPF failure")
			}
		}
		if strings.Contains(low, "dkim=") {
			hasDKIM = true
			if strings.Contains(low, "dkim=fail") {
				t.Suspect = append(t.Suspect, "Authentication-Results reports DKIM failure")
			}
		}
		if strings.Contains(low, "dmarc=") {
			hasDMARC = true
			if strings.Contains(low, "dmarc=fail") {
				t.Suspect = append(t.Suspect, "Authentication-Results reports DMARC failure")
			}
		}
	}
	if t.ReceivedSPF != "" {
		low := strings.ToLower(t.ReceivedSPF)
		if strings.Contains(low, "fail") || strings.Contains(low, "softfail") {
			t.Suspect = append(t.Suspect, "Received-SPF reports failure: "+t.ReceivedSPF)
		}
	}
	if !hasSPF && !hasDKIM && !hasDMARC {
		t.Suspect = append(t.Suspect, "no Authentication-Results header — SPF/DKIM/DMARC not evaluated on this hop")
	}

	// Zero-hop or single-hop message with an external-looking From — the
	// message did not traverse a real MTA chain.
	if len(t.Received) == 0 {
		t.Suspect = append(t.Suspect, "no Received headers at all — forged or hand-injected message")
	}

	// Date parsing — look for obviously wrong dates.
	if t.Date != "" {
		if parsed, err := parseMailDate(t.Date); err == nil {
			now := time.Now()
			if parsed.After(now.Add(24 * time.Hour)) {
				t.Suspect = append(t.Suspect, "Date is in the future — clock or manual forgery")
			}
			if now.Sub(parsed) > 30*24*time.Hour {
				// old but not necessarily suspect on its own
			}
		}
	}

	// Message-ID domain vs From domain.
	if t.MessageID != "" && fromAddr != "" {
		if !strings.Contains(t.MessageID, domOf(fromAddr)) {
			t.Suspect = append(t.Suspect, "Message-ID does not contain the From domain ("+domOf(fromAddr)+") — likely forged")
		}
	}
}

// extractAddr pulls the addr-spec out of "Display Name <user@host>" or "user@host".
var addrRe = regexp.MustCompile(`<([^>]+)>`)

func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if m := addrRe.FindStringSubmatch(s); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	// no display name — expect user@host directly
	return s
}

func domOf(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

func sameDomain(a, b string) bool {
	return domOf(a) != "" && domOf(a) == domOf(b)
}

// parseMailDate parses RFC 5322 date in the common formats.
func parseMailDate(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
		time.RFC3339,
		"2006-01-02 15:04:05 -0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, io.EOF
}

// ReadMailBytes is a convenience for callers with a byte slice.
func ReadMailBytes(b []byte) (MailTrace, error) {
	return ParseMail(bytes.NewReader(b))
}
