// Package adgo implements Active Directory attack primitives on the agent.
// Go analogue of Program/ad_attack/. Uses only the stdlib — LDAP is a
// BER/ASN.1 protocol on TCP/389 (or LDAPS on 636), and the messages we need
// (bind, search, unbind) are small enough to encode directly.
//
// The minimal LDAP client covers:
//   - simple bind (DN + password)
//   - anonymous bind
//   - search (base, filter, attributes, scope)
//   - response parsing into DN / attributes
//
// Not implemented: SASL, STARTTLS, paged results, referrals. Those are all
// follow-ups if the operator needs them. Simple bind over LDAP with an AD
// user is the common case for on-prem reconnaissance.
package adgo

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// LDAPOptions controls a bind / search session.
type LDAPOptions struct {
	Host    string
	Port    int  // 389 default, 636 for LDAPS
	TLS     bool // LDAPS
	Timeout time.Duration
	BindDN  string
	BindPW  string
	// Anon binds when BindDN and BindPW are both empty.
}

// ldapDefault fills defaults.
func ldapDefault(opts LDAPOptions) LDAPOptions {
	if opts.Port == 0 {
		if opts.TLS {
			opts.Port = 636
		} else {
			opts.Port = 389
		}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	return opts
}

// LDAPConn is a live LDAP session.
type LDAPConn struct {
	conn   net.Conn
	reader *bufio.Reader
	msgID  int
	opts   LDAPOptions
}

// --- BER / ASN.1 encoding ---

// berTag writes a tag byte followed by a length, then the content.
func berTag(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, berLength(len(content))...)
	out = append(out, content...)
	return out
}

// berLength encodes a BER definite length.
func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(n))
	// trim leading zeros
	i := 0
	for i < 4 && tmp[i] == 0 {
		i++
	}
	out := []byte{0x80 | byte(4-i)}
	out = append(out, tmp[i:]...)
	return out
}

// berInteger encodes an ASN.1 INTEGER.
func berInteger(n int) []byte {
	if n == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(n))
	i := 0
	for i < 7 && tmp[i] == 0 && tmp[i+1]&0x80 == 0 {
		i++
	}
	return berTag(0x02, tmp[i:])
}

// berOctetString encodes an ASN.1 OCTET STRING.
func berOctetString(b []byte) []byte {
	return berTag(0x04, b)
}

// berEnumerated encodes an ASN.1 ENUMERATED.
func berEnumerated(n int) []byte {
	if n < 128 {
		return []byte{0x0A, 0x01, byte(n)}
	}
	// 2-byte
	return []byte{0x0A, 0x02, byte(n >> 8), byte(n)}
}

// berSequence wraps content in a SEQUENCE.
func berSequence(content []byte) []byte {
	return berTag(0x30, content)
}

// ldapBool encodes an LDAP BOOLEAN.
func ldapBool(v bool) []byte {
	if v {
		return []byte{0x01, 0x01, 0xFF}
	}
	return []byte{0x01, 0x01, 0x00}
}

// ldapString encodes an LDAP OCTET STRING.
func ldapString(s string) []byte {
	return berOctetString([]byte(s))
}

// --- messages ---

// ldapMessage wraps a protocol op in the LDAPMessage envelope with a
// message ID. Response parsing reads the same shape back.
func ldapMessage(msgID int, op []byte) []byte {
	inner := append(berInteger(msgID), op...)
	return berSequence(inner)
}

// buildBindRequest builds a simple bind (version 3, name, password).
func buildBindRequest(msgID int, bindDN, password string) []byte {
	inner := berInteger(3)                                   // version
	inner = append(inner, ldapString(bindDN)...)             // name
	inner = append(inner, berTag(0x80, []byte(password))...) // [0] authentication (simple)
	op := berTag(0x60, inner)
	return ldapMessage(msgID, op)
}

// buildSearchRequest builds a search.
//
// LDAP SearchRequest (APPLICATION 3, tag 0x63):
//
//	baseObject (OCTET STRING)
//	scope      (ENUMERATED) 0=base, 1=one, 2=subtree
//	derefAliases (ENUMERATED) 0=never
//	sizeLimit (INTEGER) 0=no limit
//	timeLimit (INTEGER) 0=no limit
//	typesOnly (BOOLEAN) FALSE
//	filter    (Filter)
//	attributes (SEQUENCE OF OCTET STRING)
func buildSearchRequest(msgID int, base, filter string, scope int, attrs []string) []byte {
	var inner []byte
	inner = append(inner, ldapString(base)...)
	inner = append(inner, berEnumerated(scope)...)
	inner = append(inner, berEnumerated(0)...)          // never deref
	inner = append(inner, berInteger(0)...)             // no size limit
	inner = append(inner, berInteger(0)...)             // no time limit
	inner = append(inner, ldapBool(false)...)           // types only
	inner = append(inner, parseSimpleFilter(filter)...) // Filter
	// attributes
	var attrSeq []byte
	for _, a := range attrs {
		attrSeq = append(attrSeq, ldapString(a)...)
	}
	inner = append(inner, berSequence(attrSeq)...)
	op := berTag(0x63, inner)
	return ldapMessage(msgID, op)
}

// parseSimpleFilter parses a filter string of the form "(cn=value)" or
// "(&(a=b)(c=d))" into BER. Only the operators we use are supported.
func parseSimpleFilter(f string) []byte {
	f = strings.TrimSpace(f)
	if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") {
		// bare "cn=value" — wrap in equality
		return parseSimpleFilter("(" + f + ")")
	}
	inner := f[1 : len(f)-1]
	if inner == "" {
		// present filter for empty
		return berTag(0x87, nil)
	}
	switch inner[0] {
	case '&':
		// AND of children
		children := splitFilters(inner[1:])
		var content []byte
		for _, c := range children {
			content = append(content, parseSimpleFilter(c)...)
		}
		return berTag(0xA0, content)
	case '|':
		children := splitFilters(inner[1:])
		var content []byte
		for _, c := range children {
			content = append(content, parseSimpleFilter(c)...)
		}
		return berTag(0xA1, content)
	case '!':
		children := splitFilters(inner[1:])
		if len(children) < 1 {
			return berTag(0xA2, nil)
		}
		return berTag(0xA2, parseSimpleFilter(children[0]))
	}
	// equality: attr=value
	eq := strings.IndexByte(inner, '=')
	if eq < 0 {
		return berTag(0x87, nil)
	}
	attr := inner[:eq]
	val := inner[eq+1:]
	switch {
	case val == "*":
		// present filter
		return berTag(0x87, []byte(attr))
	case strings.HasPrefix(val, "*") && strings.HasSuffix(val, "*"):
		// substring any
		return berTag(0xA4, append(ldapString(attr),
			append(berTag(0x80, nil), berTag(0x81, []byte(strings.Trim(val, "*")))...)...))
	case strings.HasPrefix(val, "*"):
		// substring final
		return berTag(0xA4, append(ldapString(attr),
			berTag(0x81, []byte(strings.TrimPrefix(val, "*")))...))
	case strings.HasSuffix(val, "*"):
		// substring initial
		return berTag(0xA4, append(ldapString(attr),
			berTag(0x80, []byte(strings.TrimSuffix(val, "*")))...))
	}
	// exact equality: [A3] { attr [04] val }  — actually EqualityMatch is [A3] { attributeDesc [04], assertionValue [04] }
	content := append(ldapString(attr), ldapString(val)...)
	return berTag(0xA3, content)
}

// splitFilters splits a concatenation of (...) groups.
func splitFilters(s string) []string {
	var out []string
	depth := 0
	start := -1
	for i, r := range s {
		switch r {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, s[start:i+1])
				start = -1
			}
		}
	}
	return out
}

// --- response parsing ---

// LDAPEntry is one returned object with its DN and attributes.
type LDAPEntry struct {
	DN    string
	Attrs map[string][]string
}

// BER reader state — minimal, handles the tags we emit.

type berReader struct {
	b   []byte
	off int
}

func (r *berReader) readTag() (byte, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	t := r.b[r.off]
	r.off++
	return t, nil
}

func (r *berReader) readLength() (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	b := r.b[r.off]
	r.off++
	if b&0x80 == 0 {
		return int(b), nil
	}
	n := int(b & 0x7F)
	if n == 0 || n > 4 {
		return 0, errors.New("bad ber length")
	}
	if r.off+n > len(r.b) {
		return 0, io.EOF
	}
	var v int
	for i := 0; i < n; i++ {
		v = (v << 8) | int(r.b[r.off+i])
	}
	r.off += n
	return v, nil
}

func (r *berReader) readContent() ([]byte, error) {
	l, err := r.readLength()
	if err != nil {
		return nil, err
	}
	if r.off+l > len(r.b) {
		return nil, io.EOF
	}
	out := r.b[r.off : r.off+l]
	r.off += l
	return out, nil
}

// --- public ---

// Dial opens an LDAP connection (no bind yet).
func Dial(opts LDAPOptions) (*LDAPConn, error) {
	opts = ldapDefault(opts)
	if opts.Host == "" {
		return nil, errors.New("adgo/ldap: host required")
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("adgo/ldap: dial: %w", err)
	}
	return &LDAPConn{
		conn:   conn,
		reader: bufio.NewReader(conn),
		opts:   opts,
		msgID:  1,
	}, nil
}

// Bind sends the simple bind and reads the response.
func (c *LDAPConn) Bind() error {
	c.msgID++
	bind := buildBindRequest(c.msgID, c.opts.BindDN, c.opts.BindPW)
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(bind); err != nil {
		return fmt.Errorf("adgo/ldap: bind write: %w", err)
	}
	// read one LDAPMessage (SEQUENCE) containing a BindResponse
	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	// look for the BindResponse tag (0x61) and pull the resultCode
	rr := &berReader{b: resp}
	if t, err := rr.readTag(); err != nil || t != 0x30 {
		return errors.New("adgo/ldap: bind response not a sequence")
	}
	if _, err := rr.readContent(); err != nil {
		return err
	}
	// inside: messageID (INTEGER), BindResponse (0x61)
	_, _ = rr.readTag() // integer
	_, _ = rr.readContent()
	t, err := rr.readTag()
	if err != nil || t != 0x61 {
		return errors.New("adgo/ldap: no bind response tag")
	}
	inner, err := rr.readContent()
	if err != nil {
		return err
	}
	inner2 := &berReader{b: inner}
	// ENUMERATED resultCode
	t2, _ := inner2.readTag()
	if t2 != 0x0A {
		return errors.New("adgo/ldap: expected enumerated result code")
	}
	rc, _ := inner2.readContent()
	if len(rc) == 0 || rc[0] != 0 {
		return fmt.Errorf("adgo/ldap: bind failed result=%d", rc[0])
	}
	return nil
}

// readMessage reads one LDAPMessage from the wire (length-prefixed BER).
func (c *LDAPConn) readMessage() ([]byte, error) {
	// read tag
	tag, err := c.reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("adgo/ldap: read tag: %w", err)
	}
	if tag != 0x30 {
		return nil, fmt.Errorf("adgo/ldap: unexpected message tag 0x%02x", tag)
	}
	// read length
	b, err := c.reader.ReadByte()
	if err != nil {
		return nil, err
	}
	var length int
	if b&0x80 == 0 {
		length = int(b)
	} else {
		n := int(b & 0x7F)
		if n > 4 {
			return nil, errors.New("adgo/ldap: message length too long")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.reader, buf); err != nil {
			return nil, err
		}
		for i := 0; i < n; i++ {
			length = (length << 8) | int(buf[i])
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.reader, body); err != nil {
		return nil, err
	}
	out := []byte{0x30}
	out = append(out, berLength(length)...)
	out = append(out, body...)
	return out, nil
}

// Search issues a search and parses returned entries.
func (c *LDAPConn) Search(base, filter string, scope int, attrs []string) ([]LDAPEntry, error) {
	if scope < 0 || scope > 2 {
		scope = 2 // subtree
	}
	c.msgID++
	search := buildSearchRequest(c.msgID, base, filter, scope, attrs)
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(search); err != nil {
		return nil, fmt.Errorf("adgo/ldap: search write: %w", err)
	}

	var entries []LDAPEntry
	for {
		raw, err := c.readMessage()
		if err != nil {
			return entries, err
		}
		tag, entry, done, err := parseSearchMessage(raw)
		if err != nil {
			return entries, err
		}
		if done {
			return entries, nil
		}
		if tag == 0x64 && entry != nil { // SearchResultEntry
			entries = append(entries, *entry)
		}
		// tag 0x65 = SearchResultDone — loop condition handled above
		if tag == 0x65 {
			return entries, nil
		}
	}
}

// parseSearchMessage extracts an LDAPEntry from a SearchResultEntry
// (tag 0x64) or signals completion on SearchResultDone (0x65).
func parseSearchMessage(raw []byte) (byte, *LDAPEntry, bool, error) {
	rr := &berReader{b: raw}
	t, err := rr.readTag()
	if err != nil || t != 0x30 {
		return 0, nil, false, errors.New("bad message")
	}
	body, err := rr.readContent()
	if err != nil {
		return 0, nil, false, err
	}
	inner := &berReader{b: body}
	// messageID
	_, _ = inner.readTag()
	_, _ = inner.readContent()
	opTag, err := inner.readTag()
	if err != nil {
		return 0, nil, false, err
	}
	opBody, err := inner.readContent()
	if err != nil {
		return 0, nil, false, err
	}
	switch opTag {
	case 0x65: // SearchResultDone
		return opTag, nil, true, nil
	case 0x64: // SearchResultEntry
		entry, err := parseEntry(opBody)
		if err != nil {
			return opTag, nil, false, err
		}
		return opTag, &entry, false, nil
	default:
		return opTag, nil, false, nil
	}
}

// parseEntry reads a SearchResultEntry body: objectName (OCTET STRING),
// then a SEQUENCE OF PartialAttribute { type (OCTET STRING), vals (SET OF OCTET STRING) }.
func parseEntry(body []byte) (LDAPEntry, error) {
	var e LDAPEntry
	e.Attrs = map[string][]string{}
	rr := &berReader{b: body}
	t, err := rr.readTag()
	if err != nil || t != 0x04 {
		return e, errors.New("entry: expected objectName")
	}
	dn, _ := rr.readContent()
	e.DN = string(dn)
	// attributes sequence
	t, err = rr.readTag()
	if err != nil {
		return e, nil // may be omitted
	}
	if t != 0x30 {
		return e, nil
	}
	attrBody, _ := rr.readContent()
	ar := &berReader{b: attrBody}
	for ar.off < len(attrBody) {
		t, err := ar.readTag()
		if err != nil || t != 0x30 {
			break
		}
		partBody, _ := ar.readContent()
		pr := &berReader{b: partBody}
		t2, _ := pr.readTag()
		if t2 != 0x04 {
			continue
		}
		name, _ := pr.readContent()
		t3, _ := pr.readTag()
		if t3 != 0x31 { // SET OF
			continue
		}
		setBody, _ := pr.readContent()
		sr := &berReader{b: setBody}
		var vals []string
		for sr.off < len(setBody) {
			t4, _ := sr.readTag()
			if t4 != 0x04 {
				break
			}
			v, _ := sr.readContent()
			vals = append(vals, string(v))
		}
		e.Attrs[strings.ToLower(string(name))] = vals
	}
	return e, nil
}

// Close ends the LDAP session.
func (c *LDAPConn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
