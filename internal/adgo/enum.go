package adgo

import (
	"context"
	"fmt"
	"strings"
)

// AD enumeration via LDAP. Each function is one query the operator can
// fire against a bound session. Standard enumeration set — the same shape
// BloodHound uses, minus the graph.
//
//   1. RootDSE             — base DN discovery, naming contexts
//   2. Domain info         — name, SID, functional level
//   3. Users               — samAccountName, mail, last logon, pwd flags
//   4. Groups              — group name, description, member count
//   5. Computers           — hostname, OS, OS version, last logon
//   6. Domain Admins       — who is in the high-privilege group
//   7. GPOs                — policy list
//   8. Trusts              — inbound / outbound domain trusts
//   9. AS-REP roastable    — users with DONT_REQ_PREAUTH
//  10. Kerberoastable      — users with SPNs set
//  11. Unconstrained       — computers with TRUSTED_FOR_DELEGATION
//  12. LAPS                — password readers / find ms-Mcs-AdmPwd
//  13. ADCS CAs            — certificate authority service principals
//  14. Password-not-required — users with PASSWD_NOTREQD set
//
// Each returns a list of LDAPEntry for the caller to stream back over the
// tunnel.

// UserAccountControl flags we key on.
const (
	UACScript                 = 0x0001
	UACAccountDisable         = 0x0002
	UACHomeDirRequired        = 0x0008
	UACLockout                = 0x0010
	UACPasswordNotRequired    = 0x0020
	UACPasswordCantChange     = 0x0040
	UACEncryptedTextPwdAllow  = 0x0080
	UACTempDuplicateAccount   = 0x0100
	UACNormalAccount          = 0x0200
	UACInterdomainTrust       = 0x0800
	UACWorkstationTrust       = 0x1000
	UACServerTrust            = 0x2000
	UACDontExpirePassword     = 0x10000
	UACMNSLogonAccount        = 0x20000
	UACSmartcardRequired      = 0x40000
	UACTrustedForDelegation   = 0x80000
	UACNotDelegated           = 0x100000
	UACUseDESKeyOnly          = 0x200000
	UACDontRequirePreauth     = 0x400000
	UACPasswordExpired        = 0x800000
	UACTrustedToAuthForDeleg  = 0x1000000
)

// RootDSE returns the server's naming context (the base DN for searches).
func RootDSE(ctx context.Context, conn *LDAPConn) (string, error) {
	entries, err := conn.Search("", "(objectClass=*)", 0, []string{
		"defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
		"dnsHostName", "serverName",
	})
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if v, ok := e.Attrs["defaultnamingcontext"]; ok && len(v) > 0 {
			return v[0], nil
		}
	}
	return "", fmt.Errorf("adgo: no defaultNamingContext in RootDSE")
}

// DomainInfo pulls the domain object itself.
func DomainInfo(baseDN string, conn *LDAPConn) (LDAPEntry, error) {
	entries, err := conn.Search(baseDN, "(objectClass=domain)", 0, []string{
		"name", "distinguishedName", "objectSid", "ms-DS-MachineAccountQuota",
		"domainFunctionality", "forestFunctionality", "whenCreated",
	})
	if err != nil {
		return LDAPEntry{}, err
	}
	if len(entries) == 0 {
		return LDAPEntry{}, fmt.Errorf("adgo: no domain object")
	}
	return entries[0], nil
}

// UserFilter selects normal user accounts (excludes computers and trusts).
const UserFilter = "(&(objectCategory=person)(objectClass=user))"

// EnumerateUsers lists all user accounts with the fields that matter for
// follow-on attacks.
func EnumerateUsers(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	return conn.Search(baseDN, UserFilter, 2, []string{
		"samAccountName", "displayName", "mail", "userPrincipalName",
		"distinguishedName", "userAccountControl", "pwdLastSet",
		"lastLogonTimestamp", "servicePrincipalName", "memberOf",
		"description", "adminCount",
	})
}

// EnumerateGroups lists all groups.
func EnumerateGroups(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	return conn.Search(baseDN, "(objectCategory=group)", 2, []string{
		"name", "distinguishedName", "description", "member",
		"memberOf", "groupType", "adminCount",
	})
}

// EnumerateComputers lists all computer accounts.
func EnumerateComputers(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	return conn.Search(baseDN, "(objectCategory=computer)", 2, []string{
		"cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
		"lastLogonTimestamp", "userAccountControl", "servicePrincipalName",
		"distinguishedName", "memberOf",
	})
}

// EnumerateGPOs lists Group Policy Objects (name + path + version).
func EnumerateGPOs(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	// GPOs live in the Policies container under the domain
	base := "CN=Policies,CN=System," + baseDN
	return conn.Search(base, "(objectClass=groupPolicyContainer)", 2, []string{
		"displayName", "gPCFileSysPath", "versionNumber", "flags", "distinguishedName",
	})
}

// EnumerateTrusts lists domain trusts.
func EnumerateTrusts(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	base := "CN=System," + baseDN
	return conn.Search(base, "(objectClass=trustedDomain)", 2, []string{
		"name", "trustDirection", "trustType", "trustAttributes", "securityIdentifier",
	})
}

// EnumerateASREPRoastable finds users with DONT_REQ_PREAUTH set. These are
// AS-REP roastable — request a TGT without a session key and crack offline.
//
// LDAP bit-and query: (userAccountControl:1.2.840.113556.1.4.803:=4194304)
func EnumerateASREPRoastable(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	return conn.Search(baseDN, filter, 2, []string{
		"samAccountName", "distinguishedName", "userAccountControl", "servicePrincipalName",
	})
}

// EnumerateKerberoastable finds accounts with a servicePrincipalName set.
// These can be requested as a TGS and cracked offline.
func EnumerateKerberoastable(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
	return conn.Search(baseDN, filter, 2, []string{
		"samAccountName", "distinguishedName", "servicePrincipalName", "userAccountControl",
	})
}

// EnumerateUnconstrainedDelegation finds computers with
// TRUSTED_FOR_DELEGATION set. They can be coerced into authenticating
// to an attacker host and cache a TGT for the machine account.
func EnumerateUnconstrainedDelegation(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	filter := "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
	return conn.Search(baseDN, filter, 2, []string{
		"cn", "dNSHostName", "operatingSystem", "userAccountControl", "distinguishedName",
	})
}

// EnumeratePasswordNotRequired finds user accounts with PASSWD_NOTREQD set.
// Often overlooked — these users can have empty passwords.
func EnumeratePasswordNotRequired(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
	return conn.Search(baseDN, filter, 2, []string{
		"samAccountName", "distinguishedName", "userAccountControl",
	})
}

// EnumerateLAPS finds computers with the LAPS password attribute set (the
// query requires read access to ms-Mcs-AdmPwd).
func EnumerateLAPS(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	filter := "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))"
	return conn.Search(baseDN, filter, 2, []string{
		"cn", "dNSHostName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
	})
}

// EnumerateADCS finds Enterprise CA and certificate templates. Template
// misconfigurations (ESC1-ESC8) are the modern privesc path.
func EnumerateADCS(baseDN string, conn *LDAPConn) (cAs []LDAPEntry, templates []LDAPEntry, err error) {
	// CA is an object under CN=Certification Authorities under the configuration NC.
	// For simplicity, search under the domain first, then the config NC via a
	// second base DN the operator supplies.
	caFilter := "(objectClass=pKIEnrollmentService)"
	caBase := "CN=Certification Authorities,CN=Public Key Services,CN=Services," + configNCFromDomain(baseDN)
	cAs, _ = conn.Search(caBase, caFilter, 2, []string{
		"cn", "dNSHostName", "certificateTemplates", "distinguishedName",
	})
	tplBase := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + configNCFromDomain(baseDN)
	templates, err = conn.Search(tplBase, "(objectClass=pKICertificateTemplate)", 2, []string{
		"cn", "displayName", "msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage",
		"nTSecurityDescriptor", "distinguishedName",
	})
	return
}

// configNCFromDomain is a heuristic — real value comes from the RootDSE. The
// operator should pass the actual configurationNamingContext when calling
// EnumerateADCS with a config-DSE base.
func configNCFromDomain(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	var dc []string
	for _, p := range parts {
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			dc = append(dc, p)
		}
	}
	return "CN=Configuration," + strings.Join(dc, ",")
}

// FindDelegationRights finds principals with any of the "interesting"
// extended-rights GUIDs on other objects. Most useful are:
//   GenericAll          00299570-246d-11d0-a768-00aa006e0529
//   GenericWrite        00299570-246d-11d0-a768-00aa006e0529  (variant)
//   WriteDacl           (different GUID per ACE)
//   WriteOwner
//   ForceChangePassword 00299570-246d-11d0-a768-00aa006e0529
//   AllExtendedRights   00299570-246d-11d0-a768-00aa006e0529
//
// Rather than encode each GUID, the common move is to pull nTSecurityDescriptor
// on every object and post-process. This returns the raw descriptors.
func EnumerateDelegationDescriptors(baseDN string, conn *LDAPConn) ([]LDAPEntry, error) {
	return conn.Search(baseDN, "(objectClass=*)", 2, []string{
		"distinguishedName", "nTSecurityDescriptor",
	})
}
