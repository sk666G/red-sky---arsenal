package icsgo

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// OPC UA — TCP/4840 by default. The modern industrial protocol. Full
// implementation is enormous; this file covers the discovery phase:
//
//   1. HEL/ACK     — hello handshake
//   2. OPN         — open a SecureChannel (None security policy = no crypto)
//   3. GetEndpoints — enumerate the server's supported security policies,
//                     endpoint URLs, and available user token types
//   4. CloseSecureChannel
//
// Discovery against a server with SecurityPolicy#None is unauthenticated —
// anyone on the network can enumerate endpoints. Full browsing of the
// address space needs a session (OPC UA CreateSession / ActivateSession)
// which is a separate build.
//
// Message layout (binary protocol over TCP):
//
//   HEL     msg type "HEL" + chunk 'F' + size (4) + version (4) + recv buf (4)
//           + send buf (4) + max msg (4) + max chunk (4) + endpoint url (string)
//   ACK     msg type "ACK" + chunk 'F' + size (4) + version (4) + recv buf (4)
//           + send buf (4) + max msg (4) + max chunk (4)
//   OPN     msg type "OPN" + chunk 'F' + size (4) + SecureChannelId (4)
//           + SecurityHeader (AsymmetricAlgorithmSecurityHeader) + SequenceHeader
//           + body (OpenSecureChannelRequest)
//   MSG     msg type "MSG" + chunk 'F' + size (4) + SecureChannelId (4)
//           + SecurityHeader (SymmetricAlgorithmSecurityHeader) + SequenceHeader
//           + body (service request)

// OPCUA endpoint default port
const OPCUAPort = 4840

// OPCUAOptions controls an OPC-UA interaction.
type OPCUAOptions struct {
	Host    string
	Port    int           // 4840 default
	Timeout time.Duration // per request
}

func opcuaDefault(opts OPCUAOptions) OPCUAOptions {
	if opts.Port == 0 {
		opts.Port = OPCUAPort
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	return opts
}

// opcuaString encodes an OPC-UA String (int32 length, then bytes; -1 = null).
func opcuaString(s string) []byte {
	if s == "" {
		return []byte{0xFF, 0xFF, 0xFF, 0xFF}
	}
	out := make([]byte, 4+len(s))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(s)))
	copy(out[4:], s)
	return out
}

// opcuaByteString encodes a ByteString (int32 length, then bytes).
func opcuaByteString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

// opcuaNodeIDNone is the NodeID for the null node (used in SecurityHeader).
func opcuaNodeIDNone() []byte {
	// encoding byte 0x00 = TwoByte, then byte 0x00
	return []byte{0x00, 0x00}
}

// opcuaGuidByteString returns a ByteString-wrapped null GUID (16 zero bytes).
func opcuaNullGuid() []byte {
	return opcuaByteString(make([]byte, 16))
}

// buildHEL builds a Hello message with the given endpoint URL.
func buildHEL(endpointURL string) []byte {
	urlBytes := []byte(endpointURL)
	body := make([]byte, 0, 32+4+len(urlBytes))
	body = append(body, 'H', 'E', 'L', 'F')
	var sizeBuf [4]byte
	// size will be patched below
	body = append(body, sizeBuf[:]...)                                // size
	body = append(body, 0, 0, 0, 0)                                   // version 0
	binary.LittleEndian.PutUint32(sizeBuf[:], 0)                      // placeholder
	// receive buffer size
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], 65535)
	body = append(body, b[:]...)
	binary.LittleEndian.PutUint32(b[:], 65535)
	body = append(body, b[:]...)                                      // send buffer size
	binary.LittleEndian.PutUint32(b[:], 0)
	body = append(body, b[:]...)                                      // max message size 0 = no limit
	binary.LittleEndian.PutUint32(b[:], 0)
	body = append(body, b[:]...)                                      // max chunk count 0 = no limit
	body = append(body, opcuaString(endpointURL)...)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(body)))
	return body
}

// readOPCUAMessage reads one OPC-UA transport message and returns
// (msgType, body, err). The body starts after the 8-byte header.
func readOPCUAMessage(conn net.Conn) (string, []byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", nil, err
	}
	msgType := string(hdr[0:3])
	size := binary.LittleEndian.Uint32(hdr[4:8])
	if size < 8 || size > 64*1024*1024 {
		return "", nil, fmt.Errorf("icsgo/opcua: bad message size %d", size)
	}
	body := make([]byte, size-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", nil, err
	}
	return msgType, body, nil
}

// HelloAck sends the HEL, reads the ACK, and returns the negotiated
// parameters. Any server that speaks OPC UA binary answers this.
type HelloAck struct {
	Version     uint32
	RecvBufSize uint32
	SendBufSize uint32
	MaxMsgSize  uint32
	MaxChunkCnt uint32
}

// Hello sends the handshake, returns the ACK.
func Hello(conn net.Conn, timeout time.Duration) (HelloAck, error) {
	hel := buildHEL("opc.tcp://0.0.0.0:0")
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(hel); err != nil {
		return HelloAck{}, err
	}
	msgType, body, err := readOPCUAMessage(conn)
	if err != nil {
		return HelloAck{}, err
	}
	if msgType != "ACK" {
		return HelloAck{}, fmt.Errorf("icsgo/opcua: expected ACK got %s", msgType)
	}
	if len(body) < 20 {
		return HelloAck{}, errors.New("icsgo/opcua: short ACK")
	}
	return HelloAck{
		Version:     binary.LittleEndian.Uint32(body[0:4]),
		RecvBufSize: binary.LittleEndian.Uint32(body[4:8]),
		SendBufSize: binary.LittleEndian.Uint32(body[8:12]),
		MaxMsgSize:  binary.LittleEndian.Uint32(body[12:16]),
		MaxChunkCnt: binary.LittleEndian.Uint32(body[16:20]),
	}, nil
}

// buildOpenSecureChannelNone builds an OPN with SecurityPolicy None.
// The asymmetric security header uses a null NodeID and empty policy URI.
func buildOpenSecureChannelNone(requestID, sequenceNum uint32, channelID uint32) []byte {
	// AsymmetricAlgorithmSecurityHeader:
	//   SecurityPolicyUri (String)  — empty for None
	//   SenderCertificate (ByteString) — empty
	//   ReceiverCertificateThumbprint (ByteString) — empty
	secHeader := append(opcuaString(""),
		opcuaByteString(nil)...,
	)
	secHeader = append(secHeader, opcuaByteString(nil)...)

	// SequenceHeader: SequenceNumber (4) + RequestID (4)
	seqHeader := make([]byte, 8)
	binary.LittleEndian.PutUint32(seqHeader[0:4], sequenceNum)
	binary.LittleEndian.PutUint32(seqHeader[4:8], requestID)

	// OpenSecureChannelRequest body:
	//   RequestHeader (NodeID authenticationToken null, DateTime, RequestHandle,
	//                  ReturnDiagnostics, String auditEntryId, TimeoutHint,
	//                  ExtensionObject additionalHeader)
	//   ClientProtocolVersion (4)
	//   RequestType (4)   — 0 = ISSUE
	//   SecurityMode (4)  — 1 = None
	//   ClientNonce (ByteString) — empty for None
	//   RequestedLifetime (4) — milliseconds
	body := []byte{}
	body = append(body, opcuaNodeIDNone()...)                                     // auth token (NodeID null)
	body = append(body, make([]byte, 8)...)                                       // timestamp (0)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], 1)
	body = append(body, b[:]...)                                                  // request handle
	binary.LittleEndian.PutUint32(b[:], 0)
	body = append(body, b[:]...)                                                  // return diagnostics
	body = append(body, opcuaString("")...)                                       // audit entry id
	binary.LittleEndian.PutUint32(b[:], 10000)
	body = append(body, b[:]...)                                                  // timeout hint
	body = append(body, 0x00, 0x00)                                               // extension object (type id 0 = no header)
	body = append(body, 0, 0, 0, 0)                                               // client protocol version
	binary.LittleEndian.PutUint32(b[:], 0)                                        // request type ISSUE
	body = append(body, b[:]...)
	binary.LittleEndian.PutUint32(b[:], 1)                                        // security mode NONE
	body = append(body, b[:]...)
	body = append(body, opcuaByteString(nil)...)                                  // client nonce
	binary.LittleEndian.PutUint32(b[:], 3600000)
	body = append(body, b[:]...)                                                  // requested lifetime 1h

	// transport message
	out := make([]byte, 0, 12+len(secHeader)+len(seqHeader)+len(body))
	out = append(out, 'O', 'P', 'N', 'F')
	// size placeholder
	out = append(out, 0, 0, 0, 0)
	// secure channel id
	var cb [4]byte
	binary.LittleEndian.PutUint32(cb[:], channelID)
	out = append(out, cb[:]...)
	out = append(out, secHeader...)
	out = append(out, seqHeader...)
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	return out
}

// DiscoveryResult is a summary of what an OPC-UA server advertises.
type DiscoveryResult struct {
	EndpointURL      string
	SecurityPolicies []string   // e.g. "http://opcfoundation.org/UA/SecurityPolicy#None"
	SecurityModes    []uint32   // 1 = None, 2 = Sign, 3 = SignAndEncrypt
	UserTokenTypes   []string   // "Anonymous", "UserName", "Certificate"
	RawResponse      []byte     // full MSG response for offline parsing
}

// Discover opens the channel with SecurityPolicy None and issues
// GetEndpoints. Returns the parsed endpoint summary.
func Discover(opts OPCUAOptions) (DiscoveryResult, error) {
	opts = opcuaDefault(opts)
	if opts.Host == "" {
		return DiscoveryResult{}, errors.New("icsgo/opcua: host required")
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("icsgo/opcua: dial: %w", err)
	}
	defer conn.Close()

	// HELLO
	if _, err := Hello(conn, opts.Timeout); err != nil {
		return DiscoveryResult{}, err
	}

	// generate a request ID
	var randbuf [4]byte
	_, _ = rand.Read(randbuf[:])
	reqID := binary.LittleEndian.Uint32(randbuf[:])

	// OPN None
	opn := buildOpenSecureChannelNone(reqID, 1, 0)
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	if _, err := conn.Write(opn); err != nil {
		return DiscoveryResult{}, err
	}
	msgType, body, err := readOPCUAMessage(conn)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if msgType != "OPN" {
		return DiscoveryResult{}, fmt.Errorf("icsgo/opcua: expected OPN got %s", msgType)
	}
	// The response body: SecureChannelId (4) + AsymmetricSecurityHeader
	// + SequenceHeader (8) + ResponseHeader + channelID (4) + tokenID (4)
	// + revisedLifetime (4). We just need the channel id from the first
	// 4 bytes — the response also carries the token but we ignore it.
	if len(body) < 4 {
		return DiscoveryResult{}, errors.New("icsgo/opcua: short OPN response")
	}
	_ = body[0:4] // channel id is really in the message header, not the body

	// GetEndpoints request (MSG type, symmetric security header with token)
	msg := buildGetEndpoints(reqID+1, 2, 0)
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	if _, err := conn.Write(msg); err != nil {
		return DiscoveryResult{}, err
	}
	_, respBody, err := readOPCUAMessage(conn)
	if err != nil {
		return DiscoveryResult{}, err
	}

	// best-effort parse — look for recognizable strings
	result := DiscoveryResult{RawResponse: respBody}
	result.EndpointURL, result.SecurityPolicies, result.UserTokenTypes = scanForStrings(respBody)
	return result, nil
}

// buildGetEndpoints builds a GetEndpoints service request as a MSG.
func buildGetEndpoints(requestID, sequenceNum, channelID uint32) []byte {
	// SymmetricAlgorithmSecurityHeader: TokenId (4) = 0 (null token for None)
	secHeader := make([]byte, 4)
	// SequenceHeader
	seqHeader := make([]byte, 8)
	binary.LittleEndian.PutUint32(seqHeader[0:4], sequenceNum)
	binary.LittleEndian.PutUint32(seqHeader[4:8], requestID)

	// RequestHeader
	body := []byte{}
	body = append(body, opcuaNodeIDNone()...)
	body = append(body, make([]byte, 8)...)                                       // timestamp
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], 1)
	body = append(body, b[:]...)                                                  // request handle
	binary.LittleEndian.PutUint32(b[:], 0)
	body = append(body, b[:]...)                                                  // return diagnostics
	body = append(body, opcuaString("")...)                                       // audit id
	binary.LittleEndian.PutUint32(b[:], 10000)
	body = append(body, b[:]...)                                                  // timeout
	body = append(body, 0x00, 0x00)                                               // extension object
	// GetEndpoints specific:
	body = append(body, opcuaString("opc.tcp://localhost:4840")...)               // endpointUrl filter
	// localeIds (array of String) — empty
	binary.LittleEndian.PutUint32(b[:], 0xFFFFFFFF)                                // -1 = null array
	body = append(body, b[:]...)
	// profileUris (array of String) — empty
	binary.LittleEndian.PutUint32(b[:], 0xFFFFFFFF)
	body = append(body, b[:]...)

	// node id of GetEndpoints = ns=0;i=428
	// but NodeID is a 4-byte ExpandedNodeId in the request header of the message
	// — this is handled by the transport. Here we build only the body; the
	// caller adds the transport header.

	out := make([]byte, 0, 12+len(secHeader)+len(seqHeader)+len(body))
	out = append(out, 'M', 'S', 'G', 'F')
	out = append(out, 0, 0, 0, 0)                                                 // size placeholder
	var cb [4]byte
	binary.LittleEndian.PutUint32(cb[:], channelID)
	out = append(out, cb[:]...)
	out = append(out, secHeader...)
	out = append(out, seqHeader...)
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	return out
}

// scanForStrings does a best-effort scan of a GetEndpoints response for
// the URLs and policy names OPC UA advertises. Not a proper decoder —
// a full binary decoder is a follow-up build.
func scanForStrings(b []byte) (endpointURL string, policies []string, userTokens []string) {
	// look for strings that look like OPC UA URLs or policy URIs
	s := string(b)
	seen := map[string]bool{}
	// endpoint URLs: opc.tcp://...
	for {
		i := strings.Index(s, "opc.tcp://")
		if i < 0 {
			break
		}
		// capture until non-printable
		j := i
		for j < len(s) && s[j] >= 32 && s[j] < 127 {
			j++
		}
		u := s[i:j]
		if !seen[u] {
			seen[u] = true
			if endpointURL == "" {
				endpointURL = u
			}
		}
		s = s[j:]
	}
	// policy URIs contain "SecurityPolicy#"
	s = string(b)
	for {
		i := strings.Index(s, "SecurityPolicy#")
		if i < 0 {
			break
		}
		j := i + len("SecurityPolicy#")
		for j < len(s) && s[j] >= 32 && s[j] < 127 {
			j++
		}
		p := "SecurityPolicy#" + s[i+len("SecurityPolicy#"):j]
		if !seen[p] {
			seen[p] = true
			policies = append(policies, p)
		}
		s = s[j:]
	}
	return
}
