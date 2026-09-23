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
type Task struct {
	ID      string   `json:"id"`
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
