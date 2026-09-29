// SOCKS5 server that fronts the tunnel manager. On receiving a CONNECT
// request, it opens a tunnel through a chosen agent and pipes bytes.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// AgentSender is the interface the SOCKS server uses to send tunnel control
// messages to the agent. The session.Manager implements this.
type AgentSender interface {
	// SendTunnelOpen asks the agent to dial host:port with the given tunnel ID.
	SendTunnelOpen(tunnelID, host string, port int) error
	// SendTunnelData pushes bytes to the agent for a tunnel.
	SendTunnelData(tunnelID string, data []byte, eof bool) error
	// SendTunnelClose tears down the tunnel on the agent.
	SendTunnelClose(tunnelID string, reason string) error
	// AgentID2 returns the agent the sender targets.
	AgentID2() string
}

// Server is a SOCKS5 listener that opens tunnels through the sender.
type Server struct {
	Bind    string // e.g. "127.0.0.1:1080"
	Sender  AgentSender
	Tunnels *Manager

	ln   net.Listener
	once sync.Once
}

// Start opens the listener and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Bind)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("[tunnel] SOCKS5 listening on %s -> agent %s", s.Bind, s.Sender.AgentID2())
	go func() {
		<-ctx.Done()
		s.Stop()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil
		}
		go s.handleSocksConn(c)
	}
}

// Stop closes the listener.
func (s *Server) Stop() {
	s.once.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
	})
}

// --- SOCKS5 wire handling ---

func (s *Server) handleSocksConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Greeting: version(1)=5, nmethods(1), methods(nmethods)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Reply: version(1)=5, method(1)=0 (no auth)
	c.Write([]byte{5, 0})

	// 2. Request: ver(1) cmd(1) rsv(1) atyp(1) addr dstport(2)
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 5 || req[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3: // domain
		bl := make([]byte, 1)
		io.ReadFull(c, bl)
		b := make([]byte, bl[0])
		io.ReadFull(c, b)
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	portb := make([]byte, 2)
	io.ReadFull(c, portb)
	port := int(binary.BigEndian.Uint16(portb))

	// 3. Open the tunnel through the agent.
	tunnelID := fmt.Sprintf("tun-%d", time.Now().UnixNano())
	tun := s.Tunnels.Register(tunnelID, host, port)
	if err := s.Sender.SendTunnelOpen(tunnelID, host, port); err != nil {
		s.Tunnels.Remove(tunnelID)
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// 4. Reply success. addr=0.0.0.0 port=0 (we don't know the real exit IP).
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})

	// 5. Bidirectional pipe: SOCKS client <-> tunnel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				_ = s.Sender.SendTunnelData(tunnelID, buf[:n], false)
			}
			if err != nil {
				_ = s.Sender.SendTunnelData(tunnelID, nil, true)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		for {
			n, err := tun.ReadFromAgent(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					_ = s.Sender.SendTunnelClose(tunnelID, "client closed")
					return
				}
			}
			if err != nil {
				select {
				case <-tun.Done():
				default:
				}
				return
			}
		}
	}()
	wg.Wait()
	s.Tunnels.Remove(tunnelID)
	_ = s.Sender.SendTunnelClose(tunnelID, "closed")
}

// ErrNoAgent is returned when the SOCKS server has no agent to tunnel through.
var ErrNoAgent = errors.New("tunnel: no agent available")

// SendAll opens a single tunnel and pipes the given stream, used by tests.
func (s *Server) SendAll(ctx context.Context, host string, port int, stream io.ReadWriter) error {
	if s.Sender == nil {
		return ErrNoAgent
	}
	tunnelID := fmt.Sprintf("tun-%d", time.Now().UnixNano())
	tun := s.Tunnels.Register(tunnelID, host, port)
	defer s.Tunnels.Remove(tunnelID)
	if err := s.Sender.SendTunnelOpen(tunnelID, host, port); err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				_ = s.Sender.SendTunnelData(tunnelID, buf[:n], false)
			}
			if err != nil {
				_ = s.Sender.SendTunnelData(tunnelID, nil, true)
				return
			}
		}
	}()
	buf := make([]byte, 16*1024)
	for {
		n, err := tun.ReadFromAgent(buf)
		if n > 0 {
			stream.Write(buf[:n])
		}
		if err != nil {
			return err
		}
	}
}

// SendToAgent is a helper exposed for the session manager to route messages.
type tunnelMsg struct {
	msg proto.MessageType
	raw []byte
}
