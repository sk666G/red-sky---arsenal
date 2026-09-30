package icsgo

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// loopbackModbus spins up a tiny TCP server that answers one Modbus
// request with the given response body, and returns the address to dial.
// The server captures the request bytes for inspection.
func loopbackModbus(t *testing.T, respond func(req []byte) []byte) (addr string, reqCh chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reqCh = make(chan []byte, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		// read MBAP header (7 bytes)
		hdr := make([]byte, 7)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		rlen := int(binary.BigEndian.Uint16(hdr[4:6]))
		if rlen < 2 {
			return
		}
		body := make([]byte, rlen-1)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		full := append(hdr, body...)
		reqCh <- full

		resp := respond(full)
		_, _ = conn.Write(resp)
	}()
	return ln.Addr().String(), reqCh
}

// splitHostPort is a tiny helper — splits "host:port".
func splitHP(addr string) (string, int) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			port := 0
			for _, c := range addr[i+1:] {
				port = port*10 + int(c-'0')
			}
			return addr[:i], port
		}
	}
	return addr, 0
}

// mkReadHoldingResp builds a valid read-holding-registers response body
// carrying the given registers.
func mkReadHoldingResp(unit uint8, regs []uint16) []byte {
	// PDU: fc(0x03) + bc(2*len) + regs BE
	pdu := make([]byte, 2+2*len(regs))
	pdu[0] = MBFuncReadHolding
	pdu[1] = byte(2 * len(regs))
	for i, r := range regs {
		binary.BigEndian.PutUint16(pdu[2+i*2:4+i*2], r)
	}
	return wrapMBAP(unit, pdu)
}

// mkReadCoilsResp builds a read-coils response with the given bit byte.
func mkReadCoilsResp(unit uint8, bitByte byte) []byte {
	pdu := []byte{MBFuncReadCoils, 0x01, bitByte}
	return wrapMBAP(unit, pdu)
}

// mkErrorResp builds an exception response.
func mkErrorResp(unit uint8, fc byte, code byte) []byte {
	pdu := []byte{fc | 0x80, code}
	return wrapMBAP(unit, pdu)
}

// wrapMBAP wraps a PDU in an MBAP header with a fixed txid (echoed back).
func wrapMBAP(unit uint8, pdu []byte) []byte {
	out := make([]byte, 7+len(pdu))
	// txid is echoed from request — the caller overwrites [0:2] if needed
	binary.BigEndian.PutUint16(out[4:6], uint16(len(pdu)+1))
	out[6] = unit
	copy(out[7:], pdu)
	return out
}

// echoTxID pulls the txid from the request and stuffs it into the response.
func echoTxID(req, resp []byte) []byte {
	if len(req) >= 2 && len(resp) >= 2 {
		resp[0] = req[0]
		resp[1] = req[1]
	}
	return resp
}

// TestModbusReadHoldingLoopback verifies the read-holding path end to end:
// request bytes on the wire match the spec, response registers decode back.
func TestModbusReadHoldingLoopback(t *testing.T) {
	addr, reqCh := loopbackModbus(t, func(req []byte) []byte {
		return echoTxID(req, mkReadHoldingResp(1, []uint16{0x1234, 0x5678}))
	})
	host, port := splitHP(addr)

	res, err := ModbusRead(MBOptions{Host: host, Port: port, Unit: 1},
		MBFuncReadHolding, 0x0010, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Exception != 0 {
		t.Fatalf("exception code %d", res.Exception)
	}
	if len(res.Regs) != 2 || res.Regs[0] != 0x1234 || res.Regs[1] != 0x5678 {
		t.Fatalf("registers wrong: %v", res.Regs)
	}

	// check the request bytes we sent
	req := <-reqCh
	// MBAP: proto=0, unit=1
	if binary.BigEndian.Uint16(req[2:4]) != 0 {
		t.Fatalf("protocol id not zero")
	}
	if req[6] != 1 {
		t.Fatalf("unit id = %d", req[6])
	}
	// PDU at offset 7: fc 0x03, start 0x0010, count 0x0002
	pdu := req[7:]
	want := []byte{0x03, 0x00, 0x10, 0x00, 0x02}
	if len(pdu) < 5 {
		t.Fatalf("pdu too short: %x", pdu)
	}
	for i := 0; i < 5; i++ {
		if pdu[i] != want[i] {
			t.Fatalf("pdu[%d] = 0x%02x, want 0x%02x", i, pdu[i], want[i])
		}
	}
}

// TestModbusReadCoilsLoopback verifies the coil bit unpacking.
func TestModbusReadCoilsLoopback(t *testing.T) {
	addr, _ := loopbackModbus(t, func(req []byte) []byte {
		// bit byte 0x05 = 0000 0101 LSB-first = bits[0]=1, bits[1]=0, bits[2]=1, rest 0
		return echoTxID(req, mkReadCoilsResp(1, 0x05))
	})
	host, port := splitHP(addr)

	res, err := ModbusRead(MBOptions{Host: host, Port: port, Unit: 1},
		MBFuncReadCoils, 0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bits) < 8 {
		t.Fatalf("bit count %d", len(res.Bits))
	}
	want := []bool{true, false, true, false, false, false, false, false}
	for i, w := range want {
		if res.Bits[i] != w {
			t.Fatalf("bit[%d] = %v, want %v (all: %v)", i, res.Bits[i], w, res.Bits[:8])
		}
	}
}

// TestModbusWriteCoilLoopback confirms the write-coil PDU shape.
func TestModbusWriteCoilLoopback(t *testing.T) {
	addr, reqCh := loopbackModbus(t, func(req []byte) []byte {
		// echo the write back
		resp := make([]byte, len(req))
		copy(resp, req)
		return resp
	})
	host, port := splitHP(addr)

	_, err := ModbusWriteCoil(MBOptions{Host: host, Port: port, Unit: 1}, 0x0020, true)
	if err != nil {
		t.Fatal(err)
	}
	req := <-reqCh
	pdu := req[7:]
	want := []byte{0x05, 0x00, 0x20, 0xFF, 0x00}
	if len(pdu) < 5 {
		t.Fatalf("pdu too short: %x", pdu)
	}
	for i := 0; i < 5; i++ {
		if pdu[i] != want[i] {
			t.Fatalf("pdu[%d] = 0x%02x, want 0x%02x (full pdu: %x)", i, pdu[i], want[i], pdu)
		}
	}
}

// TestModbusWriteRegisterLoopback confirms the single register write.
func TestModbusWriteRegisterLoopback(t *testing.T) {
	addr, reqCh := loopbackModbus(t, func(req []byte) []byte {
		resp := make([]byte, len(req))
		copy(resp, req)
		return resp
	})
	host, port := splitHP(addr)

	_, err := ModbusWriteRegister(MBOptions{Host: host, Port: port, Unit: 1}, 0x0010, 0xBEEF)
	if err != nil {
		t.Fatal(err)
	}
	req := <-reqCh
	pdu := req[7:]
	want := []byte{0x06, 0x00, 0x10, 0xBE, 0xEF}
	for i := 0; i < 5; i++ {
		if pdu[i] != want[i] {
			t.Fatalf("pdu[%d] = 0x%02x, want 0x%02x", i, pdu[i], want[i])
		}
	}
}

// TestModbusExceptionLoopback confirms exception handling.
func TestModbusExceptionLoopback(t *testing.T) {
	addr, _ := loopbackModbus(t, func(req []byte) []byte {
		return echoTxID(req, mkErrorResp(1, MBFuncReadHolding, 0x02)) // illegal data address
	})
	host, port := splitHP(addr)

	res, err := ModbusRead(MBOptions{Host: host, Port: port, Unit: 1},
		MBFuncReadHolding, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Exception != 0x02 {
		t.Fatalf("exception code %d, want 2", res.Exception)
	}
}

// TestFunctionCodes verifies the function code constants.
func TestFunctionCodes(t *testing.T) {
	cases := map[byte]string{
		MBFuncReadCoils:      "read coils",
		MBFuncReadDiscrete:   "read discrete",
		MBFuncReadHolding:    "read holding",
		MBFuncReadInput:      "read input",
		MBFuncWriteCoil:      "write coil",
		MBFuncWriteRegister:  "write register",
		MBFuncWriteMultiRegs: "write multi regs",
	}
	expected := map[byte]byte{
		MBFuncReadCoils:      0x01,
		MBFuncReadDiscrete:   0x02,
		MBFuncReadHolding:    0x03,
		MBFuncReadInput:      0x04,
		MBFuncWriteCoil:      0x05,
		MBFuncWriteRegister:  0x06,
		MBFuncWriteMultiRegs: 0x10,
	}
	for code, label := range cases {
		if want, ok := expected[code]; !ok || code != want {
			t.Fatalf("%s = 0x%02x (unexpected)", label, code)
		}
	}
}

// TestModbusReadRejectsBadFunction confirms the guard.
func TestModbusReadRejectsBadFunction(t *testing.T) {
	_, err := ModbusRead(MBOptions{Host: "127.0.0.1", Port: 1, Unit: 1},
		0x99, 0, 1)
	if err == nil {
		t.Fatalf("expected error for bad function code")
	}
}

// TestModbusWriteMultiRegsRejectsTooMany confirms the 123-register limit.
func TestModbusWriteMultiRegsRejectsTooMany(t *testing.T) {
	values := make([]uint16, 200)
	_, err := ModbusWriteMultiRegs(MBOptions{Host: "127.0.0.1", Port: 1, Unit: 1}, 0, values)
	if err == nil {
		t.Fatalf("expected error for 200-register write")
	}
}
