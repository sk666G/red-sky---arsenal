// pcap writer — global pcap file format, magic 0xa1b2c3d4 (microsecond timestamps).
// Compatible with Wireshark, tcpdump, any pcap reader.
package capturer

import (
	"bufio"
	"encoding/binary"
	"os"
	"sync"
)

// PCAPWriter writes Ethernet frames to a libpcap-format file.
type PCAPWriter struct {
	f   *os.File
	w   *bufio.Writer
	mu  sync.Mutex
	n   int
	byt int64
}

// NewPCAPWriter opens path for writing and emits the pcap file header.
func NewPCAPWriter(path string) (*PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	p := &PCAPWriter{f: f, w: bufio.NewWriter(f)}
	// Global header (24 bytes)
	// magic(4)=0xa1b2c3d4, ver_major(2)=2, ver_minor(2)=4,
	// thiszone(4)=0, sigfigs(4)=0, snaplen(4)=65535, network(4)=1 (Ethernet)
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1) // LINKTYPE_ETHERNET
	if _, err := p.w.Write(hdr[:]); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}

// WriteFrame appends one frame record.
func (p *PCAPWriter) WriteFrame(f Frame) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sec := uint32(f.TS.Unix())
	usec := uint32(f.TS.Nanosecond() / 1000)
	// record header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
	var rh [16]byte
	binary.LittleEndian.PutUint32(rh[0:4], sec)
	binary.LittleEndian.PutUint32(rh[4:8], usec)
	binary.LittleEndian.PutUint32(rh[8:12], uint32(len(f.Data)))
	orig := f.OrigLen
	if orig == 0 {
		orig = len(f.Data)
	}
	binary.LittleEndian.PutUint32(rh[12:16], uint32(orig))
	if _, err := p.w.Write(rh[:]); err != nil {
		return err
	}
	if _, err := p.w.Write(f.Data); err != nil {
		return err
	}
	p.n++
	p.byt += int64(len(f.Data))
	return nil
}

// Close flushes and closes the file.
func (p *PCAPWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.w.Flush(); err != nil {
		p.f.Close()
		return err
	}
	return p.f.Close()
}

// Count returns the number of frames written.
func (p *PCAPWriter) Count() int { return p.n }

// Bytes returns the total bytes of frame data written.
func (p *PCAPWriter) Bytes() int64 { return p.byt }
