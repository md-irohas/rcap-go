package rcap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

type Reader struct {
	config     *Config
	handle     *pcap.Handle
	numPackets uint
}

// NewReader creates a new struct Reader. This function calls pcap.OpenLive and
// applies SetBPFFilter method to the returned handle based on the given Config
// struct.
func NewReader(config *Config) (*Reader, error) {
	c := &config.Rcap

	handle, err := pcap.OpenLive(c.Device, int32(c.SnapLen), c.Promisc, time.Duration(c.ToMs)*time.Millisecond)
	if err != nil {
		return nil, err
	}

	if c.BpfRules != "" {
		err := handle.SetBPFFilter(c.BpfRules)
		if err != nil {
			return nil, err
		}
	}

	log.Printf("open interface: %v (linktype: %v)", c.Device, handle.LinkType())
	log.Printf("set bpf rule: %v", c.BpfRules)

	reader := &Reader{
		config:     config,
		handle:     handle,
		numPackets: 0,
	}

	return reader, nil
}

// LinkType returns the layers.LinkType of the interface.
func (r *Reader) LinkType() layers.LinkType {
	return r.handle.LinkType()
}

// NumPackets returns the number of packets read from the packet source.
func (r *Reader) NumPackets() uint {
	return r.numPackets
}

// ResetNumPackets resets NumPackets to 0.
func (r *Reader) ResetNumPackets() {
	r.numPackets = 0
}

// ReadPacket returns a packet data with the same format as
// ZeroCopyReadPacketData.
func (r *Reader) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	data, capinfo, pkterr := r.handle.ZeroCopyReadPacketData()

	if pkterr == nil {
		r.numPackets++
	}

	return data, capinfo, pkterr
}

// Close closes the handle.
func (r *Reader) Close() error {
	r.handle.Close()
	return nil
}
