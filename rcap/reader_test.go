package rcap

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func makeReader(t *testing.T) *Reader {
	var err error

	reader := &Reader{}
	reader.handle, err = pcap.OpenOffline("testdata/sample.pcap")

	if err != nil {
		t.Fatalf("failed to make Reader for test: %v", err)
	}

	return reader
}

func TestNewReader(t *testing.T) {
	c := makeConfig()

	// OpenLive function in NewReader requires root privilege,
	// so the following call fails.
	if _, err := NewReader(c); err == nil {
		t.Errorf("err is expected, but got '%v'.", err)
	}

	// Instead, openAndSetUpReader internal function is ready
	// to test with a pcap file.
	c.Rcap.BpfRules = "ip"
	if _, err := openAndSetUpReader(c, "testdata/sample.pcap"); err != nil {
		t.Errorf("'%v' is expected, but got '%v'.", nil, err)
	}

	// file not found
	if _, err := openAndSetUpReader(c, "testdata/not-found.pcap"); err == nil {
		t.Errorf("err is expected, but got '%v'.", err)
	}

	// invalid BPF
	c.Rcap.BpfRules = "invalid bpf"
	if _, err := openAndSetUpReader(c, "testdata/sample.pcap"); err == nil {
		t.Errorf("err is expected, but got '%v'.", err)
	}
}

func TestReaderLinkType(t *testing.T) {
	r := makeReader(t)
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("'%v' is expected, but got '%v'.", layers.LinkTypeEthernet, r.LinkType())
	}
}

func TestReaderNumPackets(t *testing.T) {
	r := &Reader{}

	if r.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, r.NumPackets())
	}
}

func TestReaderResetNumPackets(t *testing.T) {
	r := &Reader{numPackets: 5}
	if r.NumPackets() != 5 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 5, r.NumPackets())
	}

	r.ResetNumPackets()
	if r.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, r.NumPackets())
	}
}

func TestReaderReadPacket(t *testing.T) {
	r := makeReader(t)

	expectedPayload := []byte("this is a test packet.\n")
	expectedTime := int64(1688205150)
	data, capinfo, err := r.ReadPacket() // first packet

	// compare payloads only.
	payload := data[len(data)-len(expectedPayload):]
	if !cmp.Equal(payload, expectedPayload) {
		t.Errorf("'%v' is expected, but got '%v'.", expectedPayload, payload)
	}
	if capinfo.Timestamp.Unix() != expectedTime {
		t.Errorf("'%v' is expected, but got '%v'.", expectedTime, capinfo.Timestamp)
	}
	if err != nil {
		t.Errorf("'%v' is expected, but got '%v'.", nil, err)
	}

	_, _, err = r.ReadPacket() // second packet (EOF)
	if err == nil {
		t.Errorf("err is expected, but got '%v'.", nil)
	}
}

func TestReaderClose(t *testing.T) {
	r := makeReader(t)
	r.Close()
}
