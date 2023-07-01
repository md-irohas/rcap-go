package rcap

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func makeReader() *Reader {
	reader := &Reader{}
	reader.handle, _ = pcap.OpenOffline("testdata/sample.pcap")
	return reader
}

func TestNewReader(t *testing.T) {
	c := makeConfig()

	if _, err := NewReader(c); err == nil {
		t.Errorf("err is expected, but got '%v'.", err)
	}
}

func TestReaderLinkType(t *testing.T) {
	r := makeReader()
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
	r := makeReader()

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
	r := makeReader()
	r.Close()
}
