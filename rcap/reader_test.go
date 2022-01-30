package rcap

import (
	"testing"
)

func TestReader(t *testing.T) {
	// TODO
	// Root required.
}

func TestReaderNumPackets(t *testing.T) {
	reader := &Reader{}

	if reader.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, reader.NumPackets())
	}
}

func TestReaderResetNumPackets(t *testing.T) {
	reader := &Reader{numPackets: 5}

	if reader.NumPackets() != 5 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 5, reader.NumPackets())
	}

	reader.ResetNumPackets()

	if reader.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, reader.NumPackets())
	}
}

func TestReadPacket(t *testing.T) {
	// TODO
	// Root required.
}

func TestReaderClose(t *testing.T) {
	// TODO
	// Root required.
}
