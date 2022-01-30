package rcap

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestNumPackets(t *testing.T) {
	writer := &Writer{}

	if writer.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, writer.NumPackets())
	}
}

func TestShouldRotateWithIntervalZero(t *testing.T) {
	// Interval = 0 , Offset = 0 -> Always false
	config := &Config{Rcap: RcapConfig{Interval: 0}}
	writer := &Writer{config: config}

	for i := int64(86401); i <= 86400+120; i++ {
		if writer.shouldRotate(i) != false {
			t.Errorf("'false' is expected, but got 'true'")
		}
	}
}

func TestShouldRotateWithoutOffset(t *testing.T) {
	// Interval = 60 , Offset = 0
	// -> true if i == 60, 120, ..., otherwise false
	// NOTE: false if i == 60 because of ts == writer.lastRotTime == 0.
	config := &Config{Rcap: RcapConfig{Interval: 60}}
	writer := &Writer{config: config}

	for i := int64(86401); i <= 86400+150; i++ {
		if i == 86401 || i == 86400+60 || i == 86400+120 {
			if writer.shouldRotate(i) != true {
				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
			}
		} else {
			if writer.shouldRotate(i) != false {
				t.Errorf("'false' is expected, but got 'true' (ts=%d)", i)
			}
		}

		if writer.shouldRotate(i) {
			writer.updateLastRotTime(i)
		}
	}
}

func TestShouldRotateWithOffset(t *testing.T) {
	// Interval = 60 , Offset = 30
	// -> true if i == 30, 90, ..., otherwise false
	config := &Config{Rcap: RcapConfig{Interval: 60, Offset: 30}}
	writer := &Writer{config: config}

	for i := int64(86401); i <= 86400+120; i++ {
		if i == 86401 || i == 86400+30 || i == 86400+90 {
			if writer.shouldRotate(i) != true {
				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
			}
		} else {
			if writer.shouldRotate(i) != false {
				t.Errorf("'false' is expected, but got 'true' (ts=%d).", i)
			}
		}

		if writer.shouldRotate(i) {
			writer.updateLastRotTime(i)
		}
	}
}

func TestShouldRotateDailyWithOffset(t *testing.T) {
	// Interval = 86400 , Offset = 54000
	// -> true if i == 54000, 140400, ..., otherwise false
	config := &Config{Rcap: RcapConfig{Interval: 86400, Offset: 54000}}
	writer := &Writer{config: config}

	for i := int64(86401); i <= 86400+86400*2; i++ {
		if i == 86401 || i == (86400*2-32400) || i == (86400*3-32400) {
			if writer.shouldRotate(i) != true {
				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
			}
		} else {
			if writer.shouldRotate(i) != false {
				t.Errorf("'false' is expected, but got 'true' (ts=%d)", i)
			}
		}

		if writer.shouldRotate(i) {
			writer.updateLastRotTime(i)
		}
	}
}

func TestNewFileName(t *testing.T) {
	var config *Config
	var writer *Writer
	var loc *time.Location

	// Base test.
	loc, _ = time.LoadLocation("UTC")
	config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S.txt", Location: loc}}
	writer = &Writer{config: config}

	if fileName := writer.newFileName(0); fileName != "testdata/19700101000000.txt" {
		t.Errorf("'testdata/19700101000000.txt' is expected, but got '%v'", fileName)
	}

	// Location test.
	loc, _ = time.LoadLocation("Asia/Tokyo")
	config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S.txt", Location: loc}}
	writer = &Writer{config: config}

	if fileName := writer.newFileName(0); fileName != "testdata/19700101090000.txt" {
		t.Errorf("'testdata/19700101090000.txt' is expected, but got '%v'", fileName)
	}

	// Alternative filename test.
	loc, _ = time.LoadLocation("UTC")
	config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S-data.txt", Location: loc}}
	writer = &Writer{config: config}

	if fileName := writer.newFileName(0); fileName != "testdata/19700101000000-data-2.txt" {
		t.Errorf("'testdata/19700101000000-data-2.txt' is expected, but got '%v'", fileName)
	}
}

func removeFile(filename string) error {
	if FileExists(filename) {
		return os.Remove(filename)
	} else {
		return nil
	}
}

func removeTestUpdateFiles() {
	removeFile("testdata/test-19700101000100.pcap")
	removeFile("testdata/test-19700101000200.pcap")
}

func TestUpdate(t *testing.T) {
	removeTestUpdateFiles()
	defer removeTestUpdateFiles()

	loc, _ := time.LoadLocation("UTC")
	config := &Config{Rcap: RcapConfig{Interval: 60, FileFmt: "testdata/test-%Y%m%d%H%M%S.pcap", Location: loc}}
	writer := &Writer{config: config, linkType: layers.LinkTypeEthernet}

	// First time.
	writer.Update(60)

	if writer.lastRotTime != 60 {
		t.Errorf("'%v' is expected, but got '%v'", 60, writer.lastRotTime)
	}
	if FileExists("testdata/test-19700101000100.pcap") != true {
		t.Errorf("'testdata/test-19700101000100.pcap' must be created, but not found")
	}

	// Update (nothing happens)
	writer.Update(90)

	// Update (file rotated)
	writer.Update(120)

	if writer.lastRotTime != 120 {
		t.Errorf("'%v' is expected, but got '%v'", 120, writer.lastRotTime)
	}
	if FileExists("testdata/test-19700101000200.pcap") != true {
		t.Errorf("'testdata/test-19700101000200.pcap' must be created, but not found")
	}
}

func TestWritePacket(t *testing.T) {
	// stub...
}

func TestClose(t *testing.T) {
	// stub...
}
