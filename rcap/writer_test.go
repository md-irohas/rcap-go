package rcap

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewWriter(t *testing.T) {
	c := makeConfig()
	if _, err := NewWriter(c, layers.LinkTypeEthernet); err != nil {
		t.Errorf("nil is expected, but got '%v'.", err)
	}
}

func TestWriterNumPackets(t *testing.T) {
	writer := &Writer{}

	if writer.NumPackets() != 0 {
		t.Errorf("'%#v' is expected, but got '%#v'.", 0, writer.NumPackets())
	}
}

func TestWriterShouldRotate(t *testing.T) {
	config := &Config{Rcap: RcapConfig{Interval: 0}}
	writer := &Writer{config: config}

	// 86400: 1970-01-02T00:00:00+00
	for ts := int64(86400); ts <= 86400+86400+120; ts++ {
		if writer.shouldRotate(ts) != false {
			t.Errorf("'false' is expected, but got 'true'")
		}
	}

	config = &Config{Rcap: RcapConfig{Interval: 60}}
	writer = &Writer{config: config, lastRotTime: 86400}

	// 86400: 1970-01-02T00:00:00+00
	for ts := int64(86400); ts <= 86400+90; ts++ {
		if ts < 86460 {
			if writer.shouldRotate(ts) != false {
				t.Errorf("'false' is expected, but got 'true': ts=%v", ts)
			}
		} else {
			if writer.shouldRotate(ts) != true {
				t.Errorf("'true' is expected, but got 'false': ts=%v", ts)
			}
		}
	}
}

func TestCalcFirstRotTime(t *testing.T) {
	// without UTCOffset
	interval := int64(60)
	offset, _ := time.ParseDuration("0")

	for ts := int64(86400); ts < 86400+150; ts++ {
		if ts < 86400+60 {
			var expected int64 = 86400
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+60+60 {
			var expected int64 = 86400 + 60
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+60+60+60 {
			var expected int64 = 86400 + 60 + 60
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}

	// with UTCOffset
	interval = int64(60)
	offset, _ = time.ParseDuration("30s")

	for ts := int64(86400); ts < 86400+150; ts++ {
		if ts < 86400+30 {
			var expected int64 = 86400 - 30
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+30+60 {
			var expected int64 = 86400 + 30
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+30+60+60 {
			var expected int64 = 86400 + 30 + 60
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}

	// with UTCOffset (daily, JST)
	interval = int64(86400) // 1970-01-02T09:00:00+09
	offset, _ = time.ParseDuration("9h")

	for ts := int64(86400); ts < 86400+86400+86400; ts++ {
		if ts < 140400 {
			// < 1970-01-03T00:00:00+09
			var expected int64 = 140400 - 86400 // 1970-01-02T00:00:00+09
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 140400+86400 {
			// < 1970-01-04T00:00:00+09
			var expected int64 = 140400 // 1970-01-03T00:00:00+09
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 140400+86400+86400 {
			// < 1970-01-05T00:00:00+09
			var expected int64 = 140400 + 86400 // 1970-01-04T00:00:00+09
			if rotTime := calcFirstRotTime(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}
}

func TestCalcFirstRotTimeWithOffset(t *testing.T) {
	// without offset
	interval := int64(60)
	offset := int64(0)

	for ts := int64(86400); ts < 86400+150; ts++ {
		if ts < 86400+60 {
			var expected int64 = 86400
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+60+60 {
			var expected int64 = 86400 + 60
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+60+60+60 {
			var expected int64 = 86400 + 60 + 60
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}

	// with offset
	interval = int64(60)
	offset = int64(30)

	for ts := int64(86400); ts < 86400+150; ts++ {
		if ts < 86400+30 {
			var expected int64 = 86400 - 30
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v' (ts=%v).", expected, rotTime, ts)
			}
		} else if ts < 86400+30+60 {
			var expected int64 = 86400 + 30
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 86400+30+60+60 {
			var expected int64 = 86400 + 30 + 60
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}

	// with offset (daily, JST)
	interval = int64(86400) // 1970-01-02T09:00:00+09
	offset = int64(54000)

	for ts := int64(86400); ts < 86400+86400+86400; ts++ {
		if ts < 140400 {
			// < 1970-01-03T00:00:00+09
			var expected int64 = 140400 - 86400 // 1970-01-02T00:00:00+09
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 140400+86400 {
			// < 1970-01-04T00:00:00+09
			var expected int64 = 140400 // 1970-01-03T00:00:00+09
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else if ts < 140400+86400+86400 {
			// < 1970-01-05T00:00:00+09
			var expected int64 = 140400 + 86400 // 1970-01-04T00:00:00+09
			if rotTime := calcFirstRotTimeWithOffset(ts, interval, offset); rotTime != expected {
				t.Errorf("'%v' is expected, but got '%v'.", expected, rotTime)
			}
		} else {
			t.Fatalf("unreachable code.")
		}
	}
}

func TestWriterPrintRotLog(t *testing.T) {
	c := makeConfig()
	w := &Writer{config: c}
	w.PrintRotLog()
}

func TestMakeFileName(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")

	cases := []struct {
		// in
		format   string
		doAppend bool
		// out
		filename string
	}{
		{"testdata/%Y%m%d%H%M%S.txt", true, "testdata/19700101000000.txt"},              // file not found, append
		{"testdata/%Y%m%d%H%M%S-data.txt", true, "testdata/19700101000000-data.txt"},    // file found, append
		{"testdata/%Y%m%d%H%M%S.txt", false, "testdata/19700101000000.txt"},             // file not found, do not append
		{"testdata/%Y%m%d%H%M%S-data.txt", false, "testdata/19700101000000-data-2.txt"}, // file found, do not append
	}

	for _, c := range cases {
		if res := makeFileName(c.format, 0, loc, c.doAppend); res != c.filename {
			t.Errorf("'%v' is expected, but got '%v'.", c.filename, res)
		}
	}

	// test location
	loc, _ = time.LoadLocation("Asia/Tokyo")
	expected := "19700101-090000.txt"
	if res := makeFileName("%Y%m%d-%H%M%S.txt", 0, loc, false); res != expected {
		t.Errorf("'%v' is expected, but got '%v'.", expected, res)
	}
}

func TestWriterOpenWriter(t *testing.T) {
	tempDir := t.TempDir()
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "a", "b", "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()
	w, _ := NewWriter(c, layers.LinkTypeEthernet)

	// Success.
	if err := w.openWriter(0); err != nil {
		t.Errorf("nil is expected, but got '%v'.", err)
	}

	expected := filepath.Join(tempDir, "a", "b", "traffic-19700101-000000.pcap")
	got := w.file.Name()
	if expected != got {
		t.Errorf("'%v' is expected, but got '%v'.", expected, got)
	}

	// Failure when MkdirAll.
	c.Rcap.FileFmt = filepath.Join("/", "usr", "local", "dir", "file")
	if err := w.openWriter(0); err == nil {
		t.Errorf("err is expected, but got 'nil'.")
	}

	// Failure when OpenFile.
	c.Rcap.FileFmt = filepath.Join("/", "usr", "local", "file")
	if err := w.openWriter(0); err == nil {
		t.Errorf("err is expected, but got 'nil'.")
	}
}

// func TestWriterShouldRotateWithIntervalZero(t *testing.T) {
// 	// If Interval = 0, then shouldRotate always returns false
// 	config := &Config{Rcap: RcapConfig{Interval: 0}}
// 	writer := &Writer{config: config}
//
// 	// 86400: 1970-01-02T00:00:00+00
// 	for i := int64(86400); i <= 86400+86400+120; i++ {
// 		if writer.shouldRotate(i) != false {
// 			t.Errorf("'false' is expected, but got 'true'")
// 		}
// 	}
// }
//
// func TestShouldRotateWithoutOffset(t *testing.T) {
// 	// Interval = 60 , Offset = 0
// 	// -> true if i == 60, 120, ..., otherwise false
// 	// NOTE: false if i == 60 because of ts == writer.lastRotTime == 0.
// 	config := &Config{Rcap: RcapConfig{Interval: 60}}
// 	writer := &Writer{config: config}
//
// 	for i := int64(86401); i <= 86400+150; i++ {
// 		if i == 86401 || i == 86400+60 || i == 86400+120 {
// 			if writer.shouldRotate(i) != true {
// 				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
// 			}
// 		} else {
// 			if writer.shouldRotate(i) != false {
// 				t.Errorf("'false' is expected, but got 'true' (ts=%d)", i)
// 			}
// 		}
//
// 		if writer.shouldRotate(i) {
// 			writer.updateLastRotTime(i)
// 		}
// 	}
// }
//
// func TestShouldRotateWithOffset(t *testing.T) {
// 	// Interval = 60, Offset = 30
// 	// -> true if i == 30, 90, ..., otherwise false
// 	config := &Config{Rcap: RcapConfig{Interval: 60, Offset: 30}}
// 	writer := &Writer{config: config}
//
// 	for i := int64(86401); i <= 86400+120; i++ {
// 		if i == 86401 || i == 86400+30 || i == 86400+90 {
// 			if writer.shouldRotate(i) != true {
// 				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
// 			}
// 		} else {
// 			if writer.shouldRotate(i) != false {
// 				t.Errorf("'false' is expected, but got 'true' (ts=%d).", i)
// 			}
// 		}
//
// 		if writer.shouldRotate(i) {
// 			writer.updateLastRotTime(i)
// 		}
// 	}
// }
//
// func TestShouldRotateWithUTCOffset(t *testing.T) {
// 	// Interval = 60, UTCOffset = 30
// 	// -> true if i == 30, 90, ..., otherwise false
// 	duration, _ := time.ParseDuration("30s")
// 	config := &Config{Rcap: RcapConfig{Interval: 60, UTCOffset: duration}}
// 	writer := &Writer{config: config}
//
// 	for i := int64(86401); i <= 86400+120; i++ {
// 		if i == 86401 || i == 86400+30 || i == 86400+90 {
// 			if writer.shouldRotate(i) != true {
// 				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
// 			}
// 		} else {
// 			if writer.shouldRotate(i) != false {
// 				t.Errorf("'false' is expected, but got 'true' (ts=%d).", i)
// 			}
// 		}
//
// 		if writer.shouldRotate(i) {
// 			writer.updateLastRotTime(i)
// 		}
// 	}
// }
//
// func TestShouldRotateDailyWithOffset(t *testing.T) {
// 	// Interval = 86400, Offset = 54000
// 	// -> true if i == 54000, 140400, ..., otherwise false
// 	config := &Config{Rcap: RcapConfig{Interval: 86400, Offset: 54000}}
// 	writer := &Writer{config: config}
//
// 	for i := int64(86401); i <= 86400+86400*2; i++ {
// 		if i == 86401 || i == (86400*2-32400) || i == (86400*3-32400) {
// 			if writer.shouldRotate(i) != true {
// 				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
// 			}
// 		} else {
// 			if writer.shouldRotate(i) != false {
// 				t.Errorf("'false' is expected, but got 'true' (ts=%d)", i)
// 			}
// 		}
//
// 		if writer.shouldRotate(i) {
// 			writer.updateLastRotTime(i)
// 		}
// 	}
// }
//
// func TestShouldRotateDailyWithUTCOffset(t *testing.T) {
// 	// Interval = 86400, UTCOffset = 9h
// 	// -> true if i == 54000, 140400, ..., otherwise false
// 	duration, _ := time.ParseDuration("9h")
// 	config := &Config{Rcap: RcapConfig{Interval: 86400, UTCOffset: duration}}
// 	writer := &Writer{config: config}
//
// 	for i := int64(86401); i <= 86400+86400*2; i++ {
// 		if i == 86401 || i == (86400*2-32400) || i == (86400*3-32400) {
// 			if writer.shouldRotate(i) != true {
// 				t.Errorf("'true' is expected, but got 'false' (ts=%d).", i)
// 			}
// 		} else {
// 			if writer.shouldRotate(i) != false {
// 				t.Errorf("'false' is expected, but got 'true' (ts=%d)", i)
// 			}
// 		}
//
// 		if writer.shouldRotate(i) {
// 			writer.updateLastRotTime(i)
// 		}
// 	}
// }

//	func TestNewFileName(t *testing.T) {
//		var config *Config
//		var writer *Writer
//		var loc *time.Location
//
//		// Base test.
//		loc, _ = time.LoadLocation("UTC")
//		config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S.txt", Location: loc}}
//		writer = &Writer{config: config}
//
//		if fileName := writer.newFileName(0); fileName != "testdata/19700101000000.txt" {
//			t.Errorf("'testdata/19700101000000.txt' is expected, but got '%v'", fileName)
//		}
//
//		// Location test.
//		loc, _ = time.LoadLocation("Asia/Tokyo")
//		config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S.txt", Location: loc}}
//		writer = &Writer{config: config}
//
//		if fileName := writer.newFileName(0); fileName != "testdata/19700101090000.txt" {
//			t.Errorf("'testdata/19700101090000.txt' is expected, but got '%v'", fileName)
//		}
//
//		// With append.
//		loc, _ = time.LoadLocation("UTC")
//		config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S-data.txt", FileAppend: true, Location: loc}}
//		writer = &Writer{config: config}
//
//		if fileName := writer.newFileName(0); fileName != "testdata/19700101000000-data.txt" {
//			t.Errorf("'testdata/19700101000000-data.txt' is expected, but got '%v'", fileName)
//		}
//
//		// Without append (alternative filename).
//		loc, _ = time.LoadLocation("UTC")
//		config = &Config{Rcap: RcapConfig{FileFmt: "testdata/%Y%m%d%H%M%S-data.txt", FileAppend: false, Location: loc}}
//		writer = &Writer{config: config}
//
//		if fileName := writer.newFileName(0); fileName != "testdata/19700101000000-data-2.txt" {
//			t.Errorf("'testdata/19700101000000-data-2.txt' is expected, but got '%v'", fileName)
//		}
//	}

func TestWriterUpdateWithIntervalZero(t *testing.T) {
	tempDir := t.TempDir()

	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "test-%Y%m%d-%H%M%S.pcap")
	c.Rcap.Interval = 0
	c.CheckAndFormat()

	w, _ := NewWriter(c, layers.LinkTypeEthernet)
	for ts := int64(86400); ts < 86410; ts++ {
		w.Update(ts)
	}

	files, _ := filepath.Glob(filepath.Join(tempDir, "*.pcap"))
	if numFiles := len(files); numFiles != 1 {
		t.Errorf("1 file is expected, but got %v file(s).", numFiles)
	}
}

func TestWriterUpdateWithInterval60(t *testing.T) {
	tempDir := t.TempDir()

	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "test-%Y%m%d-%H%M%S.pcap")
	c.Rcap.Interval = 60
	c.CheckAndFormat()

	w, _ := NewWriter(c, layers.LinkTypeEthernet)
	for ts := int64(86399); ts < 86400+300; ts++ {
		w.Update(ts)
	}

	files, _ := filepath.Glob(filepath.Join(tempDir, "*.pcap"))
	if numFiles := len(files); numFiles != 6 {
		t.Errorf("6 files are expected, but got %v file(s).", numFiles)
	}
}

func TestWriterUpdateWithInterval86400(t *testing.T) {
	tempDir := t.TempDir()

	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "test-%Y%m%d-%H%M%S.pcap")
	c.Rcap.Interval = 86400
	c.Rcap.UTCOffset, _ = time.ParseDuration("9h")
	c.Rcap.Timezone = "Asia/Tokyo"
	c.CheckAndFormat()

	w, _ := NewWriter(c, layers.LinkTypeEthernet)
	for ts := int64(86400); ts < 86400+86400+86400; ts += 3600 {
		w.Update(ts)
	}

	files, _ := filepath.Glob(filepath.Join(tempDir, "*.pcap"))
	if numFiles := len(files); numFiles != 3 {
		t.Errorf("3 files are expected, but got %v file(s)", numFiles)
	}
}

func TestWriterWritePacket(t *testing.T) {
	tempDir := t.TempDir()

	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "test-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()

	w, _ := NewWriter(c, layers.LinkTypeEthernet)
	w.Update(86400)

	data := []byte("data")
	metadata := gopacket.CaptureInfo{
		Timestamp:     time.Unix(86400, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}

	if err := w.WritePacket(metadata, data); err != nil {
		t.Errorf("no error is expected, but got '%v'.", err)
	}
	if w.NumPackets() != 1 {
		t.Errorf("1 packet is expected, but got '%v'.", w.NumPackets())
	}

}

func TestWriterClose(t *testing.T) {
	tempDir := t.TempDir()

	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "test-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()

	w, _ := NewWriter(c, layers.LinkTypeEthernet)
	w.Update(86400)
	w.Close()
}
