package rcap

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
)

func TestNewRunner(t *testing.T) {
	c := makeConfig()
	_, err := NewRunner(c)
	if err != nil {
		t.Errorf("nil is expected, but got '%v'.", err)
	}
}

func TestRunnerReloadWithFailure(t *testing.T) {
	c := makeConfig()
	r, _ := NewRunner(c)

	// empty config file
	if err := r.Reload(); err == nil {
		t.Error("err is expected, but got 'nil'.")
	}

	// invalid config
	c.Filename = "testdata/rcap-invalid-config.toml"
	if err := r.Reload(); err == nil {
		t.Error("err is expected, but got 'nil'.")
	}
}

func TestRunnerReload(t *testing.T) {
	c := makeConfig()
	r, _ := NewRunner(c)

	// valid config
	c.Filename = "testdata/rcap-good.toml"
	if err := r.Reload(); err != nil {
		t.Errorf("nil is expected, but got '%v'.", err)
	}

	// check if config values are updated.
	if c.Rcap.BpfRules == r.config.Rcap.BpfRules {
		t.Error("config is not updated.")
	}
}

func TestRunnerSetupReaderAndWriter(t *testing.T) {
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(t.TempDir(), "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()
	r, _ := NewRunner(c)

	// NewReader fails.
	if err := r.setupReaderAndWriter(); err == nil {
		t.Error("err is expected, but got 'nil'.")
	}

	// NewReader and NewWriter succeed (reader is a dummy).
	r.reader, _ = openAndSetUpReader(c, "testdata/sample.pcap")
	if err := r.setupReaderAndWriter(); err != nil {
		t.Error("err is expected, but got 'nil'.")
	}
}

func TestRunnerGetTimestamp(t *testing.T) {
	c := makeConfig()
	c.CheckAndFormat()
	r, _ := NewRunner(c)

	metadata := gopacket.CaptureInfo{
		Timestamp: time.Unix(86400, 0),
	}
	pkterr := errors.New("dummy error")

	// Timestamp is from system time because of UseSystemTime.
	c.Rcap.UseSystemTime = true
	if ts := r.getTimestamp(metadata, nil); ts < 1688137200 {
		t.Error("'ts' is not from system time (UseSystemTime=true).")
	}

	// Timestamp is from system time because of pkterr.
	c.Rcap.UseSystemTime = false
	if ts := r.getTimestamp(metadata, pkterr); ts < 1688137200 {
		t.Error("'ts' is not from system time (UseSystemTime=false, pkterr!=nil).")
	}

	// Timestamp is from metadata.
	if ts := r.getTimestamp(metadata, nil); ts != 86400 {
		t.Errorf("'ts' is expected to be '%v', but got '%v'.", 86400, ts)
	}
}

func TestRunnnerPrintSamplingResult(t *testing.T) {
	c := makeConfig()
	c.CheckAndFormat()
	r, _ := NewRunner(c)

	// numCapturePackets == 0
	r.printSamplingResult()

	// numCapturePackets == 2, numSampledPackets == 1
	r.numCapturedPackets = 2
	r.numSampledPackets = 1
	r.printSamplingResult()
}

func TestRunnerDoSamplingAll(t *testing.T) {
	c := makeConfig()
	c.Rcap.Sampling = 1.0
	c.CheckAndFormat()

	r, _ := NewRunner(c)
	r.numStatsPackets = 10

	count := 0
	for i := 0; i < 100; i++ {
		if r.doSampling() {
			count++
		}
	}

	if count != 100 {
		t.Errorf("The probability of doSample seems to be invalid: (%v != 100)", count)
	}
}

func TestRunnerDoSampling10Percent(t *testing.T) {
	c := makeConfig()
	c.Rcap.Sampling = 0.1
	c.CheckAndFormat()

	r, _ := NewRunner(c)
	r.numStatsPackets = 10

	count := 0
	for i := 0; i < 100; i++ {
		if r.doSampling() {
			count++
		}
	}

	if !(count < 30) {
		t.Errorf("The probability of doSample seems to be invalid: (%v > 30)", count)
	}
}

func TestRunnerRunWithFailure(t *testing.T) {
	tempDir := t.TempDir()
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()
	r, _ := NewRunner(c)

	// setupReaderAndWriter fails because of Device = 'any'.
	if err := r.Run(); err == nil {
		t.Error("err is expected, but got 'nil'.")
	}
}

func TestRunnerRun(t *testing.T) {
	tempDir := t.TempDir()
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()
	r, _ := NewRunner(c)
	r.reader, _ = openAndSetUpReader(c, "testdata/sample.pcap")

	// EOF error.
	if err := r.Run(); err == nil {
		t.Error("err is expected, but got 'nil'.")
	}
}

func TestRunnerClose(t *testing.T) {
	// Setup reader and writer to be closed.
	tempDir := t.TempDir()
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()
	r, _ := NewRunner(c)
	r.reader, _ = openAndSetUpReader(c, "testdata/sample.pcap")
	r.writer, _ = NewWriter(c, r.reader.LinkType())
	r.writer.openWriter(0)

	r.Close()
}

func TestRun(t *testing.T) {
	tempDir := t.TempDir()
	c := makeConfig()
	c.Rcap.FileFmt = filepath.Join(tempDir, "traffic-%Y%m%d-%H%M%S.pcap")
	c.CheckAndFormat()

	if err := Run(c); err == nil {
		t.Errorf("err is expected, but got 'nil'.")
	}
}
