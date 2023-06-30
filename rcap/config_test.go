package rcap

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/go-cmp/cmp"
	"github.com/pelletier/go-toml"
)

func TestPrintToLog(t *testing.T) {
	config := &Config{Filename: "test"}
	config.PrintToLog()
}

// make config with default values.
func makeConfig() *Config {
	config := &Config{Filename: ""}
	toml.Unmarshal([]byte(`[rcap]`), config)
	return config
}

func TestConfigDefaultValues(t *testing.T) {
	got := makeConfig()

	expected := &Config{
		Filename: "",
		Rcap: RcapConfig{
			Device:        "any",
			SnapLen:       65535,
			Promisc:       true,
			ToMs:          100,
			BpfRules:      "",
			FileFmt:       "dump/%Y%m%d/traffic-%Y%m%d%H%M00.pcap",
			FileAppend:    true,
			Timezone:      "UTC",
			Location:      nil, // not set yet
			Interval:      60,
			Offset:        0,
			Sampling:      1.0,
			SamplingMode:  false, // not set yet (default)
			LogFile:       "",
			UseSystemTime: false,
		},
	}

	if !cmp.Equal(got, expected) {
		t.Errorf("'%#v' is expected, but got '%#v'.", got, expected)
		// diff := cmp.Diff(got, expected)
		// t.Errorf("diff: %v", diff)
	}
}

func TestConfigCheckAndFormat(t *testing.T) {
	c := makeConfig()

	if err := c.CheckAndFormat(); err != nil {
		t.Errorf("The default values are expected to be valid, but invalid: %v", err)
	}

	// check if Location is set.
	if c.Rcap.Location == nil {
		t.Errorf("The 'Location' value is still nil")
	}
}

func TestConfigCheckAndFormatWithFailure(t *testing.T) {
	c := makeConfig()
	r := &c.Rcap

	// invalid config
	r.Device = "" // required
	// r.SnapLen = -1	// SnapLen > 0, SnapLen is uint.
	r.ToMs = 1000                   // 0 < ToMs < 500
	r.Timezone = "invalid-timezone" // not-timezone string
	r.Interval = -1                 // Interval >= 0
	r.Offset = -1                   // Offset >= 0
	r.Sampling = 10.0               // 0.0 <= Sampling <= 1.0
	r.LogFile = "/some/dir/"        // empty or filepath

	err := c.CheckAndFormat()
	valErrs, _ := err.(validator.ValidationErrors)

	if len(valErrs) != 7 {
		t.Errorf("%d errors are expected, but %d errors are got.", 6, len(valErrs))
	}

	// for _, valErr := range valErrs {
	// 	t.Logf("validation error: %#v", valErr)
	// }
}

func TestLoadConfig(t *testing.T) {
	if _, err := LoadConfig("testdata/rcap-good.toml"); err != nil {
		t.Errorf("nil is expected, but got '%v'.", err)
	}
}

func TestLoadConfigWithFailure(t *testing.T) {
	cases := []struct {
		// in
		filename string
		// out
		errMsg string
	}{
		{"", "open : no such file or directory"},
		{"file-not-found", "open file-not-found: no such file or directory"},
		{"testdata/rcap-invalid-toml.toml", "(2, 1): parsing error: keys cannot contain { character"},
		{"testdata/rcap-invalid-config.toml", "invalid config values"},
	}

	for _, c := range cases {
		t.Logf("test with '%v'", c.filename)

		if _, err := LoadConfig(c.filename); err.Error() != c.errMsg {
			t.Errorf("'%#v' is expected, but got '%v'.", c.errMsg, err.Error())
		}
	}
}
