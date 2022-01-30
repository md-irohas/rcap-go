package rcap

import (
	"fmt"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/go-cmp/cmp"
	"github.com/pelletier/go-toml"
)

func makeConfig() (*Config) {
	config := &Config{Filename: ""}
	toml.Unmarshal([]byte(`[rcap]`), config)

	return config
}

func TestConfigDefaultValues(t *testing.T) {
	got := makeConfig()

	expected := &Config{
		Filename: "",
		Rcap: RcapConfig{
			Device:        "",
			SnapLen:       65535,
			Promisc:       true,
			ToMs:          100,
			BpfRules:      "",
			FileFmt:       "pcap/%Y%m%d/%Y%m%d-%H%M00.pcapng",
			Timezone:      "UTC",
			Interval:      60,
			Offset:        0,
			Sampling:      1,
			LogFile:       "",
			UseSystemTime: false,
		},
	}

	if !cmp.Equal(got, expected) {
		t.Errorf("'%#v' is expected, but got '%#v'.", got, expected)
	}
}

func TestCheckConfig(t *testing.T) {
	c := makeConfig()
	r := &c.Rcap
	r.Device = ""
	// r.SnapLen = -1
	r.ToMs = 1000
	r.Timezone = "invalid-timezone"
	r.Interval = 0
	r.Offset = 30
	r.Sampling = 10

	err := c.CheckAndFormat()
	valErrs, _ := err.(validator.ValidationErrors)

	if len(valErrs) != 6 {
		t.Errorf("%d errors are expected, but %d errors are got.", 6, len(valErrs))
	}

	for _, valErr := range valErrs {
		t.Logf("validation error: %#v", valErr)
	}
}

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		// in
		filename string
		// out
		err error
	}{
		{"", ErrEmptyFilename},
		{"file-not-found", ErrFileNotFound},
		{"testdata/rcap-invalid-toml.toml", ErrInvalidToml},
		{"testdata/rcap-invalid-config.toml", ErrInvalidConfig},
		{"testdata/rcap-good.toml", nil},
	}

	for _, c := range cases {
		fmt.Println("test: " + c.filename)
		if config, err := LoadConfig(c.filename); err != c.err {
			if c.err == nil {
				if c.filename != config.Filename {
					t.Errorf("'%#v' is expected, but got '%s'.", c.filename, config.Filename)
				}
			}
		}
	}

	// Check config values (per type).
	// r := &config.Rcap
	// if r.Device != "en0" || r.SnapLen != 65535 || r.Promisc != true || r.Sampling != 1.0 {
	// 	t.Errorf("unexpected values: %+v", r)
	// }
}
