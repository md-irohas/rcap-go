package rcap

import (
	// "fmt"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Check an empty filename.
	if _, err := LoadConfig(""); err != ErrEmptyFilename {
		t.Errorf("'%#v' is expected, but got '%#v'.", ErrEmptyFilename, err)
	}

	// Check file-not-found.
	if _, err := LoadConfig("file-not-found"); err != ErrFileNotFound {
		t.Errorf("'%#v' is expected, but got '%#v'.", ErrFileNotFound, err)
	}

	// Check invalid config.
	if _, err := LoadConfig("testdata/rcap-bad.toml"); err != ErrInvalidConfig {
		t.Errorf("'%#v' is expected, but got '%#v'.", ErrInvalidConfig, err)
	}

	// Check config.
	config, err := LoadConfig("testdata/rcap-good.toml")
	if err != nil {
		t.Errorf("'nil' is expected, but got '%#v'.", err)
	}

	// Check filename.
	if config.Filename != "testdata/rcap-good.toml" {
		t.Errorf("'testadata/rcap-good.toml' is expected, but got '%s'.", config.Filename)
	}

	// Check invalid config values.
	if _, err := LoadConfig("testdata/rcap-invalid.toml"); err != ErrInvalidConfig {
		t.Errorf("'%#v' is expected, but got '%#v'.", ErrInvalidConfig, err)
	}

	// Check config values (per type).
	r := &config.Rcap
	if r.Device != "en0" || r.SnapLen != 65535 || r.Promisc != true || r.Sampling != 1.0 {
		t.Errorf("unexpected values: %+v", r)
	}
}
