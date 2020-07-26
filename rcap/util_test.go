package rcap

import (
	"testing"
)

func TestRandom(t *testing.T) {
	value := Random()
	if value < 0 || 1 <= value {
		t.Errorf("A number in [0.0, 1.0) is expected, but got %v.", value)
	}
}

func TestFileExists(t *testing.T) {
	if FileExists("../rcap.toml.orig") != true {
		t.Error("'rcap.toml.orig' must be found, but not found.")
	}
	if FileExists("file-not-found") != false {
		t.Error("'file-not-found' must be not found, but found.")
	}
	if FileExists("") != false {
		t.Error("'' must be not found, but found.")
	}
}
