package rcap

import (
	"testing"
)

func TestRandom(t *testing.T) {
	// The Random function is just a wrapper of math.rand packet,
	// so this test case only checks its return value once.
	value := Random()
	if value < 0 || 1 <= value {
		t.Errorf("A number in [0.0, 1.0) is expected, but got %v.", value)
	}
}

func TestFileExists(t *testing.T) {
	if FileExists("testdata/rcap-good.toml") != true {
		t.Error("'testdata/rcap-good.toml' must be found, but not found.")
	}
	if FileExists("file-not-found") != false {
		t.Error("'file-not-found' must be not found, but found.")
	}
	if FileExists("") != false {
		t.Error("'' must be not found, but found.")
	}
}
