package rcap

import (
	"math/rand"
	"os"
	"time"
)

var (
	randGen *rand.Rand
)

func init() {
	randGen = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// Random returns a pseudo-random number in [0.0, 1.0).
func Random() float64 {
	return randGen.Float64()
}

// FileExists returns true if the given filename exists.
func FileExists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	} else {
		return false
	}
}
