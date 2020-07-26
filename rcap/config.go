package rcap

import (
	"errors"
	"fmt"
	"github.com/pelletier/go-toml"
	"io/ioutil"
	"log"
	"time"
)

var (
	ErrEmptyFilename = errors.New("empty filename")  // Empty file.
	ErrFileNotFound  = errors.New("file not found")  // File not found.
	ErrFileRead      = errors.New("file-read error") // File-read failure.
	ErrInvalidConfig = errors.New("invalid config")  // Invalid config.
)

// Config struct is a root section of rcap-go configuration.
type Config struct {
	// Filename which has this configuration.
	Filename string

	// Rcap struct is a main section of rcap-go configuration.
	Rcap RcapConfig `toml:"rcap"`
}

// RcapConfig struct is a main section of rcap-go configuration.
type RcapConfig struct {
	// Params for libpcap.
	Device   string `toml:"device"`                // Device name.
	SnapLen  uint   `toml:"snaplen",default:65535` // Snap length.
	Promisc  bool   `toml:"promisc",default:true`  // Promiscuous mode.
	ToMs     uint   `toml:"toMs",default:100`      // Timeout when no packets are captured.
	BpfRules string `toml:"bpfRules",default:""`   // BPF rules.

	// Params for this program.
	FileFmt       string         `toml:"fileFmt",default:"pcap/%Y%m%d/%Y%m%d-%M%M00.pcapng"` // Path to PCAP files.
	Timezone      string         `toml:"timezone",default:"UTC"`                             // Timezone used for FileFmt.
	Location      *time.Location // Location data (i.e., Timezone)
	Interval      int64          `toml:"interval",default:60"` // Rotation interval (in second).
	Offset        int64          `toml:"offset",default=0`     // Rotation offset (in second).
	Sampling      float64        `toml:"sampling",default=1.0` // Sampling rate.
	SamplingMode  bool           // Sampling mode.
	LogFile       string         `toml:"logFile",default=""`          // Deprecated: Log file.
	UseSystemTime bool           `toml:"useSystemTime",default=false` // Use system time or packet-captured time.
}

// CheckAndFormat method checks and formats the values in the configuration,
// and returns an error if the configuration is invalid.
func (c *Config) CheckAndFormat() error {
	r := &c.Rcap

	if r.Device == "" {
		return fmt.Errorf("invalid value: device: %v", r.Device)
	}
	if r.SnapLen < 0 {
		return fmt.Errorf("invalid value: snaplen: %v", r.SnapLen)
	}
	if r.ToMs < 0 || 500 < r.ToMs {
		return fmt.Errorf("invalid value: toms: %v", r.SnapLen)
	}

	if r.FileFmt == "" {
		return fmt.Errorf("invalid value: fileFmt: %v", r.FileFmt)
	}
	if loc, err := time.LoadLocation(r.Timezone); err == nil {
		r.Location = loc
	} else {
		return fmt.Errorf("invalid value: timezone: %v", r.Timezone)
	}
	if r.Interval < 0 {
		return fmt.Errorf("invalid value: interval: %v", r.Interval)
	}
	if r.Offset < 0 {
		return fmt.Errorf("invalid value: offset: %v", r.Offset)
	}
	if r.Sampling <= 0 || 1 < r.Sampling {
		return fmt.Errorf("invalid value: sampling: %v", r.Sampling)
	}
	r.SamplingMode = (r.Sampling < 1)
	if r.LogFile != "" {
		log.Println("WARNING: logFile is deprecated.")
	}

	return nil
}

// LoadConfig loads a configuration from the given filename and returns an
// instance of Config struct.
//
// LoadConfig returns the following errors:
// - ErrEmptyFilename: when the filename is an empty string.
// - ErrFileNotFound: when the filename does not exist on the filesystem.
// - ErrFileRead: when ioutil.Readfile fails to read from the file.
// - ErrInvalidConfig: when the config in the file is invalid.
func LoadConfig(filename string) (*Config, error) {
	if filename == "" {
		return nil, ErrEmptyFilename
	}
	if !FileExists(filename) {
		return nil, ErrFileNotFound
	}

	doc, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("failed to read file: %s: %s", filename, err)
		return nil, ErrFileRead
	}

	config := &Config{Filename: filename}
	if err := toml.Unmarshal(doc, config); err != nil {
		log.Printf("failed to load config: %s", err)
		return nil, ErrInvalidConfig
	}

	if err := config.CheckAndFormat(); err != nil {
		log.Printf("failed to load config: %s", err)
		return nil, ErrInvalidConfig
	}

	return config, nil
}
