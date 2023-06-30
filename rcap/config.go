package rcap

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/pelletier/go-toml"
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
	Device   string `toml:"device" default:"any" validate:"required"`    // Device name.
	SnapLen  uint   `toml:"snaplen" default:"65535" validate:"gte=0"`    // Snap length.
	Promisc  bool   `toml:"promisc" default:"true"`                      // Promiscuous mode.
	ToMs     uint   `toml:"toMs" default:"100" validate:"gte=1,lte=500"` // Timeout when no packets are captured.
	BpfRules string `toml:"bpfRules" default:""`                         // BPF rules.

	// Params for this program.
	FileFmt       string         `toml:"fileFmt" default:"dump/%Y%m%d/traffic-%Y%m%d%H%M00.pcap" validate:"filepath"` // Path to PCAP files.
	FileAppend    bool           `toml:"fileAppend" default:"true"`                                                   // Append data if the file exists.
	Timezone      string         `toml:"timezone" default:"UTC" validate:"timezone"`                                  // Timezone used for FileFmt.
	Location      *time.Location // Location data (i.e., Timezone)
	Interval      int64          `toml:"interval" default:"60" validate:"gte=0"`        // Rotation interval (in second).
	Offset        int64          `toml:"offset" default:"0" validate:"gte=0"`           // Deprecated: Rotation offset (in second).
	UTCOffset     time.Duration  `toml:"utcOffset" default:"0"`                         // Rotation offset from UTC (in second).
	Sampling      float64        `toml:"sampling" default:"1.0" validate:"gte=0,lte=1"` // Sampling rate.
	SamplingMode  bool           // Sampling mode.
	LogFile       string         `toml:"logFile" default:"" validate:"omitempty,filepath"` // Deprecated: Log file.
	UseSystemTime bool           `toml:"useSystemTime" default:"false"`                    // Use system time or packet-captured time.
}

// CheckAndFormat method checks and formats the values in the configuration,
// and returns an error if the configuration is invalid.
func (c *Config) CheckAndFormat() error {
	validate := validator.New()

	if err := validate.Struct(c); err != nil {
		return err
	}

	// no error is returned from LoadLocation because validator checks timezone
	// value.
	c.Rcap.Location, _ = time.LoadLocation(c.Rcap.Timezone)
	c.Rcap.SamplingMode = (c.Rcap.Sampling < 1.0)

	return nil
}

// PrintToLog method prints config values to its log.
func (c *Config) PrintToLog() {
	r := &c.Rcap

	log.Printf("==== RCAP Config ====\n")
	log.Printf("- Filename: %v\n", c.Filename)
	log.Printf("- RCAP:\n")
	log.Printf("  - device:	%v\n", r.Device)
	log.Printf("  - snaplen:	%v\n", r.SnapLen)
	log.Printf("  - promisc:	%v\n", r.Promisc)
	log.Printf("  - toMs:	%v\n", r.ToMs)
	log.Printf("  - bpfRules:	%v\n", r.BpfRules)
	log.Printf("  - fileFmt:	%v\n", r.FileFmt)
	log.Printf("  - fileAppend:	%v\n", r.FileAppend)
	log.Printf("  - timezone:	%v (location: %v)\n", r.Timezone, r.Location)
	log.Printf("  - interval:	%v\n", r.Interval)
	log.Printf("  - offset:	%v\n", r.Offset)
	log.Printf("  - utcOffset:	%v\n", r.UTCOffset)
	log.Printf("  - sampling:	%v (samplingMode: %v)\n", r.Sampling, r.SamplingMode)
	log.Printf("  - useSystemTime:	%v\n", r.UseSystemTime)
	log.Printf("=====================\n")
}

// LoadConfig loads a configuration from the given filename and returns an
// instance of Config struct.
func LoadConfig(filename string) (*Config, error) {
	// empty filename and file-not-found error are handled here.
	str, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	config := &Config{Filename: filename}
	if err := toml.Unmarshal(str, config); err != nil {
		return nil, err
	}

	if err := config.CheckAndFormat(); err != nil {
		valErrs, ok := err.(validator.ValidationErrors)
		if ok {
			for _, valErr := range valErrs {
				log.Println(valErr.Error())
			}
		}
		return nil, errors.New("invalid config values")
	}

	return config, nil
}
