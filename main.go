package main

import (
	"flag"
	"fmt"
	"github.com/md-irohas/rcap-go/rcap"
	"log"
)

const (
	Version = "0.1.0" // Version
)

func main() {
	var configFile string
	var showVersion bool
	var fileConfig, cmdConfig, config *rcap.Config
	var err error

	// Meta flags.
	flag.StringVar(&configFile, "c", "", "config file (other arguments will be ignored).")
	flag.BoolVar(&showVersion, "v", false, "show version and exit.")

	// rcap config from command line.
	cmdConfig = &rcap.Config{}
	r := &cmdConfig.Rcap

	// rcap config flags.
	flag.StringVar(&r.Device, "i", "any", "device name (e.g. en0, eth0).")
	flag.UintVar(&r.SnapLen, "s", 65535, "snapshot length.")
	flag.BoolVar(&r.Promisc, "p", true, "do NOT put into promiscuous mode.")
	flag.UintVar(&r.ToMs, "t", 100, "timeout of reading packets from interface [milli-sec].")
	flag.StringVar(&r.BpfRules, "f", "", "BPF rules.")
	flag.StringVar(&r.FileFmt, "w", "dump/%Y%m%d/traffic-%Y%m%d%H%M00.pcap", "format of output file.")
	flag.StringVar(&r.Timezone, "z", "UTC", "timezone used for output file.")
	flag.Int64Var(&r.Interval, "T", 60, "rotation interval [sec].")
	flag.Int64Var(&r.Offset, "offset", 0, "rotation interval offset [sec].")
	flag.Float64Var(&r.Sampling, "sampling", 1, "sampling rate (0 <= p <= 1).")
	flag.StringVar(&r.LogFile, "L", "", "[deprecated] log file.")
	flag.BoolVar(&r.UseSystemTime, "S", false, "use system time as a time source of rotation (default: use packet-captured time).")
	flag.Parse()

	if showVersion {
		fmt.Println(Version)
		return
	}

	if configFile != "" {
		log.Println("config: file")
		log.Printf("load config: %v", configFile)

		fileConfig, err = rcap.LoadConfig(configFile)
		if err != nil {
			log.Fatalf("failed to load config from file: %v", err)
		}

		config = fileConfig
	} else {
		log.Println("config: command-line")

		err = cmdConfig.CheckAndFormat()
		if err != nil {
			log.Fatalf("failed to load config from command-line: %v", err)
		}

		config = cmdConfig
	}

	if err := rcap.Run(config); err != nil {
		log.Fatalf("fatal error: %v", err)
	}
}
