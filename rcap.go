package main

import (
	"flag"
	"fmt"
	//	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jehiah/go-strftime"
	"github.com/pelletier/go-toml"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	// debug
	// "reflect"
)

const (
	// SamplingDump holds the number of packets to dump sampling results.
	SamplingDump = 10000
)

var version = "0.0.4"

var (
	// Params used for libpcap.
	device   string
	snaplen  uint
	promisc  bool
	toMs     uint
	bpfRules string

	// Params used for this program.
	fileFmt       string  // format of output file
	timezone      string  // timezone used for fileFmt
	interval      int64   // rotation interval [sec]
	offset        int64   // rotation interval offset [sec]
	sampling      float64 // sampling rate (probability, from 0 to 1)
	logFile       string  // path to log file
	useSystemTime bool    // use system time as a time source of rotation
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func main() {
	var f *os.File
	var w *pcapgo.Writer
	var showVersion bool
	var cnfFile string

	// Parse params from command-line arguments.
	flag.StringVar(&device, "i", "", "device name (e.g. en0, eth0).")
	flag.UintVar(&snaplen, "s", 65535, "snapshot length.")
	flag.BoolVar(&promisc, "p", true, "do NOT put into promiscuous mode.")
	flag.UintVar(&toMs, "t", 100, "timeout of reading packets from interface [milli-sec].")
	flag.StringVar(&bpfRules, "f", "", "BPF rules.")
	flag.StringVar(&fileFmt, "w", "pcap/%Y%m%d/%Y%m%d-%H%M%S.pcap", "format of output file.")
	flag.StringVar(&timezone, "z", "Local", "timezone used for output file.")
	flag.Int64Var(&interval, "T", 60, "rotation interval [sec].")
	flag.Int64Var(&offset, "offset", 0, "rotation interval offset [sec].")
	flag.Float64Var(&sampling, "sampling", 1, "sampling rate (0 <= p <= 1).")
	flag.StringVar(&logFile, "L", "", "log file.")
	flag.StringVar(&cnfFile, "c", "", "config file (other arguments are ignored).")
	flag.BoolVar(&showVersion, "v", false, "show version and exit.")
	flag.BoolVar(&useSystemTime, "S", false, "use system time as a time source of rotation (default: use packet-captured time).")
	flag.Parse()

	if showVersion {
		fmt.Println("version:", version)
		return
	}

	// Parse params from config file. Params in the command-line arguments are ignored.
	if cnfFile != "" {
		cnf, err := toml.LoadFile(cnfFile)
		if err != nil {
			log.Fatal(err)
		}

		device = cnf.Get("rcap.device").(string)
		snaplen = uint(cnf.Get("rcap.snaplen").(int64))
		promisc = cnf.Get("rcap.promisc").(bool)
		toMs = uint(cnf.Get("rcap.toMs").(int64))
		bpfRules = cnf.Get("rcap.bpfRules").(string)
		fileFmt = cnf.Get("rcap.fileFmt").(string)
		timezone = cnf.Get("rcap.timezone").(string)
		interval = cnf.Get("rcap.interval").(int64)
		offset = cnf.Get("rcap.offset").(int64)
		sampling = cnf.Get("rcap.sampling").(float64)
		logFile = cnf.Get("rcap.logFile").(string)
		useSystemTime = cnf.Get("rcap.useSystemTime").(bool)
	}

	// Init logging.
	log.SetFlags(log.Ldate | log.Ltime)

	if logFile != "" {
		logger, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Fatal(err)
		}

		log.SetOutput(logger)
		log.Println("open a log file:", logFile)
	}

	// Init signal handling.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		s := <-sigc
		log.Println("SIGNAL:", s)
		f.Close()
		os.Exit(0)
	}()

	// Init random generator.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Lookup a default device if no device name is given.
	if device == "" {
		log.Println("no device is set. look up devices.")

		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		for _, dev := range devices {
			device = dev.Name
			break
		}

		log.Println("find device:", device)
	}

	// Open a device and set a BPF filter.
	handle, err := pcap.OpenLive(device, int32(snaplen), promisc, time.Duration(toMs)*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Println("open device:", device)

	linkType := handle.LinkType()
	log.Println("linktype:", linkType)

	if bpfRules != "" {
		err := handle.SetBPFFilter(bpfRules)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("set filter:", bpfRules)
	}

	// Load location from timezone.
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("set timezone to", timezone)

	// Set sampling mode.
	samplingMode := (sampling < 1)

	log.Println("set sampling rate:", sampling)

	if useSystemTime {
		log.Println("set time source: system")
	} else {
		log.Println("set time source: packet")
	}

	var lstTime int64 = 0
	var numPackets, numCapPackets uint64 = 0, 0

	// Read packets from device and dump them into a file.
	for {
		data, capinfo, pkterr := handle.ZeroCopyReadPacketData()

		var curTime int64

		if useSystemTime {
			curTime = time.Now().Unix()
		} else {
			if pkterr != nil {
				curTime = time.Now().Unix()
			} else {
				curTime = capinfo.Timestamp.Unix()
			}
		}

		if f != nil {
			// If file need to be rotated, close the file and reset the file variable.
			if (curTime > lstTime) && (interval > 0) && (curTime%interval == offset) {
				f.Close()
				f = nil
			}
		}

		if f == nil {
			lstTime = curTime

			// Convert unix time to native time.
			tmpTime := time.Unix(lstTime, 0)
			tmpTime = tmpTime.In(loc)

			// Fill format of date and time in fileFmt.
			fileName := strftime.Format(fileFmt, tmpTime)

			// If the filename already exists, find alternative filenames.
			// e.g. foobar.pcap -> foobar-1.pcap
			for i := 1; fileExists(fileName); i++ {
				log.Println("file already exists:", fileName)

				fileFmtExt := filepath.Ext(fileFmt)
				fileFmtBase := fileFmt[0 : len(fileFmt)-len(fileFmtExt)]
				newFileFmt := fileFmtBase + "-" + strconv.Itoa(i) + fileFmtExt
				fileName = strftime.Format(newFileFmt, tmpTime)
			}

			// Make a directory for output files.
			dirName := filepath.Dir(fileName)
			err := os.MkdirAll(dirName, 0755)
			if err != nil {
				log.Fatal(err)
			}

			// Make a new file and write a PCAP header.
			f, err = os.Create(fileName)
			if err != nil {
				log.Fatal(err)
			}

			w = pcapgo.NewWriter(f)
			w.WriteFileHeader(uint32(snaplen), linkType)

			log.Printf("capture %v packets.\n", numCapPackets)
			log.Println("dump packets into a file:", fileName)

			numPackets = 0
			numCapPackets = 0
		}

		if pkterr != nil {
			// Do NOT log messages when it is timeouted.
			if pkterr != pcap.NextErrorTimeoutExpired {
				log.Println(pkterr)
			}
			continue
		}

		// Sample packets when sampling mode.
		if samplingMode {
			sample := (r.Float64() <= sampling)

			numPackets++
			if sample {
				numCapPackets++
			}

			if numPackets%SamplingDump == 0 {
				log.Printf("sampling result: %d/%d\n", numCapPackets, numPackets)
			}

			if !sample {
				continue
			}
		} else {
			numPackets++
			numCapPackets++
		}

		if f != nil {
			err := w.WritePacket(capinfo, data)
			if err != nil {
				log.Println(err)
			}
		}
	}
}
