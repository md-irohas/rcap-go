package rcap

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	// SamplingDump holds the number of packets to dump sampling results.
	SamplingDump = 10000
)

func Run(config *Config) error {
	var reader *Reader
	var writer *Writer
	var err error

	doExit := false
	doReload := false

	// Trap signals.
	log.Println("trap signals (send SIGHUP to reload, SIGINT or SIGTERM to exit).")
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			s := <-sigc
			log.Println("SIGNAL:", s)

			switch s {
			case syscall.SIGHUP:
				doReload = true
			case syscall.SIGINT, syscall.SIGTERM:
				doExit = true
			}
		}
	}()

	defer func() {
		if reader != nil {
			reader.Close()
			log.Println("close reader.")
		}
		if writer != nil {
			writer.Close()
			log.Println("close writer.")
		}
	}()

	var numSampledPackets, numCapturedPackets uint64 = 0, 0

CAPTURE_LOOP:
	for {
		if doExit {
			break CAPTURE_LOOP
		}

		// If the doReload flag is set, reload configurations from the file and
		// close the current reader and writer. If configurations reloaded
		// are invalid, do nothing.
		if doReload {
			if config.Filename == "" {
				log.Println("failed to reload config. no config file is set.")
			} else {
				if newConfig, err := LoadConfig(config.Filename); err == nil {
					// TODO: re-init reader and writer only when configuration has
					// changed.
					if reader != nil {
						reader.Close()
						reader = nil
					}
					if writer != nil {
						writer.Close()
						writer = nil
					}

					log.Println("reload config and use the new config.")
					config = newConfig
				} else {
					log.Printf("failed to reload config: %v", err)
					log.Println("use the previous config instead.")
				}
			}

			config.PrintToLog()
			doReload = false
		}

		// Create reader and writer instances if they are not ready.
		if reader == nil {
			reader, err = NewReader(config)
			if err != nil {
				return err
			}
		}
		if writer == nil {
			linkType := reader.LinkType()
			writer, err = NewWriter(config, linkType)
			if err != nil {
				return err
			}
		}

		data, capinfo, pkterr := reader.ReadPacket()

		var curTime int64
		if config.Rcap.UseSystemTime {
			curTime = time.Now().Unix()
		} else {
			if pkterr != nil {
				curTime = time.Now().Unix()
			} else {
				curTime = capinfo.Timestamp.Unix()
			}
		}

		err = writer.Update(curTime)
		if err != nil {
			log.Printf("failed to update writer: %v", err)
			continue
		}

		if pkterr != nil {
			switch pkterr {
			// Do NOT log messages when it is timeouted.
			case pcap.NextErrorTimeoutExpired:
			// The reader is already closed.
			case io.EOF:
				break CAPTURE_LOOP
			default:
				log.Printf("failed to read packet: %v", pkterr)
			}

			continue
		}

		numCapturedPackets++

		if config.Rcap.SamplingMode {
			sample := (Random() <= config.Rcap.Sampling)

			if numCapturedPackets%SamplingDump == 0 {
				log.Printf("sampling result: %d/%d\n", numSampledPackets, numCapturedPackets)
			}

			if sample {
				numSampledPackets++
			} else {
				continue
			}
		}

		err := writer.WritePacket(capinfo, data)
		if err != nil {
			log.Printf("failed to write packet: %v", err)
		}
	}

	return nil
}
