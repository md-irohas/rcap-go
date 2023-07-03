package rcap

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	// SamplingDump holds the number of packets to dump sampling results.
	SamplingDump = 10000
)

type Runner struct {
	config             *Config
	reader             *Reader
	writer             *Writer
	doExit             bool
	doReload           bool
	numCapturedPackets uint64
	numSampledPackets  uint64
}

func NewRunner(c *Config) (*Runner, error) {
	r := &Runner{
		config:             c,
		doExit:             false,
		doReload:           false,
		numCapturedPackets: 0,
		numSampledPackets:  0,
	}

	return r, nil
}

func (r *Runner) Reload() error {
	if r.config.Filename == "" {
		return errors.New("no config file is set.")
	}

	newConfig, err := LoadConfig(r.config.Filename)
	if err != nil {
		return err
	}

	// TODO: re-init reader and writer only when configuration has changed.
	r.Close()

	log.Println("reload config and use the new config.")
	r.config = newConfig
	r.config.PrintToLog()

	return nil
}

func (r *Runner) setupReaderAndWriter() error {
	var err error

	if r.reader == nil {
		r.reader, err = NewReader(r.config)
		if err != nil {
			return err
		}
	}

	if r.writer == nil {
		// The current NewWriter returns no error.
		r.writer, _ = NewWriter(r.config, r.reader.LinkType())
	}

	return nil
}

func (r *Runner) getTimestamp(capinfo gopacket.CaptureInfo, pkterr error) int64 {
	if r.config.Rcap.UseSystemTime {
		return time.Now().Unix()
	}

	if pkterr != nil {
		return time.Now().Unix()
	}

	return capinfo.Timestamp.Unix()
}

func (r *Runner) isSamplingMode() bool {
	return r.config.Rcap.SamplingMode
}

func (r *Runner) doSample() bool {
	return Random() < r.config.Rcap.Sampling
}

func (r *Runner) Run() error {
	for !r.doExit {
		if r.doReload {
			if err := r.Reload(); err != nil {
				log.Printf("failed to reload config: %v", err)
			}
			r.doReload = false
		}

		err := r.setupReaderAndWriter()
		if err != nil {
			return fmt.Errorf("failed to setup reader/writer: %w", err)
		}

		data, capinfo, pkterr := r.reader.ReadPacket()
		currentTime := r.getTimestamp(capinfo, pkterr)

		err = r.writer.Update(currentTime)
		if err != nil {
			return fmt.Errorf("failed to update writer: %w", err)
		}

		if pkterr != nil {
			switch pkterr {
			case pcap.NextErrorTimeoutExpired:
				// Go to next loop.
				// Do NOT log messages when it is timeouted.
				continue
			default:
				// Return error (unexpected error).
				return fmt.Errorf("failed to read packet: %w", pkterr)
			}
		}

		r.numCapturedPackets++
		if r.isSamplingMode() {
			doSample := r.doSample()

			if doSample {
				r.numSampledPackets++
			}
			if r.numCapturedPackets%SamplingDump == 0 {
				samplingRatio := float32(r.numSampledPackets) / float32(r.numCapturedPackets) * 100
				log.Printf("sampling result: %v/%v (%.2f%%)\n", r.numSampledPackets, r.numCapturedPackets, samplingRatio)
			}
			if !doSample {
				continue
			}
		}

		err = r.writer.WritePacket(capinfo, data)
		if err != nil {
			return fmt.Errorf("failed to write packet: %w", err)
		}
	}

	return nil
}

func (r *Runner) Close() {
	if r.reader != nil {
		r.reader.Close()
		r.reader = nil
		log.Println("close reader.")
	}
	if r.writer != nil {
		r.writer.Close()
		r.writer = nil
		log.Println("close writer.")
	}
}

func Run(config *Config) error {
	// The current NewRunner returns no error.
	r, _ := NewRunner(config)

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
				r.doReload = true
			case syscall.SIGINT, syscall.SIGTERM:
				r.doExit = true
			}
		}
	}()

	defer r.Close()

	return r.Run()
}
