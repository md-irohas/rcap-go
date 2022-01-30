package rcap

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jehiah/go-strftime"
)

// Writer writes packet data to files which are rotated every interval.
type Writer struct {
	config      *Config
	file        *os.File
	writer      *pcapgo.Writer
	linkType    layers.LinkType
	lastRotTime int64
	numPackets  uint
	closed      bool
}

// NewWriter returns a new instance of Writer.
func NewWriter(c *Config, linkType layers.LinkType) (*Writer, error) {
	w := &Writer{
		config:      c,
		linkType:    linkType,
		lastRotTime: 0,
		numPackets:  0,
		closed:      false,
	}

	return w, nil
}

// NumPackets returns the number of packets the Writer wrote to the file. The
// number will be reset when the file is rotated.
func (w *Writer) NumPackets() uint {
	return w.numPackets
}

// shoudRotate returns true if the file should be rotated, otherwise false.
func (w *Writer) shouldRotate(ts int64) bool {
	c := &w.config.Rcap

	if c.Interval == 0 {
		return false
	} else {
		return (ts >= (w.lastRotTime + c.Interval))
	}
}

func (w *Writer) updateLastRotTime(ts int64) {
	c := &w.config.Rcap

	if w.lastRotTime == 0 {
		rotTime := (ts / c.Interval * c.Interval) + c.Offset
		if ts < rotTime {
			rotTime -= c.Interval
		}
		w.lastRotTime = rotTime
	} else {
		w.lastRotTime += c.Interval
	}
}

// newFileName returns a file name of the next PCAP file. The file name is made
// from the Config.FileNameFormat, and if the file name already exists, this
// function returns alternative filenames (e.g. foobar.pcap -> foobar-1.pcap)
func (w *Writer) newFileName(ts int64) string {
	c := &w.config.Rcap

	// Convert unix time to location-aware time.
	// NOTE: time.Unix(sec, nanosec)
	tmpTime := time.Unix(ts, 0)
	locTime := tmpTime.In(c.Location)

	// Default file name.
	fileName := strftime.Format(c.FileFmt, locTime)

	// If the file name already exists, find alternatives.
	for i := 1; FileExists(fileName); i++ {
		log.Println("file already exists:", fileName)

		fmt := c.FileFmt
		ext := filepath.Ext(fmt)
		base := fmt[0 : len(fmt)-len(ext)]

		// e.g. foobar.pcap -> foobar-1.pcap
		newFmt := base + "-" + strconv.Itoa(i) + ext
		fileName = strftime.Format(newFmt, locTime)
	}

	return fileName
}

// Update method update internal timestamp and rotates the file.
func (w *Writer) Update(ts int64) error {
	c := &w.config.Rcap

	if w.file != nil {
		if w.shouldRotate(ts) {
			w.file.Close()
			w.file = nil
		}
	}

	if w.file == nil {
		w.updateLastRotTime(ts)

		// Fill datetime format in file name format.
		fileName := w.newFileName(ts)

		// Make a directory for PCAP files.
		dirName := filepath.Dir(fileName)
		if err := os.MkdirAll(dirName, 0755); err != nil {
			return err
		}

		// Make a new file
		file, err := os.Create(fileName)
		if err != nil {
			return err
		}

		log.Printf("capture %v packets.", w.numPackets)
		log.Printf("dump packets into a file: %v", fileName)

		// Make a new writer.
		writer := pcapgo.NewWriter(file)
		writer.WriteFileHeader(uint32(c.SnapLen), w.linkType)

		w.numPackets = 0
		w.file = file
		w.writer = writer
	}

	return nil
}

// WritePacket writes packet data to the file.
func (w *Writer) WritePacket(capinfo gopacket.CaptureInfo, data []byte) error {
	w.numPackets += 1
	return w.writer.WritePacket(capinfo, data)
}

// Close closes a file in a Writer instance.
func (w *Writer) Close() error {
	err := w.file.Close()
	w.file = nil
	return err
}
