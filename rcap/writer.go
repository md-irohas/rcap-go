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
}

// NewWriter returns a new instance of Writer.
func NewWriter(c *Config, linkType layers.LinkType) (*Writer, error) {
	w := &Writer{
		config:      c,
		linkType:    linkType,
		lastRotTime: 0,
		numPackets:  0,
	}

	return w, nil
}

// NumPackets returns the number of packets the Writer wrote to the file.
// The number will be reset when the file is rotated.
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

func calcFirstRotTime(ts int64, interval int64, utcOffset time.Duration) int64 {
	offset := int64(utcOffset.Seconds())

	rotTime := ((ts/interval)*interval + interval) - offset
	for ts < rotTime {
		rotTime -= interval
	}

	return rotTime
}

func calcFirstRotTimeWithOffset(ts int64, interval int64, offset int64) int64 {
	rotTime := ((ts/interval)*interval + interval) + offset

	for ts < rotTime {
		rotTime -= interval
	}

	return rotTime
}

// PrintRotLog prints the last rotation time and the next rotation time to log.
func (w *Writer) PrintRotLog() {
	c := w.config.Rcap

	currentTime := time.Unix(w.lastRotTime, 0)
	nextTime := time.Unix(w.lastRotTime+c.Interval, 0)

	if c.Location != nil {
		currentTime = currentTime.In(c.Location)
		nextTime = nextTime.In(c.Location)
	}

	log.Printf("rotation time: last=%v, next=%v", currentTime, nextTime)
}

// newFileName returns a filename of PCAP file based on the given timestamp.
func makeFileName(format string, ts int64, loc *time.Location, doAppend bool) string {
	locTime := time.Unix(ts, 0).In(loc)
	filename := strftime.Format(format, locTime)

	if doAppend {
		return filename
	}

	if !FileExists(filename) {
		return filename
	}

	// If file exists, find alternative filename.
	extension := filepath.Ext(filename)
	baseFilename := filename[:len(filename)-len(extension)]

	for i := 1; FileExists(filename); i++ {
		log.Println("file already exists: ", filename)
		filename = baseFilename + "-" + strconv.Itoa(i) + extension
	}

	return filename
}

func (w *Writer) openWriter(ts int64) error {
	c := w.config.Rcap

	fileName := makeFileName(c.FileFmt, ts, c.Location, c.FileAppend)
	isNewFile := !FileExists(fileName)

	// Make a directory for PCAP files.
	dirName := filepath.Dir(fileName)
	if err := os.MkdirAll(dirName, 0755); err != nil {
		return err
	}

	// Make a new file.
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	log.Printf("dump packets into a file: %v (append: %v)", fileName, !isNewFile)

	// Make a new writer.
	writer := pcapgo.NewWriter(file)
	if isNewFile {
		writer.WriteFileHeader(uint32(c.SnapLen), w.linkType)
	}

	w.numPackets = 0
	w.file = file
	w.writer = writer

	return nil
}

// Update method updates internal timestamp and rotates the file.
func (w *Writer) Update(ts int64) error {
	c := &w.config.Rcap

	// Never rotate.
	if c.Interval == 0 {
		if w.file == nil {
			return w.openWriter(ts)
		} else {
			return nil
		}
	}

	// First time.
	if w.lastRotTime == 0 {
		var rotTime int64
		if c.UTCOffset != 0 {
			rotTime = calcFirstRotTime(ts, c.Interval, c.UTCOffset)
		} else {
			rotTime = calcFirstRotTimeWithOffset(ts, c.Interval, c.Offset)
		}
		w.lastRotTime = rotTime
		w.PrintRotLog()
		return w.openWriter(w.lastRotTime)
	}

	// Do rotate.
	if w.shouldRotate(ts) {
		log.Printf("capture %v packets.", w.numPackets)
		w.Close()
		w.lastRotTime += c.Interval
		w.PrintRotLog()
		return w.openWriter(w.lastRotTime)
	}

	// Do nothing.
	return nil
}

// WritePacket writes packet data to the file.
// Update method must be called before WritePacket to make file.
func (w *Writer) WritePacket(capinfo gopacket.CaptureInfo, data []byte) error {
	w.numPackets += 1

	// NOTE: WritePacket function calls write system call,
	// so the 'data' are copied in the write system call.
	return w.writer.WritePacket(capinfo, data)
}

// Close closes a file in a Writer instance.
func (w *Writer) Close() error {
	var err error

	if w.file != nil {
		err = w.file.Close()
	}

	w.file = nil
	return err
}
