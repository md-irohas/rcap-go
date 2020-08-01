# rcap-go

The `rcap` is a simple packet capturing utility written in Go.

I just want a utility to capture traffic for honeypot monitoring.
But existing utilities such as tcpdump and tshark do not satisfy my needs, so I wrote the `rcap`.

The `rcap` has the following functions.

* Dumping packets to files as PCAP format.
* Rotation of pcap files every specified interval with offset (even if no packets are captured).
* Flexible filename format (timezone-aware)
* Random sampling of packets.
* Configuration file.
* Logging.


## Installation

### Requirements

* Go compiler
* libpcap-dev

### Compilation

```sh
$ go build
```

### Compiled Binaries

Compiled binaries are available (only for Linux x86_64) at GitHub release page.

See https://github.com/md-irohas/rcap-go/releases.


## Usage

```sh
$ ./rcap
Usage of ./rcap:
  -L string
    	[deprecated] log file.
  -S	use system time as a time source of rotation (default: use packet-captured time).
  -T int
    	rotation interval [sec]. (default 60)
  -c string
    	config file (other arguments will be ignored).
  -f string
    	BPF rules.
  -i string
    	device name (e.g. en0, eth0). (default "any")
  -offset int
    	rotation interval offset [sec].
  -p	do NOT put into promiscuous mode. (default true)
  -s uint
    	snapshot length. (default 65535)
  -sampling float
    	sampling rate (0 <= p <= 1). (default 1)
  -t uint
    	timeout of reading packets from interface [milli-sec]. (default 100)
  -v	show version and exit.
  -w string
    	format of output file. (default "pcap/%Y%m%d/%Y%m%d-%H%M%S.pcap")
  -z string
    	timezone used for output file. (default "Local")
```


### Examples

```sh
# capture traffic of HTTP (80/tcp) on the interface 'en0' and files are rotated at every 00:00 (UTC).
$ ./rcap -i en0 -w http-%Y%m%d.pcap -f "tcp and port 80" -T 86400
```

NOTE: files are rotated at (unixtime % 86400) == offset.

```sh
# capture the whole traffic on the interface 'en0' and files are rotated at every 09:00 (i.e., 00:00 (JST)).
# the time format of pcap files are filled with the timezone "Asia/Tokyo".
$ ./rcap -i en0 -w traffic-%Y%m%d.pcap -T 86400 -offset 54000 -z Asia/Tokyo
```

NOTE:
In this case, JST is ahead of UTC by 32400 (=3600 * 9) seconds, so the offset
is 54000 (=86400 - 32400) seconds.

You can find your timezone string here:
https://en.wikipedia.org/wiki/List_of_tz_database_time_zones


### Configuration file

See rcap.toml.orig.


### systemd

`rcap.service.orig` is a template unit file of systemd.
Edit it and start/enable the service.

```sh
# Copy systemd's unit file to systemd's directory.
$ cp rcap.service.orig /etc/systemd/system/rcap.service

# Edit the unit file.
$ vim /etc/systemd/system/rcap.service

# Start the rcap service.
$ systemctl start rcap

# (Optional) Enable the rcap service at startup.
$ systemctl enable rcap
```


## Limitations

### Run as daemon?

Many services in Linux run as daemon.
But golang does not support daemon officially because of some technical
reasons, so I do not implement this program as a daemon.
(See "[runtime: support for daemonize #227](https://github.com/golang/go/issues/227)")

Use systemd or supervisord instead.


## License

MIT License ([link](https://opensource.org/licenses/MIT)).


## Contact

mkt (E-mail: md.irohas at gmail.com)

