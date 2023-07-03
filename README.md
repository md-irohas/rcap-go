# rcap-go

![Release](https://github.com/md-irohas/rcap-go/actions/workflows/release.yml/badge.svg)
![Build and Tests](https://github.com/md-irohas/rcap-go/actions/workflows/build.yml/badge.svg)
[![codecov](https://codecov.io/gh/md-irohas/rcap-go/branch/master/graph/badge.svg?token=QMU3RTHEBE)](https://codecov.io/gh/md-irohas/rcap-go)

The `rcap` is a simple packet capturing utility written in Go.

I just want a utility to capture traffic for honeypot monitoring.
But existing utilities such as tcpdump and tshark do not satisfy my needs, so I wrote the `rcap`.

The `rcap` has the following functions.

* Dumping packets to files as PCAP format.
* Rotating pcap files every specified interval with offset (even if no packets are captured).
* Flexible filename format (timezone-aware).
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
$ ./rcap --help
Usage of ./rcap:
  -L string
        [deprecated] log file.
  -S    use system time as a time source of rotation (default: use packet-captured time).
  -T int
        rotation interval [sec]. (default 60)
  -append
        append data to a file if it exists. (default true)
  -c string
        config file (other arguments will be ignored).
  -f string
        BPF rules.
  -i string
        device name (e.g. en0, eth0). (default "any")
  -offset int
        [deprecated] rotation interval offset [sec].
  -p    do NOT put into promiscuous mode. (default true)
  -s uint
        snapshot length. (default 65535)
  -sampling float
        sampling rate (0 <= p <= 1). (default 1)
  -t uint
        timeout of reading packets from interface [milli-sec]. (default 100)
  -utcoffset duration
        rotation interval offset from UTC [sec]. The negative value is also available.
  -v    show version and exit.
  -w string
        format of output file. (default "dump/%Y%m%d/traffic-%Y%m%d%H%M%S.pcap")
  -z string
        timezone used for output file. (default "UTC")
```


### Examples

Example-1: Capture traffic of HTTP (80/tcp) on the interface 'en0' and files are rotated at every 00:00 (UTC).

```sh
$ ./rcap -i en0 -w http-%Y%m%d.pcap -f "tcp and port 80" -T 86400
```

Example-2: Capture the whole traffic on the interface 'en0' and files are rotated at every 09:00 (i.e., 00:00 (JST)).
Plus, the filename of pcap files are filled with time (timezone "Asia/Tokyo").

```sh
$ ./rcap -i en0 -w traffic-%Y%m%d.pcap -T 86400 -utcoffset 9h -z Asia/Tokyo
```

You can find your timezone string here:
https://en.wikipedia.org/wiki/List_of_tz_database_time_zones


### Configuration file

See [rcap.toml.orig](rcap.toml.orig).


### Systemd

`rcap.service.orig` is a template unit file of systemd.
Edit it and start/enable the service.

```sh
# Copy systemd's unit file to systemd's directory.
$ cp -vi rcap.service.orig /etc/systemd/system/rcap.service

# Edit the unit file.
$ vim /etc/systemd/system/rcap.service
...(edit)...

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


## Alternatives

- tcpdump
- tshark
- dumpcap


## License

MIT License ([link](https://opensource.org/licenses/MIT)).


## Contact

mkt (E-mail: md.irohas at gmail.com)

