# rcap-go

I just want a utility to capture traffic for honeypot monitoring.
But existing utilities such as tcpdump and tshark do not satisfy my needs, so I
wrote `rcap-go`.

`rcap-go` is a traffic-capturing utility with the following functions.

* rotation of pcap files every specified interval (even if no packets are
  captured).
* timezone of pcap files.
* random sampling of packets.
* configuration file.
* logging.


## Requirements

* libpcap-dev


### Ubuntu

```bash
$ apt install libpcap-dev
```

## Compilation

Compiled binary is available (only for Linux).


## Usage

```bash
$ ./rcap -h
Usage of ./rcap:
  -L string
    	log file.
  -T int
    	rotation interval [sec]. (default 60)
  -c string
    	config file (other arguments are ignored).
  -f string
    	BPF rules.
  -i string
    	device name (e.g. en0, eth0).
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

```bash
# capture daily traffic of HTTP (80/tcp) and rotation will be done at 00:00 (UTC).
$ ./rcap -i en0 -w http-%Y%m%d.pcap -f "tcp and port 80" -T 86400
```

```bash
# capture daily traffic and rotation will be done at 09:00 (i.e. 00:00 (JST)).
# the time format of pcap files are filled with the timezone "Asia/Tokyo".
$ ./rcap -i en0 -w traffic-%Y%m%d.pcap -T 86400 -offset 54000 -z Asia/Tokyo
```

NOTE:
In this case, JST is ahead of UTC by 32400 (=3600 * 9) seconds, so the offset
is 54000 (=86400 - 32400) seconds.

You can find your timezone string here:
https://en.wikipedia.org/wiki/List_of_tz_database_time_zones


### Configuration file

See rcap.toml.

## Limitations

### Run as daemon?

Many services in Linux run as daemon.
But golang does not support daemon officially because of some technical
reasons, so I do not implement this program as a daemon.
(See "[runtime: support for daemonize #227](https://github.com/golang/go/issues/227)")

Use systemd or supervisord instead.


## TODO?

* Check performance.
* Add a unit file of systemd.
* Make documents rich.

## License

MIT License ([link](https://opensource.org/licenses/MIT)).


## Contact

md (E-mail: md.irohas at gmail.com)


