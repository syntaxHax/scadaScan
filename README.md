# scadaScan
---
The Safe(-er?) SCADA/OT Port Enumeration Tool

USAGE:

`python3 scadaScan.py --ip 192.168.10.15`
- Scan a single IP with default ports and 30s delay

`python3 scadaScan.py --file /path/to/scope.txt --ports /path/to/ports.txt --sleep 45`
- Scan a list of IPs, use custom ports, and delay 45 seconds between probes

`python3 scadaScan.py --ip 192.168.10.15 --interface eth0`
- (Linux) Scan using a specific network interface (requires root)

`python3 scadaScan.py --ip 192.168.10.15 --interface 192.168.1.101`
- (Windows) Scan using a specific NIC by binding to its local IP address

OPTIONS:
  --ip <ip_address>             Scan a single IP address
  --file <targets.txt>          Scan multiple IPs from a file (one per line)
  --ports <ports.txt>           Optional port list file (one port per line)
  --sleep <seconds>             Delay in seconds between connections (default: 30)
  --timeout <seconds>           Timeout for socket connections (default: 3)
  --interface, -i <interface>   Specify interface to use:
                                  Linux  → interface name (e.g., eth0, wlan0)
                                  Windows → local IP bound to the desired NIC
  --output <file.txt>           Specify custom output file (default: output.txt)
  --verbose                     Enable verbose banner output and debugging
  -h, --help                    Show this help message and exit
