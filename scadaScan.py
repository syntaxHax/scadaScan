import argparse
import socket
import time
import sys
import platform
import ipaddress
import os
from collections import defaultdict

# SCADA/OT-aware default ports list
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 102, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 502, 512, 513, 514, 515, 587, 631, 637, 993, 995, 1080, 1089, 1090, 1883, 1911, 1962, 2000, 2222, 2323, 2332, 2404, 2601, 3389, 4840, 4911, 5000, 5007, 5020, 5021, 5094, 5190, 5432, 5480, 5631, 5632, 5900, 5901, 6000, 8000, 8008, 8080, 8081, 8443, 8883, 8888, 9000, 9020, 9191, 9600, 9876, 9900, 10001, 12345, 20000, 22222, 24007, 24008, 24009, 44818, 47808, 50000, 50020
]

# ANSI color codes
RED = '\033[91m'
PINK = '\033[95m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

BANNER_ART = f"""
{PINK}
     /  /\\         /  /\\         /  /\\        /  /::\\        /  /\\         /  /\\         /  /\\         /  /\\         /__/\\    
    /  /:/_       /  /:/        /  /::\\      /  /:/\\:\\      /  /::\\       /  /:/_       /  /:/        /  /::\\        \\  \\:\\   
   /  /:/ /\\     /  /:/        /  /:/\\:\\    /  /:/  \\:\\    /  /:/\\:\\     /  /:/ /\\     /  /:/        /  /:/\\:\\        \\  \\:\\  
  /  /:/ /::\\   /  /:/  ___   /  /:/~/::\\  /__/:/ \\__\\:|  /  /:/~/::\\   /  /:/ /::\\   /  /:/  ___   /  /:/~/::\\   _____\\__\\:\\ 
 /__/:/ /:/\\:\\ /__/:/  /  /\\ /__/:/ /:/\\:\\ \\  \\:\\ /  /:/ /__/:/ /:/\\:\\ /__/:/ /:/\\:\\ /__/:/  /  /\\ /__/:/ /:/\\:\\ /__/::::::::\\
 \\  \\:\\/:/~/:/ \\  \\:\\ /  /:/ \\  \\:\\/:/__\\/  \\  \\:\\  /:/  \\  \\:\\/:/__\\/ \\  \\:\\/:/~/:/ \\  \\:\\ /  /:/ \\  \\:\\/:/__\\/ \\  \\:\\~~\\~~\\/
  \\  \\::/ /:/   \\  \\:\\  /:/   \\  \\::/        \\  \\:\\/:/    \\  \\::/       \\  \\::/ /:/   \\  \\:\\  /:/   \\  \\::/       \\  \\:\\  ~~~ 
   \\__\\/ /:/     \\  \\:\\/:/     \\  \\:\\         \\  \\::/      \\  \\:\\        \\__\\/ /:/     \\  \\:\\/:/     \\  \\:\\        \\  \\:\\     
     /__/:/       \\  \\::/       \\  \\:\\         \\__\\/        \\  \\:\\         /__/:/       \\  \\::/       \\  \\:\\        \\  \\:\\    
     \\__\\/         \\__\\/         \\__\\/                       \\__\\/         \\__\\/         \\__\\/         \\__\\/         \\__\\/    
{YELLOW}
    The Safe(-er?) SCADA/OT Port Enumeration Tool
{RESET}
"""

def show_help():
    print(BANNER_ART)
    print(f"""{CYAN}
USAGE:
  python3 scadaScan.py --ip 192.168.10.15
    - Scan a single IP with default ports and 30s delay

  python3 scadaScan.py --file /path/to/scope.txt --ports /path/to/ports.txt --sleep 45
    - Scan a list of IPs, use custom ports, and delay 45 seconds between probes

  python3 scadaScan.py --ip 192.168.10.15 --interface eth0
    - (Linux) Scan using a specific network interface (requires root)

  python3 scadaScan.py --ip 192.168.10.15 --interface 192.168.1.101
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
{RESET}""")
    sys.exit(0)

def parse_args():
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', help='Target IP address')
    group.add_argument('--file', help='File containing list of IP addresses')
    parser.add_argument('--ports', help='File containing list of ports')
    parser.add_argument('--sleep', type=int, default=30, help='Delay (in seconds) between connections. Default is 30.')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout for banner grabbing (default: 3s)')
    parser.add_argument('--interface', '-i', help='Interface to use (Linux: eth0, Windows: local IP)')
    parser.add_argument('--output', default='output.txt', help='Specify output file (default: output.txt)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose banner output and debugging')
    return parser.parse_args()

def load_targets(args):
    try:
        if args.file:
            with open(args.file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            return [args.ip]
    except FileNotFoundError:
        print(f"{RED}[!] File not found: {args.file}{RESET}")
        sys.exit(1)

def load_ports(args):
    try:
        ports = []
        if args.ports:
            with open(args.ports, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.isdigit() and 1 <= int(line) <= 65535:
                        ports.append(int(line))
                    elif line:
                        print(f"{YELLOW}[!] Skipping invalid port entry: {line}{RESET}")
            if not ports:
                print(f"{YELLOW}[!] No valid ports found in {args.ports}. Falling back to default port list.{RESET}")
                return DEFAULT_PORTS
            return ports
    except FileNotFoundError:
        print(f"{RED}[!] Port list file not found: {args.ports}{RESET}")
        sys.exit(1)
    return DEFAULT_PORTS

def scan_port(ip, port, timeout=5, interface=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if interface:
                if platform.system() == 'Linux':
                    try:
                        s.setsockopt(socket.SOL_SOCKET, 25, interface.encode())
                    except PermissionError:
                        print(f"{RED}[!] Root privileges are required to bind to interface '{interface}' on Linux.{RESET}")
                        return False
                elif platform.system() == 'Windows':
                    s.bind((interface, 0))
            s.connect((ip, port))
            return True
        except (socket.timeout, socket.error, OSError):
            return False

def grab_banner(ip, port, timeout=3, interface=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)

            if interface:
                if platform.system() == 'Linux':
                    try:
                        s.setsockopt(socket.SOL_SOCKET, 25, interface.encode())
                    except PermissionError:
                        return f"Permission denied binding to interface {interface} — try running as root"
                elif platform.system() == 'Windows':
                    s.bind((interface, 0))

            s.connect((ip, port))

            probe = None
            if port in [80, 8080, 8000, 8888]:
                probe = b"GET / HTTP/1.0\r\n\r\n"
            elif port == 21:
                probe = b"\r\n"
            elif port == 502:
                probe = b"\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01"
            elif port == 20000:
                probe = b"\x05\x64\x01\x00\x00\x00\xc0\x01\x00\x00"

            # Send probe if defined for known ports only
            if probe:
                s.send(probe)
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass  # prevent shutdown exception if already closed

                try:
                    banner = s.recv(2048)
                    return banner.decode(errors='ignore').strip()
                except (socket.timeout, socket.error) as e:
                    return f"No banner received: {e}"
            else:
                return "No probe available for this port"
    except (socket.error, OSError) as e:
        return f"Socket error: {e}"

def main():
    args = parse_args()
    delay = args.sleep
    interface = args.interface
    verbose = args.verbose
    output_file = args.output
    targets = load_targets(args)
    ports = load_ports(args)
    open_ports = defaultdict(list)
    banners = {}

    if os.path.exists(output_file):
        print(f"{YELLOW}[!] Warning: {output_file} already exists and will be overwritten.{RESET}")

    with open(output_file, "w") as output:
        print(BANNER_ART)
        output.write(BANNER_ART + "\n\n")

        output.write("========== SCADA/OT Port Scan ==========\n")
        print(f"{CYAN}========== SCADA/OT Port Scan =========={RESET}")

        for ip in targets:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"{RED}[!] Invalid IP address: {ip}{RESET}")
                continue

            print(f"\n{YELLOW}[*] Scanning Target: {ip}{RESET}")
            output.write(f"\n[*] Scanning Target: {ip}\n")
            for port in ports:
                print(f"   [~] Checking {ip}:{port}...", end="")
                sys.stdout.flush()
                if scan_port(ip, port, timeout=args.timeout, interface=interface):
                    print(f"{GREEN} OPEN{RESET}")
                    open_ports[ip].append(port)
                    output.write(f"[+] {ip}:{port} OPEN\n")
                else:
                    print(f"{RED} CLOSED{RESET}")
                    output.write(f"[-] {ip}:{port} CLOSED\n")
                time.sleep(delay)

        print(f"\n{CYAN}========== Scan Summary =========={RESET}")
        output.write("\n========== Scan Summary ==========\n")
        for ip, port_list in open_ports.items():
            port_str = ', '.join(map(str, port_list))
            print(f"{GREEN}[+] {ip}: Open Ports -> {port_str}{RESET}")
            output.write(f"[+] {ip}: Open Ports -> {port_str}\n")

        print(f"\n{CYAN}========== Banner Grabbing =========={RESET}")
        output.write("\n========== Banner Grabbing ==========\n")
        for ip, port_list in open_ports.items():
            for port in port_list:
                print(f"{YELLOW}[*] Grabbing banner from {ip}:{port}...{RESET}")
                banner = grab_banner(ip, port, timeout=args.timeout, interface=interface)
                banners[f"{ip}:{port}"] = banner
                output.write(f"\n[{ip}:{port}] Banner:\n{banner}\n")
                time.sleep(delay)

        print(f"\n{CYAN}========== Banners =========={RESET}")
        for key, banner in banners.items():
            banner_stripped = banner.strip()
            if verbose:
                print(f"{GREEN}[{key}] Banner:{RESET}\n{banner_stripped}\n")
            else:
                preview = banner_stripped.splitlines()[0] if banner_stripped else "No banner"
                print(f"{GREEN}[{key}]{RESET} {preview}")

    print(f"{CYAN}[+] {len(targets)} host(s) scanned. {sum(len(v) for v in open_ports.values())} open port(s) found.{RESET}")
    print(f"{CYAN}[+] Scan complete. Results saved to {output_file}{RESET}")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(1)
