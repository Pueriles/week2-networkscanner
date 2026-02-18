import argparse
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import nmap
from scapy.all import ARP, Ether, ICMP, IP, sr1, srp, conf, IFACES

# Disable scapy verbose output and warnings
conf.verb = 0


def get_interface_for_ip(target_ip: str) -> Optional[str]:
    """
    Find the correct network interface for reaching a target IP.
    Returns the interface name that's on the same subnet as the target.
    """
    target_octets = target_ip.split('.')[:3]
    target_prefix = '.'.join(target_octets)
    
    for iface in IFACES.values():
        if hasattr(iface, 'ip') and iface.ip:
            iface_prefix = '.'.join(iface.ip.split('.')[:3])
            if iface_prefix == target_prefix:
                return iface.name
    
    # Fallback to default
    return None


def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse an IP range string into a list of IP addresses.
    Supports formats like:
      - 192.168.1.1 (single IP)
      - 192.168.1.1-50 (range from .1 to .50)
      - 192.168.1.1-192.168.1.50 (full range)
    """
    # Check for range with hyphen
    if "-" in ip_range:
        parts = ip_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid IP range format: {ip_range}")
        
        start_ip = parts[0].strip()
        end_part = parts[1].strip()
        
        # Check if end_part is a full IP or just the last octet
        if "." in end_part:
            # Full IP range: 192.168.1.1-192.168.1.50
            end_ip = end_part
            start_octets = list(map(int, start_ip.split(".")))
            end_octets = list(map(int, end_ip.split(".")))
            
            if start_octets[:3] != end_octets[:3]:
                raise ValueError("IP range must be within the same /24 subnet")
            
            start_last = start_octets[3]
            end_last = end_octets[3]
        else:
            # Short format: 192.168.1.1-50
            start_octets = start_ip.split(".")
            if len(start_octets) != 4:
                raise ValueError(f"Invalid IP format: {start_ip}")
            
            base = ".".join(start_octets[:3])
            start_last = int(start_octets[3])
            end_last = int(end_part)
        
        if start_last > end_last:
            raise ValueError("Start IP must be less than or equal to end IP")
        if end_last > 255:
            raise ValueError("IP octet cannot exceed 255")
        
        base = ".".join(start_ip.split(".")[:3])
        return [f"{base}.{i}" for i in range(start_last, end_last + 1)]
    else:
        # Single IP
        return [ip_range]


def parse_port_range(port_range: str) -> Tuple[int, int]:
    """
    Parse a port range string into a tuple of (start, end).
    Supports formats like:
      - 80 (single port)
      - 20-100 (range from 20 to 100)
    """
    if "-" in port_range:
        parts = port_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range format: {port_range}")
        
        start_port = int(parts[0].strip())
        end_port = int(parts[1].strip())
        
        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port")
        if start_port < 1 or end_port > 65535:
            raise ValueError("Port numbers must be between 1 and 65535")
        
        return (start_port, end_port)
    else:
        # Single port
        port = int(port_range)
        if port < 1 or port > 65535:
            raise ValueError("Port number must be between 1 and 65535")
        return (port, port)

def scan_ip_addr(ip: str, verbose: bool = True) -> Optional[str]:
    """
    Purpose: Detect/validate IP address
    Input: Target IP address (string)
    Output: Validated IP address or error message with color coding
    """
    try:
        target = socket.gethostbyname(ip)
    except socket.gaierror:
        if verbose:
            print(f"[-] Unable to resolve target: {ip}")
        return None

    if verbose:
        print(f"[*] Scanning IP: {target}")
    reply = sr1(IP(dst=target) / ICMP(), timeout=2, verbose=0)
    if reply is None:
        if verbose:
            print(f"[-] No ICMP reply from {target}")
        return None

    if verbose:
        print(f"[+] Host {target} is up")
    return target


def scan_ip_range(ips: List[str], max_threads: int = 50) -> List[str]:
    """
    Scan multiple IP addresses in parallel to find live hosts.
    Uses multiple detection methods: ARP, ICMP, and TCP port probes.
    Returns list of IPs that responded.
    """
    live_hosts: List[str] = []
    
    def check_ip(ip: str) -> Optional[str]:
        try:
            target = socket.gethostbyname(ip)
        except socket.gaierror:
            return None
        
        # Method 1: ARP request (works for local network)
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answers, _ = srp(arp_request, timeout=1, retry=0, verbose=0)
            if answers:
                return target
        except Exception:
            pass
        
        # Method 2: ICMP ping
        try:
            reply = sr1(IP(dst=target) / ICMP(), timeout=1, verbose=0)
            if reply is not None:
                return target
        except Exception:
            pass
        
        # Method 3: TCP SYN to common ports
        common_ports = [80, 443, 22, 21, 25, 445, 139, 3389, 8080]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return target
            except Exception:
                pass
        
        return None
    
    print(f"[*] Scanning {len(ips)} IP(s) for live hosts...")
    with ThreadPoolExecutor(max_workers=min(max_threads, len(ips))) as executor:
        futures = {executor.submit(check_ip, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                live_hosts.append(result)
                print(f"[+] Host {result} is up")
    
    print(f"[+] Found {len(live_hosts)} live host(s)")
    return sorted(live_hosts, key=lambda x: [int(p) for p in x.split('.')])

def scan_mac_addr(ip: str) -> Optional[str]:
    """
    Purpose: Detect MAC address
    Input: IP address string
    Output: MAC address string (e.g., "AA:BB:CC:DD:EE:FF") or None
    How to call: Use ARP protocol via scapy library (ARP() and srp() functions)
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answers, _ = srp(arp_request, timeout=2, retry=1, verbose=0, iface="Ethernet 3")
    for _, received in answers:
        return received.hwsrc.upper()

    return None


def scan_open_ports(ip: str, port_range: Tuple[int, int], max_threads: int = 100) -> List[int]:
    """
    Purpose: Detect open ports on target
    Input: IP address, port range (start, end)
    Output: List of open port numbers [22, 80, 443, ...]
    How to call: Use socket.socket() with connect_ex() to attempt TCP connections
    """
    start_port, end_port = port_range
    open_ports: List[int] = []
    
    def check_port(port: int) -> Optional[int]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    
    ports_to_scan = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports_to_scan))) as executor:
        futures = {executor.submit(check_port, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    return sorted(open_ports)

def detect_service(ip: str, port: int, verbose: bool = True) -> str:
    """
    Purpose: Identify service running on each open port
    Input: IP address, port number
    Output: Service name/banner string (e.g., "SSH-2.0-OpenSSH_8.2")
    How to call: Using the nmap module with version detection enabled, this can be done with flag -sV.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, str(port), arguments="-sV")
        
        if ip in nm.all_hosts():
            if "tcp" in nm[ip] and port in nm[ip]["tcp"]:
                port_info = nm[ip]["tcp"][port]
                name = port_info.get("name", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                
                if product and version:
                    return f"{product} {version}"
                elif product:
                    return product
                elif name:
                    return name
        else:
            if verbose:
                print(f"[-] nmap: Host {ip} not found in scan results")
    except nmap.PortScannerError as e:
        if verbose:
            print(f"[-] nmap error: {e}")
    except Exception as e:
        if verbose:
            print(f"[-] Error detecting service: {e}")
    
    return "unknown"


def scan_hostname(ip: str) -> Optional[str]:
    """
    Purpose: Resolve hostname from IP
    Input: IP address string
    Output: Hostname string or None
    How to call: Use socket.gethostbyaddr() for reverse DNS lookup
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def detect_os(ip: str, open_ports: List[int], verbose: bool = True) -> str:
    """
    Purpose: Fingerprint operating system
    Input: IP address, list of open ports
    Output: OS guess string (e.g., "Linux 3.x-4.x")
    How to call: Also making use of the nmap module. To detect the OS the -O flag can be used.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O")
        
        if ip in nm.all_hosts():
            if "osmatch" in nm[ip] and nm[ip]["osmatch"]:
                # Return the best OS match
                best_match = nm[ip]["osmatch"]
                name = best_match.get("name", "unknown")
                accuracy = best_match.get("accuracy", "")
                if accuracy:
                    return f"{name} ({accuracy}% confidence)"
                return name
            else:
                if verbose:
                    print(f"[-] nmap: No OS match found for {ip}")
        else:
            if verbose:
                print(f"[-] nmap: Host {ip} not found in scan results")
    except nmap.PortScannerError as e:
        if verbose:
            print(f"[-] nmap error: {e}")
    except Exception as e:
        if verbose:
            print(f"[-] Error detecting OS: {e}")
    
    
    return "unknown"

def perform_full_scan(target: str, port_range: Tuple[int, int]) -> Dict[str, object]:
    """
    Purpose: Coordinate all scans and compile results
    Input: Target (hostname/IP), port range tuple
    Output: Dictionary with all scan results
    How to call: Calls all above functions in sequence and aggregates data
    """
    start_time = time.time()
    ip = scan_ip_addr(target, verbose=True)
    if ip is None:
        return {"error": "unreachable"}

    print("[*] Scanning MAC address...")
    mac = scan_mac_addr(ip)
    
    print(f"[*] Scanning ports {port_range[0]}-{port_range[1]}...")
    open_ports = scan_open_ports(ip, port_range)
    
    print("[*] Detecting services...")
    services = {port: detect_service(ip, port, verbose=False) for port in open_ports}
    
    print("[*] Resolving hostname...")
    hostname = scan_hostname(ip)
    
    print("[*] Detecting OS...")
    os_guess = detect_os(ip, open_ports, verbose=False)

    return {
        "target": target,
        "ip": ip,
        "mac": mac,
        "open_ports": open_ports,
        "services": services,
        "hostname": hostname,
        "os": os_guess,
        "duration_seconds": round(time.time() - start_time, 2),
    }


def main() -> None:
    """
    CLI entry point with flag-based argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="Network Scanner - Scan IP addresses, ports, and detect services",
        usage="%(prog)s -ip TARGET [-mac] [-p PORT_RANGE] [-service] [-host] [-os] [-fs] [-h]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -ip 192.168.1.1                    # Validate IP
  python scanner.py -ip 192.168.1.1-50                 # Validate IP range
  python scanner.py -ip 192.168.1.1 -mac               # Get MAC address
  python scanner.py -ip 192.168.1.1 -p 20-100          # Scan ports 20-100
  python scanner.py -ip 192.168.1.1 -p 80              # Scan port 80
  python scanner.py -ip 192.168.1.1 -service -p 80     # Detect service on port 80
  python scanner.py -ip 192.168.1.1 -host              # Resolve hostname
  python scanner.py -ip 192.168.1.1 -os                # Detect OS
  python scanner.py -ip 192.168.1.1-3 -fs -p 1-500     # Full scan
        """
    )
    
    # Required IP argument
    parser.add_argument("-ip", metavar="TARGET", required=True, help="Target IP address or range (e.g., 192.168.1.1 or 192.168.1.1-50)")
    
    # Scan type flags (can combine multiple)
    parser.add_argument("-mac", action="store_true", help="Detect MAC address")
    parser.add_argument("-service", action="store_true", help="Detect service on port(s)")
    parser.add_argument("-host", action="store_true", help="Resolve hostname from IP")
    parser.add_argument("-os", action="store_true", help="Detect operating system")
    parser.add_argument("-fs", action="store_true", help="Perform full scan")
    
    # Additional options
    parser.add_argument("-p", help="Port or port range to scan, e.g., 80 or 20-100")
    
    args = parser.parse_args()
    
    # Parse IP range
    try:
        ips = parse_ip_range(args.ip)
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    # Parse port range (only if -p specified or -fs/-service used)
    port_range = None
    if args.p:
        try:
            port_range = parse_port_range(args.p)
        except ValueError as e:
            print(f"Error: {e}")
            return
    elif args.fs:
        # Default port range for full scan
        port_range = (1, 1024)
    
    # If no scan flags specified, just validate the IP
    if not any([args.mac, args.p, args.service, args.host, args.os, args.fs]):
        if len(ips) > 1:
            live_hosts = scan_ip_range(ips)
            print(f"\n[+] Live hosts: {live_hosts}")
        else:
            result = scan_ip_addr(ips[0])
            if result:
                print(f"[+] Validated IP: {result}")
        return
    
    # For multiple IPs, first find live hosts in parallel
    if len(ips) > 1:
        print(f"[*] Discovering live hosts in range...")
        live_ips = scan_ip_range(ips)
        if not live_ips:
            print("[-] No live hosts found")
            return
    else:
        live_ips = ips
    
    # Collect results for final report
    all_results: List[Dict[str, object]] = []
    start_time = time.time()
    
    # Process each IP
    for ip in live_ips:
        result: Dict[str, object] = {"ip": ip}
        
        if len(ips) > 1:
            print(f"\n{'='*50}")
        print(f"[*] Scanning target: {ip}")
        print("="*50)
        
        if args.fs:
            scan_result = perform_full_scan(ip, port_range)
            result.update(scan_result)
            all_results.append(result)
            continue
        
        if args.mac:
            print("[*] Detecting MAC address...")
            mac = scan_mac_addr(ip)
            result["mac"] = mac
            if mac:
                print(f"[+] MAC Address: {mac}")
            else:
                print("[-] Could not detect MAC address")
        
        if args.p and not args.service:
            print(f"[*] Scanning ports {port_range[0]}-{port_range[1]}...")
            open_ports = scan_open_ports(ip, port_range)
            result["open_ports"] = open_ports
            if open_ports:
                print(f"[+] Found {len(open_ports)} open port(s): {open_ports}")
            else:
                print("[-] No open ports found")
        
        if args.service:
            if port_range is None:
                print("[-] Error: -service requires -p to specify port(s)")
                return
            print(f"[*] Scanning ports {port_range[0]}-{port_range[1]}...")
            open_ports = scan_open_ports(ip, port_range)
            result["open_ports"] = open_ports
            if not open_ports:
                print(f"[-] No open ports found in range {port_range[0]}-{port_range[1]}")
            else:
                print(f"[+] Found {len(open_ports)} open port(s)")
                print("[*] Detecting services...")
                services = {}
                for port in open_ports:
                    service = detect_service(ip, port, verbose=False)
                    services[port] = service
                    print(f"    [+] Port {port}: {service}")
                result["services"] = services
        
        if args.host:
            print("[*] Resolving hostname...")
            hostname = scan_hostname(ip)
            result["hostname"] = hostname
            if hostname:
                print(f"[+] Hostname: {hostname}")
            else:
                print("[-] Could not resolve hostname")
        
        if args.os:
            print("[*] Detecting operating system...")
            os_guess = detect_os(ip, [], verbose=False)
            result["os"] = os_guess
            print(f"[+] OS: {os_guess}")
        
        all_results.append(result)
    
    # Print final report
    duration = round(time.time() - start_time, 2)
    print("\n")
    print("="*50)
    print("                  SCAN REPORT")
    print("="*50)
    
    for result in all_results:
        ip_addr = result.get('ip', 'N/A')
        print(f"\nTarget: {ip_addr}")
        print("-"*30)
        
        if result.get("error"):
            print(f"  Status:       {result['error']}")
            continue
        
        if "mac" in result:
            print(f"  MAC Address:  {result['mac'] or 'Not found'}")
        if "hostname" in result:
            print(f"  Hostname:     {result['hostname'] or 'Not found'}")
        if "os" in result:
            print(f"  OS:           {result['os']}")
        if "open_ports" in result:
            ports = result['open_ports']
            if ports:
                print(f"  Open Ports:   {len(ports)} found")
                for port in ports:
                    service = result.get('services', {}).get(port, '')
                    if service:
                        print(f"                - {port}/tcp ({service})")
                    else:
                        print(f"                - {port}/tcp")
            else:
                print("  Open Ports:   None found")
        if "duration_seconds" in result:
            print(f"  Scan Time:    {result['duration_seconds']}s")
    
    print(f"\nTotal scan completed in {duration} seconds")
    print("="*50)


if __name__ == "__main__":
    main()