import argparse
import socket
import time
from typing import Dict, List, Optional, Tuple

import nmap
from scapy.all import ARP, Ether, ICMP, IP, TCP, sr1, srp

def scan_ip_addr(ip: str) -> Optional[str]:
    """
    Purpose: Detect/validate IP address
    Input: Target IP address (string)
    Output: Validated IP address or error message with color coding
    """
    try:
        target = socket.gethostbyname(ip)
    except socket.gaierror:
        print(f"Unable to resolve target: {ip}")
        return None

    print(f"Scanning IP: {target}")
    reply = sr1(IP(dst=target) / ICMP(), timeout=2, verbose=0)
    if reply is None:
        print(f"No ICMP reply from {target}")
        return None

    print(f"Scanned. Hostname is {target}")
    return target

def scan_mac_addr(ip: str) -> Optional[str]:
    """
    Purpose: Detect MAC address
    Input: IP address string
    Output: MAC address string (e.g., "AA:BB:CC:DD:EE:FF") or None
    How to call: Use ARP protocol via scapy library (ARP() and srp() functions)
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answers, _ = srp(arp_request, timeout=2, retry=1, verbose=0)
    for _, received in answers:
        return received.hwsrc
    return None


def scan_open_ports(ip: str, port_range: Tuple[int, int]) -> List[int]:
    """
    Purpose: Detect open ports on target
    Input: IP address, port range (start, end)
    Output: List of open port numbers [22, 80, 443, ...]
    How to call: Use socket.socket() with connect_ex() to attempt TCP connections, or use scapy for SYN scanning
    """
    start_port, end_port = port_range
    open_ports: List[int] = []

    for port in range(start_port, end_port + 1):
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        reply = sr1(packet, timeout=1, verbose=0)
        if reply is None:
            continue
        if reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=1, verbose=0)

    return open_ports

def detect_service(ip: str, port: int) -> str:
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
    except Exception:
        pass
    
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

def detect_os(ip: str, open_ports: List[int]) -> str:
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
                best_match = nm[ip]["osmatch"][0]
                name = best_match.get("name", "unknown")
                accuracy = best_match.get("accuracy", "")
                if accuracy:
                    return f"{name} ({accuracy}% confidence)"
                return name
    except Exception:
        pass
    
    return "unknown"

def perform_full_scan(target: str, port_range: Tuple[int, int]) -> Dict[str, object]:
    """
    Purpose: Coordinate all scans and compile results
    Input: Target (hostname/IP), port range tuple
    Output: Dictionary with all scan results
    How to call: Calls all above functions in sequence and aggregates data
    """
    start_time = time.time()
    ip = scan_ip_addr(target)
    if ip is None:
        return {"error": "unreachable"}

    print("Scanning MAC address (ARP)...")
    mac = scan_mac_addr(ip)
    
    print(f"Scanning ports {port_range[0]}-{port_range[1]} (scapy SYN scan)...")
    open_ports = scan_open_ports(ip, port_range)
    
    print("Detecting services (nmap -sV)...")
    services = {port: detect_service(ip, port) for port in open_ports}
    
    print("Resolving hostname (DNS)...")
    hostname = scan_hostname(ip)
    
    print("Detecting OS (nmap -O)...")
    os_guess = detect_os(ip, open_ports)

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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -ip 192.168.1.1
  python scanner.py -mac 192.168.1.1
  python scanner.py -ports 192.168.1.1 --start 20 --end 100
  python scanner.py -service 192.168.1.1 -port 80
  python scanner.py -host 8.8.8.8
  python scanner.py -os 192.168.1.1
  python scanner.py -fs 192.168.1.1 --start 1 --end 500
        """
    )
    
    # Mutually exclusive command flags
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-ip", metavar="TARGET", help="Detect/Validate IP address")
    group.add_argument("-mac", metavar="IP", help="Detect MAC address")
    group.add_argument("-ports", metavar="IP", help="Scan open ports")
    group.add_argument("-service", metavar="IP", help="Detect service on a port")
    group.add_argument("-host", metavar="IP", help="Resolve hostname from IP")
    group.add_argument("-os", metavar="IP", help="Detect operating system")
    group.add_argument("-fs", metavar="TARGET", help="Perform full scan")
    
    # Additional options
    parser.add_argument("-port", type=int, help="Port number (for -service)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    
    args = parser.parse_args()
    
    # Check if any command was given
    if not any([args.ip, args.mac, args.ports, args.service, args.host, args.os, args.fs]):
        parser.print_help()
        return
    
    if args.ip:
        result = scan_ip_addr(args.ip)
        if result:
            print(f"Validated IP: {result}")
    
    elif args.mac:
        result = scan_mac_addr(args.mac)
        if result:
            print(f"MAC Address: {result}")
        else:
            print("Could not detect MAC address")
    
    elif args.ports:
        open_ports = scan_open_ports(args.ports, (args.start, args.end))
        if open_ports:
            print(f"Open ports: {open_ports}")
        else:
            print("No open ports found")
    
    elif args.service:
        if args.port is None:
            print("Error: -service requires -port")
            return
        service = detect_service(args.service, args.port)
        print(f"Service on port {args.port}: {service}")
    
    elif args.host:
        hostname = scan_hostname(args.host)
        if hostname:
            print(f"Hostname: {hostname}")
        else:
            print("Could not resolve hostname")
    
    elif args.os:
        os_guess = detect_os(args.os, [])
        print(f"OS Detection: {os_guess}")
    
    elif args.fs:
        result = perform_full_scan(args.fs, (args.start, args.end))
        print("\n=== Full Scan Results ===")
        for key, value in result.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()