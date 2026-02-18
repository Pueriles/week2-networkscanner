import socket
import time
from typing import Dict, List, Optional, Tuple
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
        with socket.create_connection((ip, port), timeout=2) as conn:
            conn.settimeout(2)
            try:
                banner = conn.recv(1024)
                if banner:
                    return banner.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass
    except (OSError, ConnectionError):
        pass

    try:
        return socket.getservbyport(port)
    except OSError:
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
    reply = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
    if reply is None or not reply.haslayer(IP):
        return "unknown"

    ttl = reply.getlayer(IP).ttl
    if ttl >= 128:
        return "Windows (TTL>=128)"
    if ttl >= 64:
        return "Linux/Unix (TTL>=64)"
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

    mac = scan_mac_addr(ip)
    open_ports = scan_open_ports(ip, port_range)
    services = {port: detect_service(ip, port) for port in open_ports}
    hostname = scan_hostname(ip)
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
    CLI entry point with interactive inputs.
    """
    print("Network Scanner Guide")
    print("Run this program from a terminal and use the guide below to choose a command.")
    print("-ip {target}) = Detect/Validate IP address")
    print("-m {ip}) = Detect/Validate MAC address")
    print("-v {ip}, {port}) Detect Services")
    print("-h {ip}) Detect Hostname")
    print("-os {ip}, {open_ports}) Detect OS")
    print("-fs {target}, {port_range}) Perform full scan")

    # Use arguments example: "py scanner.py -ip 192.168.1.10"

if __name__ == "__main__":
    main()