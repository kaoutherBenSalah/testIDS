"""
Network Scanner Module
Scans network for active hosts, discovers IP/MAC addresses, and identifies open ports

This module provides network reconnaissance capabilities for the attacker interface.
Results are displayed in a live table in the web interface.

Usage:
    scanner = NetworkScanner(interface='eth0')
    hosts = scanner.scan_subnet('192.168.189.0/24')
    
Author: Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane
"""

import sys
import subprocess
import socket
import ssl
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP, TCP

sys.path.append(str(Path(__file__).parent.parent))
from utils.logger import get_logger
from utils.network_utils import list_interfaces_detailed, get_default_network_range


class Host:
    """Represents a discovered network host"""

    def __init__(self, ip, mac='Unknown'):
        self.ip = ip
        self.mac = mac
        self.hostname = None
        self.open_ports: List[int] = []
        self.services: List[Dict[str, str]] = []  # [{'port': 80, 'service': 'http', 'banner': 'nginx'}, ...]
        self.is_active = True
        self.os_guess = 'Unknown'

    def to_dict(self):
        """Convert host to dictionary for JSON response"""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'open_ports': self.open_ports,
            'services': self.services,
            'is_active': self.is_active,
            'os_guess': self.os_guess
        }


class NetworkScanner:
    """
    Network Scanner for host discovery and port scanning
    
    Features:
    - ARP scan for local network discovery
    - ICMP ping sweep
    - TCP port scanning
    - MAC address resolution
    - Hostname resolution
    """
    
    def __init__(self, interface=None, timeout=1):
        """
        Initialize Network Scanner
        
        Args:
            interface (str): Network interface to use (e.g., 'eth0', 'ens33')
            timeout (int): Timeout for network requests in seconds
        """
        self.interface = interface
        self.timeout = timeout
        self.logger = get_logger("NetworkScanner")
        self.discovered_hosts = []
        self.stop_requested = False
        self.default_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    def scan_subnet(self, network_range):
        """
        Scan a subnet for active hosts using ARP requests
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., '192.168.1.0/24')
        
        Returns:
            list<Host>: List of discovered hosts
        """
        self.logger.info(f"🔍 Scanning network: {network_range}")
        self.discovered_hosts = []
        self.stop_requested = False
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
            packet = ether / arp
            
            # Send packet and receive responses
            self.logger.info("Sending ARP requests...")
            result = srp(packet, timeout=self.timeout, verbose=False, iface=self.interface)[0]
            
            if self.stop_requested:
                self.logger.info("🛑 Scan aborted before processing responses")
                return []
            
            # Process responses
            for sent, received in result:
                if self.stop_requested:
                    self.logger.info("🛑 Scan aborted during processing")
                    break
                ip = received.psrc
                mac = received.hwsrc
                
                # Skip broadcast/multicast addresses
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_multicast or str(ip).endswith('.255'):
                        continue
                except Exception:
                    pass
                
                host = Host(ip=ip, mac=mac)
                self.discovered_hosts.append(host)
                
                self.logger.info(f"  ✅ Found: {ip} ({mac})")
            
            self.logger.info(f"📊 Scan complete. Found {len(self.discovered_hosts)} hosts.")
            return self.discovered_hosts
        
        except Exception as e:
            self.logger.error(f"❌ Error during scan: {e}")
            return []
    
    def scan_ports(self, ip_address, ports=None):
        """
        Scan specific ports on a target IP
        
        Args:
            ip_address (str): Target IP address
            ports (list): List of ports to scan. If None, scans common ports.
        
        Returns:
            list<int>: List of open ports
        """
        if ports is None:
            ports = self.default_ports
        
        self.logger.info(f"🔍 Scanning ports on {ip_address}")
        open_ports = []
        
        for port in ports:
            if self.stop_requested:
                self.logger.info("🛑 Port scan aborted")
                break
            try:
                # Create TCP SYN packet
                packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=0.5, verbose=False)

                # Check if port is open (SYN-ACK response)
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        self.logger.info(f"  ✅ Port {port} is OPEN")

                        # Send RST to close connection
                        rst = IP(dst=ip_address) / TCP(dport=port, flags="R")
                        sr1(rst, timeout=1, verbose=False)
            
            except Exception as e:
                pass  # Silently continue on errors
        
        self.logger.info(f"📊 Port scan complete. Found {len(open_ports)} open ports.")
        return open_ports

    def stop(self):
        """Signal the scanner to stop after current operation."""
        self.stop_requested = True
    
    def identify_active_machines(self, network_range=None, full_scan=False):
        """
        Identify all active machines on network
        Alias for scan_subnet with optional port scanning
        
        Args:
            network_range (str): Network range in CIDR notation
            full_scan (bool): When True, also perform port scan and OS guess
        
        Returns:
            list<Host>: List of active hosts with detailed info
        """
        if not network_range:
            network_range = get_default_network_range(self.interface) or '192.168.1.0/24'

        hosts = self.scan_subnet(network_range)
        
        if not full_scan:
            return hosts
        
        # For each host, gather additional information
        for host in hosts:
            if self.stop_requested:
                self.logger.info("🛑 Full scan aborted")
                break
            self.logger.info(f"🔍 Gathering info for {host.ip}...")
            
            # Hostname resolution (try multiple times for better results)
            self.logger.info(f"🔎 Resolving hostname for {host.ip}...")
            host.hostname = self._resolve_hostname(host.ip)
            if not host.hostname:
                self.logger.info(f"⚠️  First attempt failed, retrying {host.ip}...")
                # Retry with a small delay for DHCP/DNS propagation
                import time
                time.sleep(0.2)
                host.hostname = self._resolve_hostname(host.ip)
            
            if host.hostname:
                self.logger.info(f"✅ Resolved {host.ip} -> {host.hostname}")
            else:
                self.logger.warning(f"❌ Could not resolve hostname for {host.ip}")

            # Scan common ports
            host.open_ports = self.scan_ports(host.ip)

            # Service/banner detection
            host.services = self._detect_services(host.ip, host.open_ports)

            # Simple OS detection based on open ports
            host.os_guess = self._guess_os(host.open_ports)
        
        return hosts
    
    def ping_sweep(self, network_range):
        """
        Perform ICMP ping sweep to identify live hosts
        
        Args:
            network_range (str): Network range in CIDR notation
        
        Returns:
            list<str>: List of IP addresses that responded to ping
        """
        self.logger.info(f"🔍 Ping sweep: {network_range}")
        live_hosts = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            for ip in network.hosts():
                ip_str = str(ip)
                
                # Send ICMP echo request
                packet = IP(dst=ip_str) / ICMP()
                response = sr1(packet, timeout=1, verbose=False)
                
                if response:
                    live_hosts.append(ip_str)
                    self.logger.info(f"  ✅ {ip_str} is alive")
            
            self.logger.info(f"📊 Ping sweep complete. Found {len(live_hosts)} live hosts.")
            return live_hosts
        
        except Exception as e:
            self.logger.error(f"❌ Error during ping sweep: {e}")
            return []
    
    def get_mac_address(self, ip_address):
        """
        Get MAC address for a specific IP
        
        Args:
            ip_address (str): Target IP address
        
        Returns:
            str: MAC address or 'Unknown'
        """
        try:
            arp = ARP(pdst=ip_address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=self.timeout, verbose=False, iface=self.interface)[0]
            
            if result:
                return result[0][1].hwsrc
            return 'Unknown'
        
        except Exception as e:
            self.logger.error(f"Error getting MAC for {ip_address}: {e}")
            return 'Unknown'
    
    def display_scan_results(self):
        """
        Display scan results in a formatted table
        (For command-line use)
        """
        if not self.discovered_hosts:
            self.logger.info("No hosts discovered yet.")
            return
        
        print("\n" + "="*90)
        print("NETWORK SCAN RESULTS")
        print("="*90)
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Open Ports'}")
        print("-"*90)
        
        for host in self.discovered_hosts:
            ports_str = ','.join(map(str, host.open_ports[:10]))  # Show first 10 ports
            if len(host.open_ports) > 10:
                ports_str += '...'
            
            print(f"{host.ip:<18} {host.mac:<20} {ports_str}")
        
        print("="*90)
        print(f"Total: {len(self.discovered_hosts)} hosts discovered\n")
    
    def _guess_os(self, open_ports):
        """
        Simple OS detection based on open ports
        
        Args:
            open_ports (list): List of open ports
        
        Returns:
            str: OS guess
        """
        if not open_ports:
            return 'Unknown'
        
        # Simple heuristics
        if 3389 in open_ports:  # RDP
            return 'Windows'
        elif 22 in open_ports and 80 in open_ports:
            return 'Linux'
        elif 445 in open_ports:  # SMB
            return 'Windows'
        elif 22 in open_ports:
            return 'Linux/Unix'
        elif 80 in open_ports or 443 in open_ports:
            return 'Web Server'
        else:
            return 'Unknown'

    def _resolve_hostname(self, ip_address: str) -> Optional[str]:
        """Multi-method hostname resolution with comprehensive fallbacks."""
        
        # Method 1: Check hosts file (Windows: C:\Windows\System32\drivers\etc\hosts, Linux: /etc/hosts)
        import platform
        hosts_file = r'C:\Windows\System32\drivers\etc\hosts' if platform.system() == 'Windows' else '/etc/hosts'
        try:
            with open(hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip_address:
                            hostname = parts[1].split('.')[0]
                            self.logger.info(f"Resolved {ip_address} -> {hostname} (hosts file)")
                            return hostname
        except Exception as e:
            self.logger.debug(f"Hosts file lookup failed: {e}")
        
        # Method 2: Reverse DNS (most reliable when configured)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            if hostname and hostname != ip_address:
                short_name = hostname.split('.')[0]
                self.logger.info(f"Resolved {ip_address} -> {short_name} (reverse DNS)")
                return short_name
        except Exception as e:
            self.logger.debug(f"Reverse DNS failed for {ip_address}: {e}")
        
        # Method 3: NetBIOS lookup (Windows networks)
        try:
            result = subprocess.run(
                ["nmblookup", "-A", ip_address], 
                capture_output=True, text=True, timeout=2, stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "<00>" in line and "GROUP" not in line and "<ACTIVE>" in line:
                        parts = line.split()
                        if parts and parts[0]:
                            hostname = parts[0].strip()
                            self.logger.info(f"Resolved {ip_address} -> {hostname} (NetBIOS)")
                            return hostname
        except Exception as e:
            self.logger.debug(f"NetBIOS lookup failed: {e}")
        
        # Method 4: nmap hostname detection (when nmap is available)
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-n", "--system-dns", ip_address],
                capture_output=True, text=True, timeout=3, stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Nmap scan report for" in line:
                        parts = line.split("for")[1].strip()
                        if parts and "(" in parts:
                            hostname = parts.split("(")[0].strip()
                            if hostname and hostname != ip_address:
                                short_name = hostname.split('.')[0]
                                self.logger.info(f"Resolved {ip_address} -> {short_name} (nmap)")
                                return short_name
        except Exception as e:
            self.logger.debug(f"nmap hostname lookup failed: {e}")
        
        # Method 5: getent hosts (Linux)
        try:
            result = subprocess.run(
                ["getent", "hosts", ip_address],
                capture_output=True, text=True, timeout=1, stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1].split('.')[0]
                    self.logger.info(f"Resolved {ip_address} -> {hostname} (getent)")
                    return hostname
        except Exception as e:
            self.logger.debug(f"getent lookup failed: {e}")
        
        # Method 6: ARP cache check with hostname (Linux)
        try:
            result = subprocess.run(
                ["arp", "-a"], 
                capture_output=True, text=True, timeout=1, stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ip_address in line:
                        # Format: hostname (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        match = line.split('(')[0].strip()
                        if match and not match.startswith('?') and match != ip_address:
                            hostname = match.split('.')[0]
                            self.logger.info(f"Resolved {ip_address} -> {hostname} (ARP cache)")
                            return hostname
        except Exception as e:
            self.logger.debug(f"ARP cache lookup failed: {e}")
        
        # Method 7: Try mDNS/Avahi (for .local domains)
        try:
            result = subprocess.run(
                ["avahi-resolve", "-a", ip_address],
                capture_output=True, text=True, timeout=2, stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1].replace('.local', '').split('.')[0]
                    self.logger.info(f"Resolved {ip_address} -> {hostname} (mDNS)")
                    return hostname
        except Exception as e:
            self.logger.debug(f"mDNS lookup failed: {e}")
        
        self.logger.warning(f"Could not resolve hostname for {ip_address}")
        return None

    def _detect_services(self, ip_address: str, ports: List[int]) -> List[Dict[str, str]]:
        """Attempt to fingerprint services/banners on open ports."""
        services = []
        for port in ports:
            service_name = self._common_service_name(port)
            banner = self._grab_banner(ip_address, port, service_name)
            services.append({
                'port': port,
                'service': service_name or 'unknown',
                'banner': banner or ''
            })
        return services

    def _grab_banner(self, ip_address: str, port: int, service_hint: Optional[str]) -> Optional[str]:
        """Lightweight banner grabbing with short timeouts."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            sock.connect((ip_address, port))

            if service_hint in ['http', 'http-alt'] or port in [80, 8080, 8000]:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip_address.encode())
            elif service_hint == 'smtp' or port == 25:
                sock.sendall(b"EHLO test.local\r\n")
            elif service_hint == 'pop3' or port == 110:
                sock.sendall(b"QUIT\r\n")
            elif service_hint == 'imap' or port == 143:
                sock.sendall(b"\r\n")
            elif service_hint == 'ftp' or port == 21:
                sock.sendall(b"QUIT\r\n")

            data = sock.recv(1024)
            sock.close()
            if not data:
                return None
            # Clean and limit banner text
            banner = data.decode(errors='ignore').strip().replace('\r', '').replace('\n', ' ')
            return banner[:300] if len(banner) > 300 else banner
        except Exception:
            # Try minimal TLS client hello for 443 to extract SNI/cert CN
            if port == 443:
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ip_address) as s:
                        s.settimeout(1)
                        s.connect((ip_address, port))
                        cert = s.getpeercert()
                        if cert:
                            subject = dict(x[0] for x in cert.get('subject', []))
                            return subject.get('commonName')
                except Exception:
                    return None
            return None

    def _common_service_name(self, port: int) -> Optional[str]:
        mapping = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
            110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgres', 8080: 'http-alt', 8000: 'http-alt'
        }
        return mapping.get(port)


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def main():
    """Command-line interface for network scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('network', help='Network range (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--ports', '-p', help='Scan ports (default: common ports)', action='store_true')
    parser.add_argument('--full', '-f', help='Full scan with port scanning', action='store_true')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(interface=args.interface)
    
    if args.full:
        hosts = scanner.identify_active_machines(args.network)
    else:
        hosts = scanner.scan_subnet(args.network)
        
        if args.ports:
            for host in hosts:
                host.open_ports = scanner.scan_ports(host.ip)
    
    scanner.display_scan_results()


if __name__ == '__main__':
    main()
