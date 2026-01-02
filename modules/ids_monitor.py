"""
Intrusion Detection Monitor
- Periodic ARP anomaly scan (detects duplicated MAC -> IP mappings)
- Live TCP SYN rate monitor (basic SYN flood heuristic)

Designed to be light-weight and extensible for future detectors.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from scapy.all import ARP, Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, srp, sniff

from utils.logger import get_logger
from utils.network_utils import get_default_network_range

Alert = Dict[str, object]


class IDSMonitor:
    """Background IDS monitor combining ARP anomaly checks and SYN-rate detection."""

    def __init__(
        self,
        interface: Optional[str] = None,
        network_range: Optional[str] = None,
        arp_interval: int = 20,
        syn_threshold: int = 150,
        syn_window_sec: int = 10,
        syn_unique_sources: int = 15,
        alert_sink: Optional[Callable[[Alert], None]] = None,
    ):
        self.interface = interface
        self.network_range = network_range or get_default_network_range(interface) or "192.168.1.0/24"
        self.arp_interval = max(5, arp_interval)
        self.syn_threshold = max(20, syn_threshold)
        self.syn_window_sec = max(3, syn_window_sec)
        self.syn_unique_sources = max(5, syn_unique_sources)
        self.alert_sink = alert_sink

        # Whitelist: trusted IPs (gateway, servers)
        self.whitelist = {'192.168.111.1', '192.168.111.2', '192.168.111.254', '192.168.111.12'}
        
        self.logger = get_logger("IDSMonitor")
        self.running = threading.Event()
        self.threads: List[threading.Thread] = []
        self.alerts: List[Alert] = []
        self.alert_cooldowns: Dict[str, float] = {}
        self.syn_history: Dict[str, List[tuple]] = defaultdict(list)  # dst_ip -> [(ts, src_ip)]
        self.arp_table: Dict[str, str] = {}  # ip -> mac (baseline learned mappings)
        self.port_scan_tracker: Dict[str, List[tuple]] = defaultdict(list)  # src_ip -> [(ts, dst_port)]
        self.dns_cache: Dict[str, str] = {}  # domain -> expected_ip (legitimate mappings)

        self.stats = {
            "started_at": None,
            "packets_seen": 0,
            "alerts": 0,
            "arp_scans": 0,
            "syn_events": 0,
            "port_scans": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self):
        if self.running.is_set():
            return
        self.running.set()
        self.stats["started_at"] = datetime.utcnow().isoformat() + "Z"

        self.threads = [
            threading.Thread(target=self._arp_spoof_sniff_loop, name="IDS-ARP-SPOOF", daemon=True),
            threading.Thread(target=self._syn_sniff_loop, name="IDS-SYN", daemon=True),
            threading.Thread(target=self._dns_sniff_loop, name="IDS-DNS", daemon=True),
        ]
        for t in self.threads:
            t.start()
        self.logger.info(
            f"IDS monitor started (iface={self.interface or 'auto'}, range={self.network_range}, "
            f"arp_interval={self.arp_interval}s, syn_threshold={self.syn_threshold}/{self.syn_window_sec}s)"
        )

    def stop(self):
        self.running.clear()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1)
        self.logger.info("IDS monitor stopped")

    def get_status(self) -> Dict[str, object]:
        return {
            "running": self.running.is_set(),
            "interface": self.interface,
            "network_range": self.network_range,
            "config": {
                "arp_interval": self.arp_interval,
                "syn_threshold": self.syn_threshold,
                "syn_window_sec": self.syn_window_sec,
                "syn_unique_sources": self.syn_unique_sources,
            },
            "stats": self.stats,
            "alerts": list(self.alerts)[-50:],
        }

    def ack_alert(self, alert_id: str) -> bool:
        for alert in self.alerts:
            if alert.get("id") == alert_id:
                alert["acknowledged"] = True
                return True
        return False

    # ------------------------------------------------------------------
    # Internal loops (PASSIVE SNIFFING ONLY - NO NETWORK SCANNING)
    # ------------------------------------------------------------------
    def _syn_sniff_loop(self):
        # Use short sniffs with timeout so we can react to stop events
        while self.running.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter="tcp",
                    prn=self._handle_tcp_packet,
                    store=False,
                    timeout=3,
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"TCP sniff failed: {exc}")
                time.sleep(2)

    def _arp_spoof_sniff_loop(self):
        """Detect ARP spoofing by monitoring for gratuitous/unsolicited ARP replies."""
        arp_seen = {}  # Track {(src_ip, mac): timestamp}
        while self.running.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=lambda pkt: self._handle_arp_packet(pkt, arp_seen),
                    store=False,
                    timeout=3,
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"ARP spoof sniff failed: {exc}")
                time.sleep(2)

    def _dns_sniff_loop(self):
        """Detect DNS spoofing by monitoring DNS responses"""
        while self.running.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter="udp port 53",
                    prn=self._handle_dns_packet,
                    store=False,
                    timeout=3,
                )
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"DNS sniff failed: {exc}")
                time.sleep(2)

    # ------------------------------------------------------------------
    # Detection logic (PASSIVE - no network scanning)
    # ------------------------------------------------------------------
    def _handle_tcp_packet(self, packet):
        """Handle TCP packets for both SYN flood and port scan detection."""
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        self.stats["packets_seen"] += 1
        tcp_layer = packet[TCP]
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = tcp_layer.dport
        ts = time.time()

        # Skip whitelisted sources
        if src_ip in self.whitelist:
            return

        # 1. SYN flood detection
        if tcp_layer.flags & 0x02:  # SYN flag
            self.stats["syn_events"] += 1
            history = self.syn_history[dst_ip]
            history.append((ts, src_ip))
            window_start = ts - self.syn_window_sec
            filtered = [(t, s) for t, s in history if t >= window_start]
            self.syn_history[dst_ip] = filtered

            syn_count = len(filtered)
            unique_sources = len({s for _, s in filtered})

            cooldown_until = self.alert_cooldowns.get(dst_ip, 0)
            if (
                syn_count >= self.syn_threshold
                and unique_sources >= self.syn_unique_sources
                and ts >= cooldown_until
            ):
                summary = (
                    f"SYN FLOOD: {syn_count} SYNs to {dst_ip} in {self.syn_window_sec}s "
                    f"from {unique_sources} sources"
                )
                details = {
                    "dst_ip": dst_ip,
                    "syn_count": syn_count,
                    "window_seconds": self.syn_window_sec,
                    "unique_sources": unique_sources,
                }
                self._raise_alert("SYN_FLOOD_DETECTED", summary, "critical", details)
                self.alert_cooldowns[dst_ip] = ts + self.syn_window_sec

        # 2. Port scan detection (track ports hit by each source)
        scan_history = self.port_scan_tracker[src_ip]
        scan_history.append((ts, dst_port))
        window_start = ts - 10  # 10-second window
        filtered_scans = [(t, p) for t, p in scan_history if t >= window_start]
        self.port_scan_tracker[src_ip] = filtered_scans

        unique_ports = len({p for _, p in filtered_scans})
        
        # If source hits 10+ unique ports in 10 seconds, it's a port scan
        if unique_ports >= 10:
            cooldown_key = f"port_scan_{src_ip}"
            cooldown_until = self.alert_cooldowns.get(cooldown_key, 0)
            if ts >= cooldown_until:
                self.stats["port_scans"] += 1
                summary = f"PORT SCAN DETECTED: {src_ip} scanned {unique_ports} ports in 10s"
                details = {
                    "src_ip": src_ip,
                    "unique_ports": unique_ports,
                    "ports_scanned": list({p for _, p in filtered_scans}),
                    "window_seconds": 10,
                }
                self._raise_alert("PORT_SCAN_DETECTED", summary, "high", details)
                self.alert_cooldowns[cooldown_key] = ts + 60

    def _handle_arp_packet(self, packet, arp_seen):
        """Detect ARP spoofing by tracking MAC changes for each IP."""
        if not packet.haslayer(ARP):
            return
        
        arp_layer = packet[ARP]
        is_reply = arp_layer.op == 2
        
        if not is_reply:
            return
        
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        
        # Skip whitelisted IPs (gateway, trusted servers)
        if src_ip in self.whitelist:
            return
        
        # Learn the baseline: first time seeing this IP, record its MAC
        if src_ip not in self.arp_table:
            self.arp_table[src_ip] = src_mac
            return
        
        # Check if MAC changed for this IP (ARP spoofing!)
        expected_mac = self.arp_table[src_ip]
        if src_mac != expected_mac:
            # MAC changed! This is ARP spoofing
            ts = time.time()
            cooldown_key = f"arp_spoof_{src_ip}"
            cooldown_until = self.alert_cooldowns.get(cooldown_key, 0)
            if ts >= cooldown_until:
                summary = f"ARP SPOOFING DETECTED: {src_ip} changed MAC from {expected_mac} to {src_mac}"
                details = {
                    "ip": src_ip,
                    "original_mac": expected_mac,
                    "spoofed_mac": src_mac,
                    "attack_type": "arp_spoof",
                }
                self._raise_alert("ARP_SPOOF_DETECTED", summary, "critical", details)
                self.alert_cooldowns[cooldown_key] = ts + 60
                self.logger.warning(f"ARP SPOOF: {src_ip} MAC changed {expected_mac} -> {src_mac}")

    def _handle_dns_packet(self, packet):
        """Handle DNS packets for spoofing detection"""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(IP):
                return
            
            dns_layer = packet[DNS]
            ip_layer = packet[IP]
            ts = time.time()
            
            # Only process DNS responses
            if dns_layer.qr == 1:  # Response
                src_ip = ip_layer.src
                
                # Skip whitelisted IPs
                if src_ip in self.whitelist:
                    return
                
                # Extract query and answer
                if dns_layer.qd and dns_layer.an:
                    query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                    
                    # Get answered IP
                    for i in range(dns_layer.ancount):
                        try:
                            answer = dns_layer.an[i]
                            if answer.type == 1:  # A record
                                resolved_ip = answer.rdata
                                
                                # Check if we've seen legitimate resolution for this domain
                                if query_name in self.dns_cache:
                                    legitimate_ip = self.dns_cache[query_name]
                                    if resolved_ip != legitimate_ip:
                                        # Different IP - potential spoofing
                                        summary = f"DNS SPOOF: {query_name} resolved to {resolved_ip} instead of {legitimate_ip}"
                                        details = {
                                            "domain": query_name,
                                            "spoofed_ip": resolved_ip,
                                            "legitimate_ip": legitimate_ip,
                                            "source_ip": src_ip,
                                        }
                                        self._raise_alert("DNS_SPOOF_DETECTED", summary, "critical", details)
                                else:
                                    # Learn legitimate resolution
                                    self.dns_cache[query_name] = resolved_ip
                        except (AttributeError, IndexError):
                            continue
        
        except Exception as e:
            self.logger.error(f"Error handling DNS packet: {e}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _raise_alert(self, alert_type: str, summary: str, severity: str, details: Dict[str, object]):
        alert: Alert = {
            "id": f"{alert_type}-{int(time.time() * 1000)}",
            "type": alert_type,
            "summary": summary,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "acknowledged": False,
            "action": "block_or_stop",  # defender may decide action externally
        }
        self.alerts.append(alert)
        self.alerts = self.alerts[-200:]
        self.stats["alerts"] += 1

        self.logger.attack_detected(alert_type, details)
        if self.alert_sink:
            try:
                self.alert_sink(alert)
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"Alert sink failed: {exc}")


__all__ = ["IDSMonitor", "Alert"]
