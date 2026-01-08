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

from scapy.all import ARP, Ether, IP, TCP, UDP, srp, sniff

from utils.logger import get_logger
from utils.network_utils import get_default_network_range, get_local_ip

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
        self.local_ip = get_local_ip(interface)

        # Whitelist: trusted IPs (gateway, legitimate servers)
        self.whitelist = {
            '192.168.111.1',      # Gateway
            '192.168.111.2', 
            '192.168.111.254', 
            '192.168.111.12',
            '8.8.8.8',            # Google (common external IP)
            '8.8.4.4',            
            '1.1.1.1',            # Cloudflare
            '1.0.0.1',
            '127.0.0.1',          # Localhost
            '::1'                 # IPv6 localhost
        }
        
        self.logger = get_logger("IDSMonitor")
        self.running = threading.Event()
        self.threads: List[threading.Thread] = []
        self.alerts: List[Alert] = []
        self.alert_cooldowns: Dict[str, float] = {}
        self.syn_history: Dict[str, List[tuple]] = defaultdict(list)  # dst_ip -> [(ts, src_ip)]
        self.arp_table: Dict[str, str] = {}  # ip -> mac (baseline learned mappings)
        self.port_scan_tracker: Dict[str, List[tuple]] = defaultdict(list)  # src_ip -> [(ts, dst_port)]
        self.local_attackers: Dict[str, int] = defaultdict(int)  # Track local IPs sending spoofed packets (suspicious pattern)

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

    # ------------------------------------------------------------------
    # Detection logic (PASSIVE - no network scanning)
    # ------------------------------------------------------------------
    def _detect_local_attacker(self, spoofed_sources: set, dst_ip: str) -> Optional[str]:
        """
        Detect which local machine is generating spoofed packets.
        Strategy: Check the ARP table and port scanner history to find which
        local IP has been active and is most likely the attacker.
        """
        try:
            import ipaddress
            network = ipaddress.ip_network(self.network_range, strict=False)
            
            # Get all local IPs that have been seen in port scan history
            # (port scanners typically probe before launching attacks)
            local_suspects = {ip for ip in self.port_scan_tracker.keys() 
                            if ipaddress.ip_address(ip) in network}
            
            # If we found local IPs that were actively scanning, one of them is likely the attacker
            if local_suspects:
                # Return the one with most port scan activity
                suspect = max(local_suspects, 
                            key=lambda ip: len(self.port_scan_tracker.get(ip, [])))
                return suspect
            
            # Fallback: Check if any known local IPs sent unusual traffic
            # Look for IPs in the 192.168.111.x range that we've seen
            for src_ip in self.arp_table.keys():
                try:
                    if ipaddress.ip_address(src_ip) in network:
                        return src_ip
                except:
                    pass
        except Exception as e:
            self.logger.debug(f"Attacker detection error: {e}")
        
        return None

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

        # Do not count our own responses (SYN-ACKs) as attack traffic
        if self.local_ip and src_ip == self.local_ip:
            return

        # 1. SYN flood detection
        # Only count pure SYN (not SYN-ACK) to avoid misattributing defender responses
        if (tcp_layer.flags & 0x02) and not (tcp_layer.flags & 0x10):
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
                self.stats["syn_events"] += 1  # Increment ONLY when alert is raised
                
                # Collect all source IPs from this attack window
                all_sources = {s for _, s in filtered}
                
                # Detect the local machine that's generating these spoofed packets
                local_attacker = self._detect_local_attacker(all_sources, dst_ip)
                
                # Find the most frequent source IP for reference
                source_counts = {}
                for _, src in filtered:
                    source_counts[src] = source_counts.get(src, 0) + 1
                top_source = max(source_counts, key=source_counts.get) if source_counts else "unknown"
                
                summary = (
                    f"SYN FLOOD: {syn_count} SYNs to {dst_ip} in {self.syn_window_sec}s "
                    f"from {unique_sources} sources (attacker: {local_attacker or 'unknown'})"
                )
                details = {
                    "dst_ip": dst_ip,
                    "src_ip": local_attacker or top_source,  # Block the LOCAL attacker, not spoofed IP
                    "local_attacker_ip": local_attacker,  # Actual local machine doing the spoofing
                    "syn_count": syn_count,
                    "window_seconds": self.syn_window_sec,
                    "unique_sources": unique_sources,
                    "top_sources": list(source_counts.keys())[:5],  # Spoofed source IPs for reference
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
                # Only include top 10 ports in alert, not all ports (keeps alert compact)
                all_ports = sorted(list(set(p for _, p in filtered_scans)))
                top_ports = all_ports[:10]
                details = {
                    "src_ip": src_ip,
                    "unique_ports": unique_ports,
                    "ports_scanned": top_ports,
                    "ports_truncated": len(all_ports) > 10,
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
