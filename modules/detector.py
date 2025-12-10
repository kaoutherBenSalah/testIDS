"""
Network Intrusion Detection System (IDS)
Detects ARP Spoofing and SYN Flood attacks in real-time

This module monitors network traffic and identifies:
1. ARP Spoofing: Duplicate IP addresses with different MAC addresses
2. SYN Flood: Abnormally high rate of TCP SYN packets

Usage:
    detector = NetworkDetector(interface='eth0', sensitivity='medium')
    detector.start_monitoring()

Author: Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane
Class: 4-ING-J-SSIR4
"""

import sys
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

# Scapy imports for packet sniffing
from scapy.all import sniff, ARP, TCP, IP

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger


class NetworkDetector:
    """
    Intrusion Detection System for monitoring network attacks
    
    This class provides real-time detection of:
    - ARP Spoofing (MAC address changes for same IP)
    - SYN Flood attacks (high rate of SYN packets)
    
    Attributes:
        interface (str): Network interface to monitor (e.g., 'eth0', 'ens33')
        sensitivity (str): Detection sensitivity ('low', 'medium', 'high')
        logger: Logger instance for alerts and events
    """
    
    def __init__(self, interface=None, sensitivity='medium'):
        """
        Initialize the Network Detector
        
        Args:
            interface (str): Network interface to sniff on. If None, uses default.
            sensitivity (str): Detection sensitivity level:
                - 'low': Higher thresholds, fewer false positives
                - 'medium': Balanced detection
                - 'high': Lower thresholds, catches more but may have false positives
        """
        self.interface = interface
        self.sensitivity = sensitivity
        self.logger = get_logger("IDS-Detector")
        
        # ARP Spoofing Detection
        # Stores: {IP_address: MAC_address}
        self.arp_table = {}
        
        # SYN Flood Detection
        # Stores timestamps of SYN packets for rate calculation
        self.syn_packets = defaultdict(deque)  # {destination_IP: deque of timestamps}
        
        # Detection thresholds based on sensitivity
        self.thresholds = self._set_thresholds(sensitivity)
        
        # Monitoring state
        self.is_monitoring = False
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        
        # Alert cooldown to prevent spam (seconds)
        self.alert_cooldown = {}  # {alert_type: last_alert_time}
        self.cooldown_period = 10  # Don't re-alert same issue within 10 seconds
        
        self.logger.info(f"🔍 IDS Detector initialized")
        self.logger.info(f"   Interface: {interface or 'default'}")
        self.logger.info(f"   Sensitivity: {sensitivity}")
        self.logger.info(f"   SYN Flood Threshold: {self.thresholds['syn_rate']} packets/sec")
    
    def _set_thresholds(self, sensitivity):
        """
        Set detection thresholds based on sensitivity level
        
        Args:
            sensitivity (str): 'low', 'medium', or 'high'
        
        Returns:
            dict: Threshold values for different attack types
        """
        thresholds = {
            'low': {
                'syn_rate': 200,      # SYN packets per second to trigger alert
                'syn_window': 5,      # Time window (seconds) for rate calculation
            },
            'medium': {
                'syn_rate': 100,
                'syn_window': 3,
            },
            'high': {
                'syn_rate': 50,
                'syn_window': 2,
            }
        }
        
        return thresholds.get(sensitivity, thresholds['medium'])
    
    def start_monitoring(self):
        """
        Start the IDS monitoring process
        
        This method begins packet sniffing and analysis. It runs indefinitely
        until stopped with Ctrl+C or stop_monitoring().
        """
        if self.is_monitoring:
            self.logger.warning("⚠️  IDS is already monitoring")
            return
        
        self.is_monitoring = True
        self.start_time = datetime.now()
        self.packet_count = 0
        self.alert_count = 0
        
        self.logger.info("=" * 70)
        self.logger.info("🚀 Starting IDS Monitoring")
        self.logger.info("=" * 70)
        self.logger.info(f"   Interface: {self.interface or 'all'}")
        self.logger.info(f"   Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"   Press Ctrl+C to stop")
        self.logger.info("=" * 70)
        
        # Start packet sniffing
        try:
            # Sniff packets and pass each to packet_handler
            # store=False: Don't keep packets in memory (for long-running monitoring)
            # prn=callback function to process each packet
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_monitoring
            )
        except KeyboardInterrupt:
            self.logger.info("\n🛑 Monitoring stopped by user")
            self.stop_monitoring()
        except Exception as e:
            self.logger.error(f"❌ Error during monitoring: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """
        Stop the IDS monitoring process
        
        Displays final statistics and cleans up resources.
        """
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("📊 IDS Monitoring Statistics")
        self.logger.info("=" * 70)
        self.logger.info(f"   Duration: {duration}")
        self.logger.info(f"   Packets Analyzed: {self.packet_count}")
        self.logger.info(f"   Alerts Generated: {self.alert_count}")
        self.logger.info("=" * 70)
    
    def _packet_handler(self, packet):
        """
        Main packet processing function
        
        This is called for EVERY packet captured by Scapy. It determines
        the packet type and routes it to the appropriate detection function.
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            
            # Display progress every 1000 packets
            if self.packet_count % 1000 == 0:
                self.logger.info(f"📦 Processed {self.packet_count} packets...")
            
            # Check for ARP packets (ARP Spoofing detection)
            if ARP in packet:
                self._detect_arp_spoofing(packet)
            
            # Check for TCP packets (SYN Flood detection)
            if TCP in packet and IP in packet:
                self._detect_syn_flood(packet)
        
        except Exception as e:
            # Don't let packet processing errors stop monitoring
            self.logger.error(f"Error processing packet: {e}")
    
    def _detect_arp_spoofing(self, packet):
        """
        Detect ARP Spoofing attacks
        
        ARP Spoofing Detection Logic:
        1. Extract IP and MAC from ARP packet
        2. Check if we've seen this IP before
        3. If yes, compare MAC addresses
        4. If MAC changed → ALERT! (possible ARP spoofing)
        
        Args:
            packet: Scapy ARP packet
        """
        try:
            # Extract ARP packet information
            # op=2 means ARP reply (op=1 is ARP request)
            if packet[ARP].op == 2:  # ARP reply
                ip_src = packet[ARP].psrc    # Source IP
                mac_src = packet[ARP].hwsrc  # Source MAC
                
                # Check if we've seen this IP before
                if ip_src in self.arp_table:
                    stored_mac = self.arp_table[ip_src]
                    
                    # MAC address changed for same IP → ALERT!
                    if stored_mac != mac_src:
                        self._trigger_alert(
                            alert_type='ARP_SPOOFING',
                            severity='HIGH',
                            message=f"ARP Spoofing Detected!",
                            details={
                                'ip': ip_src,
                                'old_mac': stored_mac,
                                'new_mac': mac_src,
                                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }
                        )
                        
                        # Update table with new MAC (attacker's MAC)
                        self.arp_table[ip_src] = mac_src
                else:
                    # First time seeing this IP, store it
                    self.arp_table[ip_src] = mac_src
        
        except Exception as e:
            self.logger.error(f"Error in ARP detection: {e}")
    
    def _detect_syn_flood(self, packet):
        """
        Detect SYN Flood attacks
        
        SYN Flood Detection Logic:
        1. Check if packet is a TCP SYN packet (flags='S')
        2. Record timestamp of this SYN packet
        3. Count SYN packets in recent time window
        4. If rate exceeds threshold → ALERT!
        
        Args:
            packet: Scapy TCP/IP packet
        """
        try:
            # Check if this is a SYN packet
            # TCP flags: S=SYN, A=ACK, F=FIN, R=RST, P=PUSH
            if packet[TCP].flags == 'S':  # SYN flag only (not SYN-ACK)
                dst_ip = packet[IP].dst
                current_time = time.time()
                
                # Add this SYN packet timestamp to the queue
                self.syn_packets[dst_ip].append(current_time)
                
                # Remove old timestamps outside the time window
                time_window = self.thresholds['syn_window']
                cutoff_time = current_time - time_window
                
                # Remove timestamps older than cutoff
                while self.syn_packets[dst_ip] and self.syn_packets[dst_ip][0] < cutoff_time:
                    self.syn_packets[dst_ip].popleft()
                
                # Calculate current rate (packets per second)
                packet_count = len(self.syn_packets[dst_ip])
                rate = packet_count / time_window
                
                # Check if rate exceeds threshold
                if rate > self.thresholds['syn_rate']:
                    self._trigger_alert(
                        alert_type='SYN_FLOOD',
                        severity='CRITICAL',
                        message=f"SYN Flood Attack Detected!",
                        details={
                            'target_ip': dst_ip,
                            'target_port': packet[TCP].dport,
                            'syn_rate': f"{rate:.1f} packets/sec",
                            'threshold': f"{self.thresholds['syn_rate']} packets/sec",
                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                    )
        
        except Exception as e:
            self.logger.error(f"Error in SYN flood detection: {e}")
    
    def _trigger_alert(self, alert_type, severity, message, details):
        """
        Trigger a security alert
        
        This function handles alert generation with cooldown to prevent spam.
        
        Args:
            alert_type (str): Type of alert (e.g., 'ARP_SPOOFING', 'SYN_FLOOD')
            severity (str): Alert severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            message (str): Alert message
            details (dict): Additional alert details
        """
        current_time = time.time()
        
        # Check cooldown to prevent duplicate alerts
        alert_key = f"{alert_type}_{details.get('ip', details.get('target_ip', 'unknown'))}"
        
        if alert_key in self.alert_cooldown:
            last_alert = self.alert_cooldown[alert_key]
            if current_time - last_alert < self.cooldown_period:
                # Too soon since last alert, skip
                return
        
        # Update cooldown
        self.alert_cooldown[alert_key] = current_time
        self.alert_count += 1
        
        # Format alert for display
        severity_emoji = {
            'LOW': '🟢',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        
        emoji = severity_emoji.get(severity, '⚠️')
        
        # Display alert
        self.logger.warning("\n" + "=" * 70)
        self.logger.warning(f"{emoji} SECURITY ALERT - {severity}")
        self.logger.warning("=" * 70)
        self.logger.warning(f"   Type: {alert_type}")
        self.logger.warning(f"   Message: {message}")
        for key, value in details.items():
            self.logger.warning(f"   {key.title()}: {value}")
        self.logger.warning("=" * 70 + "\n")
        
        # TODO: In future, send alert to web interface via WebSocket
        # TODO: Log to database for historical analysis
        # TODO: Send email/SMS notification for critical alerts
    
    def get_statistics(self):
        """
        Get current IDS statistics
        
        Returns:
            dict: Statistics including packet count, alert count, uptime
        """
        if self.start_time:
            uptime = datetime.now() - self.start_time
        else:
            uptime = timedelta(0)
        
        return {
            'is_monitoring': self.is_monitoring,
            'uptime': str(uptime),
            'packets_processed': self.packet_count,
            'alerts_generated': self.alert_count,
            'known_arp_entries': len(self.arp_table),
            'monitored_targets': len(self.syn_packets)
        }


# ============================================================================
# COMMAND-LINE INTERFACE (for standalone use)
# ============================================================================

def main():
    """
    Command-line interface for running the IDS detector
    
    Usage:
        python detector.py --interface eth0 --sensitivity high
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Monitor default interface with medium sensitivity
  sudo python3 detector.py

  # Monitor specific interface with high sensitivity
  sudo python3 detector.py --interface eth0 --sensitivity high

  # Monitor with low sensitivity (fewer false positives)
  sudo python3 detector.py --interface ens33 --sensitivity low

Note: This script requires root privileges to capture packets.
        '''
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        default=None,
        help='Network interface to monitor (e.g., eth0, ens33). Default: all interfaces'
    )
    
    parser.add_argument(
        '--sensitivity', '-s',
        type=str,
        choices=['low', 'medium', 'high'],
        default='medium',
        help='Detection sensitivity (default: medium)'
    )
    
    args = parser.parse_args()
    
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print("❌ Error: This script must be run as root (use sudo)")
        print("   Example: sudo python3 detector.py")
        sys.exit(1)
    
    # Create and start detector
    detector = NetworkDetector(
        interface=args.interface,
        sensitivity=args.sensitivity
    )
    
    try:
        detector.start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Stopping detector...")
        detector.stop_monitoring()


if __name__ == '__main__':
    main()
