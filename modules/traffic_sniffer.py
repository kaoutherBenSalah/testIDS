"""
Traffic Sniffer Module
Captures and analyzes network traffic in real-time

This module provides packet sniffing capabilities for monitoring
network traffic during Man-in-the-Middle attacks.

Usage:
    sniffer = TrafficSniffer(interface='eth0')
    sniffer.start_sniffing(filter='tcp port 80', count=100)
    
Author: Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane
"""

import sys
import threading
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, wrpcap, PcapWriter, IP, TCP, UDP, ICMP, ARP, DNS, Raw

sys.path.append(str(Path(__file__).parent.parent))
from utils.logger import get_logger


class TrafficSniffer:
    """
    Network Traffic Sniffer for packet capture and analysis
    
    Features:
    - Live packet capture
    - Protocol filtering
    - Packet analysis
    - PCAP file export
    - Real-time statistics
    """
    
    def __init__(self, interface=None):
        """
        Initialize Traffic Sniffer
        
        Args:
            interface (str): Network interface to sniff on
        """
        self.interface = interface
        self.logger = get_logger("TrafficSniffer")
        
        # State variables
        self.is_sniffing = False
        self.packet_count = 0
        self.captured_packets = []
        self.filter_string = None
        
        # Statistics
        self.protocol_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'DNS': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'Other': 0
        }
        
        # PCAP writer
        self.pcap_file = None
        self.pcap_writer = None
        
        # Callback for live display (set by web interface)
        self.packet_callback = None
        
        self.logger.info(f"🔍 Traffic Sniffer initialized on {interface or 'default interface'}")
    
    def start_sniffing(
        self,
        filter_str=None,
        count=0,
        prn_callback=None,
        interface=None,
        promisc=False,
        timeout=None,
        pcap_file=None,
    ):
        """
        Start packet sniffing
        
        Args:
            filter_str (str): BPF filter (e.g., 'tcp port 80', 'host 192.168.1.1')
            count (int): Number of packets to capture (0 = infinite)
            prn_callback (function): Callback function for each packet
            interface (str): Interface override (defaults to self.interface)
            promisc (bool): Enable promiscuous capture
            timeout (int|float|None): Stop after N seconds (None = infinite)
            pcap_file (str|None): If set, write packets to this PCAP file
        """
        if self.is_sniffing:
            self.logger.warning("⚠️  Already sniffing!")
            return
        
        self.is_sniffing = True
        self.filter_string = filter_str
        self.packet_count = 0
        self.captured_packets = []
        
        if prn_callback:
            self.packet_callback = prn_callback

        # Allow on-demand interface override
        if interface:
            self.interface = interface
        
        self.logger.info(f"🚀 Starting packet capture...")
        self.logger.info(f"   Filter: {filter_str or 'None (all traffic)'}")
        self.logger.info(f"   Count: {count if count > 0 else 'Unlimited'}")
        self.logger.info(f"   Promisc: {'on' if promisc else 'off'} | Timeout: {timeout or 'none'}")

        # Enable PCAP writing when requested
        if pcap_file:
            try:
                self.enable_pcap_logging(pcap_file)
            except Exception as e:
                self.logger.error(f"❌ Failed to enable PCAP logging: {e}")
        
        try:
            # Start sniffing in a separate thread
            sniff_thread = threading.Thread(
                target=self._sniff_thread,
                args=(filter_str, count, promisc, timeout),
                daemon=True
            )
            sniff_thread.start()
            
        except Exception as e:
            self.logger.error(f"❌ Error starting sniffer: {e}")
            self.is_sniffing = False
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        if not self.is_sniffing:
            self.logger.warning("⚠️  Not currently sniffing")
            return
        
        self.is_sniffing = False
        self.logger.info("🛑 Stopping packet capture...")
        self.logger.info(f"📊 Captured {self.packet_count} packets")
        
        # Close PCAP writer if open
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
    
    def _sniff_thread(self, filter_str, count, promisc, timeout):
        """Sniffing thread (runs in background)."""
        try:
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._process_packet,
                count=count,
                store=False,
                promisc=promisc,
                timeout=timeout,
                stop_filter=lambda _: not self.is_sniffing,
            )
        except Exception as e:
            self.logger.error(f"❌ Sniffing error: {e}")
        finally:
            self.is_sniffing = False
    
    def _process_packet(self, packet):
        """
        Process each captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            
            # Analyze packet
            packet_info = self.analyze_packet(packet)
            
            # Update statistics
            protocol = packet_info.get('protocol', 'Other')
            self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
            
            # Store packet (limit to last 1000 to avoid memory issues)
            if len(self.captured_packets) < 1000:
                self.captured_packets.append(packet_info)
            
            # Write to PCAP file if enabled
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            # Call user callback if set
            if self.packet_callback:
                self.packet_callback(packet_info)
            
            # Log progress every 100 packets
            if self.packet_count % 100 == 0:
                self.logger.info(f"📦 Captured {self.packet_count} packets...")
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def analyze_packet(self, packet):
        """
        Analyze packet and extract information
        
        Args:
            packet: Scapy packet object
        
        Returns:
            dict: Packet information
        """
        info = {
            'number': self.packet_count,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'protocol': 'Unknown',
            'src': 'Unknown',
            'dst': 'Unknown',
            'length': len(packet),
            'info': ''
        }
        
        try:
            # IP Layer
            if IP in packet:
                info['src'] = packet[IP].src
                info['dst'] = packet[IP].dst
                
                # TCP
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    info['info'] = f"{src_port} → {dst_port}"
                    
                    # HTTP/HTTPS detection
                    if dst_port == 80 or src_port == 80:
                        info['protocol'] = 'HTTP'
                    elif dst_port == 443 or src_port == 443:
                        info['protocol'] = 'HTTPS'
                    
                    # Check for payload
                    if Raw in packet:
                        payload = packet[Raw].load
                        if b'HTTP' in payload:
                            info['protocol'] = 'HTTP'
                            # Extract HTTP method
                            try:
                                first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                info['info'] = first_line[:80]
                            except:
                                pass
                
                # UDP
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    info['info'] = f"{src_port} → {dst_port}"
                    
                    # DNS detection
                    if dst_port == 53 or src_port == 53:
                        info['protocol'] = 'DNS'
                        if DNS in packet:
                            if packet[DNS].qd:
                                info['info'] = f"Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                
                # ICMP
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type {packet[ICMP].type}"
            
            # ARP
            elif ARP in packet:
                info['protocol'] = 'ARP'
                info['src'] = packet[ARP].psrc
                info['dst'] = packet[ARP].pdst
                op = packet[ARP].op
                info['info'] = f"{'Request' if op == 1 else 'Reply'}: Who has {packet[ARP].pdst}?"
        
        except Exception as e:
            info['info'] = f"Error analyzing: {str(e)[:50]}"
        
        return info
    
    def intercept_traffic(self):
        """
        Get all captured traffic
        
        Returns:
            list: List of packet information dictionaries
        """
        return self.captured_packets

    def get_packets(self, limit=100):
        """Return the most recent captured packets for API consumption"""
        if limit <= 0:
            return []
        return self.captured_packets[-limit:]
    
    def export_to_pcap(self, filename):
        """
        Export captured packets to PCAP file
        
        Args:
            filename (str): Output filename
        """
        if not self.captured_packets:
            self.logger.warning("⚠️  No packets to export")
            return False
        
        try:
            # Note: This exports packet info, not actual packets
            # For real PCAP, would need to store actual Scapy packets
            self.logger.info(f"💾 Exporting {len(self.captured_packets)} packets to {filename}")
            
            # In real implementation, would use wrpcap with actual packets
            # For now, export as JSON
            import json
            with open(filename + '.json', 'w') as f:
                json.dump(self.captured_packets, f, indent=2)
            
            self.logger.info(f"✅ Export complete: {filename}.json")
            return True
        
        except Exception as e:
            self.logger.error(f"❌ Export error: {e}")
            return False
    
    def enable_pcap_logging(self, filename):
        """
        Enable real-time PCAP file writing
        
        Args:
            filename (str): PCAP filename
        """
        try:
            self.pcap_file = filename
            self.pcap_writer = PcapWriter(filename, append=False, sync=True)
            self.logger.info(f"📝 PCAP logging enabled: {filename}")
        except Exception as e:
            self.logger.error(f"❌ Error enabling PCAP logging: {e}")
    
    def get_statistics(self):
        """
        Get current sniffing statistics
        
        Returns:
            dict: Statistics including packet counts by protocol
        """
        return {
            'is_sniffing': self.is_sniffing,
            'packet_count': self.packet_count,
            'protocol_stats': self.protocol_stats,
            'filter': self.filter_string,
            'captured_packets': len(self.captured_packets)
        }


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def main():
    """Command-line interface for traffic sniffer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Traffic Sniffer')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--filter', '-f', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('--count', '-c', type=int, default=0, help='Number of packets (0=infinite)')
    parser.add_argument('--output', '-o', help='Output PCAP file')
    
    args = parser.parse_args()
    
    sniffer = TrafficSniffer(interface=args.interface)
    
    if args.output:
        sniffer.enable_pcap_logging(args.output)
    
    # Simple callback to print packets
    def print_packet(packet_info):
        print(f"{packet_info['timestamp']} | {packet_info['protocol']:<8} | "
              f"{packet_info['src']:<15} → {packet_info['dst']:<15} | {packet_info['info']}")
    
    print("="*100)
    print("TRAFFIC SNIFFER - Press Ctrl+C to stop")
    print("="*100)
    print(f"{'Time':<12} | {'Protocol':<8} | {'Source':<15} → {'Destination':<15} | Info")
    print("-"*100)
    
    try:
        sniffer.start_sniffing(filter_str=args.filter, count=args.count, prn_callback=print_packet)
        
        # Keep main thread alive
        while sniffer.is_sniffing:
            import time
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffer...")
        sniffer.stop_sniffing()
        
        # Display statistics
        stats = sniffer.get_statistics()
        print("\n" + "="*100)
        print("STATISTICS")
        print("="*100)
        print(f"Total Packets: {stats['packet_count']}")
        print("\nBy Protocol:")
        for protocol, count in stats['protocol_stats'].items():
            if count > 0:
                print(f"  {protocol}: {count}")
        print("="*100)


if __name__ == '__main__':
    main()
