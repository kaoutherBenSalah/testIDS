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
    
    def __init__(self, interface=None):
        """
        self.interface = interface
        self.logger = get_logger("TrafficSniffer")
        
        self.is_sniffing = False
        self.packet_count = 0
        self.captured_packets = []
        self.filter_string = None
        
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
        
        self.pcap_file = None
        self.pcap_writer = None
        
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
        if self.is_sniffing:
            self.logger.warning("⚠️  Already sniffing!")
            return
        
        self.is_sniffing = True
        self.filter_string = filter_str
        self.packet_count = 0
        self.captured_packets = []
        
        if prn_callback:
            self.packet_callback = prn_callback

        if interface:
            self.interface = interface
        
        self.logger.info(f"🚀 Starting packet capture...")
        self.logger.info(f"   Filter: {filter_str or 'None (all traffic)'}")
        self.logger.info(f"   Count: {count if count > 0 else 'Unlimited'}")
        self.logger.info(f"   Promisc: {'on' if promisc else 'off'} | Timeout: {timeout or 'none'}")

        if pcap_file:
            try:
                self.enable_pcap_logging(pcap_file)
            except Exception as e:
                self.logger.error(f"❌ Failed to enable PCAP logging: {e}")
        
        try:
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
        if not self.is_sniffing:
            self.logger.warning("⚠️  Not currently sniffing")
            return
        
        self.is_sniffing = False
        self.logger.info("🛑 Stopping packet capture...")
        self.logger.info(f"📊 Captured {self.packet_count} packets")
        
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
    
    def _sniff_thread(self, filter_str, count, promisc, timeout):
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
        try:
            self.packet_count += 1
            
            packet_info = self.analyze_packet(packet)
            
            protocol = packet_info.get('protocol', 'Other')
            self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
            
            if len(self.captured_packets) < 1000:
                self.captured_packets.append(packet_info)
            
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            if self.packet_callback:
                self.packet_callback(packet_info)
            
            if self.packet_count % 100 == 0:
                self.logger.info(f"📦 Captured {self.packet_count} packets...")
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def analyze_packet(self, packet):
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
            if IP in packet:
                info['src'] = packet[IP].src
                info['dst'] = packet[IP].dst
                
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    info['info'] = f"{src_port} → {dst_port}"
                    
                    if dst_port == 80 or src_port == 80:
                        info['protocol'] = 'HTTP'
                    elif dst_port == 443 or src_port == 443:
                        info['protocol'] = 'HTTPS'
                    
                    if Raw in packet:
                        payload = packet[Raw].load
                        if b'HTTP' in payload:
                            info['protocol'] = 'HTTP'
                            try:
                                first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                info['info'] = first_line[:80]
                            except:
                                pass
                
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    info['info'] = f"{src_port} → {dst_port}"
                    
                    if dst_port == 53 or src_port == 53:
                        info['protocol'] = 'DNS'
                        if DNS in packet:
                            if packet[DNS].qd:
                                info['info'] = f"Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type {packet[ICMP].type}"
            
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
        return self.captured_packets

    def get_packets(self, limit=100):
        if limit <= 0:
            return []
        return self.captured_packets[-limit:]
    
    def export_to_pcap(self, filename):
        """
        if not self.captured_packets:
            self.logger.warning("⚠️  No packets to export")
            return False
        
        try:
            self.logger.info(f"💾 Exporting {len(self.captured_packets)} packets to {filename}")
            
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
        try:
            self.pcap_file = filename
            self.pcap_writer = PcapWriter(filename, append=False, sync=True)
            self.logger.info(f"📝 PCAP logging enabled: {filename}")
        except Exception as e:
            self.logger.error(f"❌ Error enabling PCAP logging: {e}")
    
    def get_statistics(self):
        """
        return {
            'is_sniffing': self.is_sniffing,
            'packet_count': self.packet_count,
            'protocol_stats': self.protocol_stats,
            'filter': self.filter_string,
            'captured_packets': len(self.captured_packets)
        }

def main():
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
        
        while sniffer.is_sniffing:
            import time
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffer...")
        sniffer.stop_sniffing()
        
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
