"""

import socket
import struct
import re
import os  # needed for enable/disable_ip_forwarding
import ipaddress
import json
import subprocess
from typing import List, Dict, Optional
from scapy.all import *

def get_mac(ip):
    """
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    except Exception as e:
        print(f"❌ Erreur lors de la récupération de la MAC: {e}")
        return None

def get_local_ip(interface=None):
    """
    try:
        if interface:
            import netifaces
            addrs = netifaces.ifaddresses(interface)
            return addrs[netifaces.AF_INET][0]['addr']
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
    except Exception as e:
        print(f"❌ Erreur lors de la récupération de l'IP locale: {e}")
        return "127.0.0.1"

def get_gateway_ip():
    """
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == '00000000':  # Route par défaut
                    gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    return gateway
    except Exception:
        import platform
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and '0.0.0.0' in line.split()[0]:
                    return line.split()[3]
    
    return None

def is_valid_ip(ip):
    """
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ip) is not None

def is_valid_mac(mac):
    """
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return pattern.match(mac) is not None

def get_network_interfaces():
    """
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as e:
        print(f"❌ Erreur lors de la récupération des interfaces: {e}")
        return []

def _parse_nmcli_device_status() -> List[Dict[str, str]]:
    interfaces = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                interfaces.append({
                    "name": parts[0],
                    "type": parts[1],
                    "state": parts[2],
                    "connection": parts[3],
                })
    except Exception:
        return []
    return interfaces

def _parse_ip_link_show() -> List[str]:
    names = []
    try:
        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=False)
        for line in result.stdout.strip().splitlines():
            segments = line.split(":")
            if len(segments) >= 2:
                name = segments[1].strip()
                if name:
                    names.append(name)
    except Exception:
        return []
    return names

def _get_interface_addrs(ifname: str) -> Dict[str, Optional[str]]:
    try:
        result = subprocess.run(["ip", "-j", "addr", "show", ifname], capture_output=True, text=True, check=False)
        data = json.loads(result.stdout or "[]")
        if not data:
            return {"ip": None, "cidr": None, "gateway": None}
        for addr in data[0].get("addr_info", []):
            if addr.get("family") == "inet":
                ip = addr.get("local")
                prefix = addr.get("prefixlen")
                cidr = f"{ip}/{prefix}" if ip and prefix is not None else None
                return {"ip": ip, "cidr": cidr, "gateway": None}
    except Exception:
        pass
    return {"ip": None, "cidr": None, "gateway": None}

def _get_default_gateway_for_interface(ifname: str) -> Optional[str]:
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()  # Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
                if len(fields) >= 3 and fields[0] == ifname and fields[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except Exception:
        return None
    return None

def list_interfaces_detailed() -> List[Dict[str, Optional[str]]]:
    """
    detailed = []
    base = _parse_nmcli_device_status()
    base_names = [item.get("name") for item in base]
    if not base_names:
        base_names = _parse_ip_link_show()
        base = [{"name": n, "type": "unknown", "state": "unknown", "connection": ""} for n in base_names]
    for item in base:
        name = item.get("name")
        if not name or name == "lo":
            continue
        addr_info = _get_interface_addrs(name)
        gateway = _get_default_gateway_for_interface(name)
        detailed.append({
            "name": name,
            "type": item.get("type"),
            "state": item.get("state"),
            "connection": item.get("connection"),
            "ip": addr_info.get("ip"),
            "cidr": addr_info.get("cidr"),
            "gateway": gateway,
        })
    return detailed

def get_dhcp_scope() -> Optional[str]:
    lease_paths = [
        "/var/lib/NetworkManager/internal-leases",
        "/var/lib/NetworkManager/dhclient-*.lease",
        "/var/lib/dhcp/dhclient*.lease",
    ]
    import glob
    for pattern in lease_paths:
        for path in glob.glob(pattern):
            try:
                with open(path, "r") as f:
                    content = f.read()
                subnet_match = re.search(r"option subnet-mask ([0-9.]+);", content)
                router_match = re.search(r"option routers ([0-9.]+);", content)
                yiaddr_match = re.search(r"yiaddr ([0-9.]+);", content)
                if subnet_match and (yiaddr_match or router_match):
                    ip = yiaddr_match.group(1) if yiaddr_match else router_match.group(1)
                    mask = subnet_match.group(1)
                    if ip and mask:
                        try:
                            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            return str(net)
                        except Exception:
                            continue
            except Exception:
                continue
    return None

def infer_cidr_from_ip(ip: str, netmask: str) -> Optional[str]:
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return None

def get_default_network_range(interface: Optional[str] = None) -> Optional[str]:
    dhcp_scope = get_dhcp_scope()
    if dhcp_scope:
        return dhcp_scope

    detailed = list_interfaces_detailed()
    chosen = None
    if interface:
        chosen = next((i for i in detailed if i.get("name") == interface), None)
    if not chosen and detailed:
        chosen = next((i for i in detailed if i.get("ip")), detailed[0])
    if chosen and chosen.get("cidr"):
        return chosen.get("cidr")

    ip = get_local_ip(interface)
    try:
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network)
    except Exception:
        return None

def enable_ip_forwarding():
    """
    try:
        import platform
        if platform.system() == "Linux":
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print("✅ IP Forwarding activé")
            return True
        elif platform.system() == "Windows":
            os.system('netsh interface ipv4 set interface "Ethernet" forwarding=enabled')
            print("✅ IP Forwarding activé")
            return True
        return False
    except Exception as e:
        print(f"❌ Erreur lors de l'activation du forwarding: {e}")
        return False

def disable_ip_forwarding():
    """
    try:
        import platform
        if platform.system() == "Linux":
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("✅ IP Forwarding désactivé")
            return True
        elif platform.system() == "Windows":
            os.system('netsh interface ipv4 set interface "Ethernet" forwarding=disabled')
            print("✅ IP Forwarding désactivé")
            return True
        return False
    except Exception as e:
        print(f"❌ Erreur lors de la désactivation du forwarding: {e}")
        return False

def scan_network(network_range="192.168.1.0/24"):
    """
    print(f"🔍 Scan du réseau {network_range}...")
    
    try:
        arp_request = ARP(pdst=network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        hosts = []
        for element in answered_list:
            host = {
                'ip': element[1].psrc,
                'mac': element[1].hwsrc
            }
            hosts.append(host)
        
        print(f"✅ {len(hosts)} hôte(s) trouvé(s)")
        return hosts
    
    except Exception as e:
        print(f"❌ Erreur lors du scan: {e}")
        return []

def get_packet_info(packet):
    """
    info = {}
    
    try:
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
        
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
        
        if packet.haslayer(TCP):
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['tcp_flags'] = packet[TCP].flags
        
        if packet.haslayer(ARP):
            info['arp_op'] = packet[ARP].op
            info['arp_psrc'] = packet[ARP].psrc
            info['arp_pdst'] = packet[ARP].pdst
            info['arp_hwsrc'] = packet[ARP].hwsrc
        
        return info
    
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    print("=== Test des utilitaires réseau ===\n")
    
    print(f"IP locale: {get_local_ip()}")
    print(f"Passerelle: {get_gateway_ip()}")
    print(f"\nInterfaces réseau: {get_network_interfaces()}")
    
    print(f"\nTest de validation:")
    print(f"  192.168.1.1 valide? {is_valid_ip('192.168.1.1')}")
    print(f"  999.999.999.999 valide? {is_valid_ip('999.999.999.999')}")
    print(f"  aa:bb:cc:dd:ee:ff valide? {is_valid_mac('aa:bb:cc:dd:ee:ff')}")
    print(f"  zz:yy:xx valide? {is_valid_mac('zz:yy:xx')}")
