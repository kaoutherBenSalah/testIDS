"""
Utilitaires réseau pour la plateforme de cybersécurité
Fonctions communes pour la manipulation réseau
"""

import socket
import struct
import re
import os  # needed for enable/disable_ip_forwarding
from scapy.all import *


def get_mac(ip):
    """
    Récupère l'adresse MAC associée à une IP via ARP
    
    Args:
        ip (str): Adresse IP cible
    
    Returns:
        str: Adresse MAC ou None si non trouvée
    """
    try:
        # Envoyer une requête ARP
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
    Récupère l'adresse IP locale
    
    Args:
        interface (str): Interface réseau (optionnel)
    
    Returns:
        str: Adresse IP locale
    """
    try:
        if interface:
            # Utiliser l'interface spécifiée
            import netifaces
            addrs = netifaces.ifaddresses(interface)
            return addrs[netifaces.AF_INET][0]['addr']
        else:
            # Méthode par socket
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
    Récupère l'adresse IP de la passerelle par défaut
    
    Returns:
        str: Adresse IP de la passerelle
    """
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == '00000000':  # Route par défaut
                    gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    return gateway
    except Exception:
        # Alternative pour Windows ou autres systèmes
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
    Vérifie si une adresse IP est valide
    
    Args:
        ip (str): Adresse IP à vérifier
    
    Returns:
        bool: True si valide, False sinon
    """
    pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ip) is not None


def is_valid_mac(mac):
    """
    Vérifie si une adresse MAC est valide
    
    Args:
        mac (str): Adresse MAC à vérifier
    
    Returns:
        bool: True si valide, False sinon
    """
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return pattern.match(mac) is not None


def get_network_interfaces():
    """
    Liste les interfaces réseau disponibles
    
    Returns:
        list: Liste des interfaces
    """
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception as e:
        print(f"❌ Erreur lors de la récupération des interfaces: {e}")
        return []


def enable_ip_forwarding():
    """
    Active le forwarding IP (nécessaire pour MITM)
    
    Returns:
        bool: True si succès, False sinon
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
    Désactive le forwarding IP
    
    Returns:
        bool: True si succès, False sinon
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
    Scanne un réseau pour trouver les hôtes actifs
    
    Args:
        network_range (str): Plage réseau au format CIDR
    
    Returns:
        list: Liste des hôtes actifs (IP, MAC)
    """
    print(f"🔍 Scan du réseau {network_range}...")
    
    try:
        # Créer une requête ARP pour la plage
        arp_request = ARP(pdst=network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Envoyer et recevoir les réponses
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
    Extrait les informations importantes d'un paquet
    
    Args:
        packet: Paquet Scapy
    
    Returns:
        dict: Informations du paquet
    """
    info = {}
    
    try:
        # Couche Ethernet
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
        
        # Couche IP
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
        
        # Couche TCP
        if packet.haslayer(TCP):
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['tcp_flags'] = packet[TCP].flags
        
        # Couche ARP
        if packet.haslayer(ARP):
            info['arp_op'] = packet[ARP].op
            info['arp_psrc'] = packet[ARP].psrc
            info['arp_pdst'] = packet[ARP].pdst
            info['arp_hwsrc'] = packet[ARP].hwsrc
        
        return info
    
    except Exception as e:
        return {'error': str(e)}


if __name__ == "__main__":
    # Tests des fonctions
    print("=== Test des utilitaires réseau ===\n")
    
    print(f"IP locale: {get_local_ip()}")
    print(f"Passerelle: {get_gateway_ip()}")
    print(f"\nInterfaces réseau: {get_network_interfaces()}")
    
    print(f"\nTest de validation:")
    print(f"  192.168.1.1 valide? {is_valid_ip('192.168.1.1')}")
    print(f"  999.999.999.999 valide? {is_valid_ip('999.999.999.999')}")
    print(f"  aa:bb:cc:dd:ee:ff valide? {is_valid_mac('aa:bb:cc:dd:ee:ff')}")
    print(f"  zz:yy:xx valide? {is_valid_mac('zz:yy:xx')}")
