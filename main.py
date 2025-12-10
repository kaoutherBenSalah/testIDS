#!/usr/bin/env python3
"""
Plateforme de Cybersécurité - Point d'entrée principal
ARP Spoofing & SYN Flood : Attaque et Détection

Ce script est le point d'entrée principal permettant de :
- Lancer des attaques (ARP Spoofing, SYN Flooding)
- Démarrer le système de détection
- Afficher un menu interactif

Auteurs: Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane
Classe: 4-ING-J-SSIR4
"""

import sys
import os
import argparse
from pathlib import Path

# Ajouter les modules au path
sys.path.append(str(Path(__file__).parent))

from modules.arp_spoof import ARPSpoofer
from modules.syn_flood import SYNFlooder
from modules.detector import NetworkDetector
from utils.logger import get_logger
from utils.network_utils import get_local_ip, get_gateway_ip, scan_network


class CyberSecurityPlatform:
    """Classe principale de la plateforme"""
    
    def __init__(self):
        """Initialise la plateforme"""
        self.logger = get_logger("Platform")
        self.version = "1.0.0"
    
    def print_banner(self):
        """Affiche la bannière de la plateforme"""
        banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     🔐  PLATEFORME DE CYBERSÉCURITÉ - ATTAQUE & DÉTECTION  🔐      ║
║                                                                   ║
║              ARP Spoofing & SYN Flood Simulator                   ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║  Auteurs: K. Ben Salah, M.F. Ben Hmida, H.E. Ben Chaabane       ║
║  Classe:  4-ING-J-SSIR4                                          ║
║  Version: 1.0.0                                                  ║
╚═══════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self):
        """Affiche le menu principal"""
        menu = """
┌─────────────────────────────────────────────────────────────────┐
│                       MENU PRINCIPAL                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MODE ATTAQUANT 🔴                                               │
│    1. Lancer une attaque ARP Spoofing (MITM)                    │
│    2. Lancer une attaque SYN Flooding (DoS)                     │
│                                                                  │
│  MODE DÉFENSEUR 🛡️                                               │
│    3. Démarrer le système de détection                          │
│                                                                  │
│  UTILITAIRES 🔧                                                  │
│    4. Scanner le réseau                                         │
│    5. Afficher les informations réseau                          │
│                                                                  │
│    0. Quitter                                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
        """
        print(menu)
    
    def get_network_info(self):
        """Affiche les informations réseau"""
        print("\n" + "="*60)
        print("📡 INFORMATIONS RÉSEAU")
        print("="*60)
        
        try:
            local_ip = get_local_ip()
            gateway_ip = get_gateway_ip()
            
            print(f"Adresse IP locale: {local_ip}")
            print(f"Passerelle par défaut: {gateway_ip}")
            
            from utils.network_utils import get_network_interfaces
            interfaces = get_network_interfaces()
            print(f"\nInterfaces disponibles:")
            for iface in interfaces:
                print(f"  • {iface}")
        
        except Exception as e:
            print(f"❌ Erreur: {e}")
        
        print("="*60)
    
    def interactive_mode(self):
        """Mode interactif avec menu"""
        self.print_banner()
        
        # Vérifier les permissions
        if os.geteuid() != 0:
            print("\n⚠️  ATTENTION: Ce programme nécessite les privilèges root (sudo)")
            print("   Relancez avec: sudo python3 main.py\n")
            return
        
        while True:
            self.print_menu()
            
            try:
                choice = input("👉 Votre choix: ").strip()
                
                if choice == "0":
                    print("\n👋 Au revoir!\n")
                    break
                
                elif choice == "1":
                    self._launch_arp_attack()
                
                elif choice == "2":
                    self._launch_syn_attack()
                
                elif choice == "3":
                    self._launch_detector()
                
                elif choice == "4":
                    self._scan_network()
                
                elif choice == "5":
                    self.get_network_info()
                
                else:
                    print("\n❌ Choix invalide!\n")
            
            except KeyboardInterrupt:
                print("\n\n👋 Au revoir!\n")
                break
            
            except Exception as e:
                print(f"\n❌ Erreur: {e}\n")
                self.logger.error(f"Erreur dans le menu: {e}")
    
    def _launch_arp_attack(self):
        """Lance une attaque ARP Spoofing"""
        print("\n" + "="*60)
        print("⚡ ATTAQUE ARP SPOOFING")
        print("="*60)
        
        try:
            target = input("IP de la victime: ").strip()
            gateway = input("IP de la passerelle: ").strip()
            interface = input("Interface (laisser vide pour auto): ").strip() or None
            interval = input("Intervalle en secondes (défaut 2): ").strip()
            interval = int(interval) if interval else 2
            
            print("\n⚠️  L'attaque va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            spoofer = ARPSpoofer(target, gateway, interface)
            spoofer.start_attack(interval=interval)
        
        except Exception as e:
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur ARP attack: {e}")
    
    def _launch_syn_attack(self):
        """Lance une attaque SYN Flooding"""
        print("\n" + "="*60)
        print("💥 ATTAQUE SYN FLOODING")
        print("="*60)
        
        try:
            target = input("IP de la cible: ").strip()
            port = int(input("Port de la cible: ").strip())
            threads = input("Nombre de threads (défaut 10): ").strip()
            threads = int(threads) if threads else 10
            duration = input("Durée en secondes (laisser vide pour infini): ").strip()
            duration = int(duration) if duration else None
            
            print("\n⚠️  L'attaque va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            flooder = SYNFlooder(target, port, threads)
            flooder.start_attack(duration=duration)
        
        except Exception as e:
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur SYN attack: {e}")
    
    def _launch_detector(self):
        """Lance le système de détection"""
        print("\n" + "="*60)
        print("🛡️  SYSTÈME DE DÉTECTION")
        print("="*60)
        
        try:
            interface = input("Interface à surveiller (laisser vide pour auto): ").strip() or None
            sensitivity = input("Sensibilité (low/medium/high, défaut medium): ").strip() or "medium"
            
            if sensitivity not in ['low', 'medium', 'high']:
                print("⚠️  Sensibilité invalide, utilisation de 'medium'")
                sensitivity = 'medium'
            
            print("\n👁️  Le détecteur va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            detector = NetworkDetector(interface, sensitivity)
            detector.start_monitoring()
        
        except Exception as e:
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur detector: {e}")
    
    def _scan_network(self):
        """Scanne le réseau"""
        print("\n" + "="*60)
        print("🔍 SCAN DU RÉSEAU")
        print("="*60)
        
        try:
            network = input("Plage réseau (défaut 192.168.1.0/24): ").strip()
            network = network if network else "192.168.1.0/24"
            
            hosts = scan_network(network)
            
            if hosts:
                print(f"\n✅ {len(hosts)} hôte(s) trouvé(s):\n")
                print(f"{'IP':<20} {'MAC':<20}")
                print("-" * 40)
                for host in hosts:
                    print(f"{host['ip']:<20} {host['mac']:<20}")
            else:
                print("\n⚠️  Aucun hôte trouvé")
        
        except Exception as e:
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur scan: {e}")
        
        print("="*60)


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description="🔐 Plateforme de Cybersécurité - Attaque & Détection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

  Mode interactif:
    sudo python3 main.py

  Mode attaquant - ARP Spoofing:
    sudo python3 main.py --mode attacker --attack arp \\
                         --target 192.168.1.10 --gateway 192.168.1.1

  Mode attaquant - SYN Flood:
    sudo python3 main.py --mode attacker --attack syn \\
                         --target 192.168.1.100 --port 80 --threads 20

  Mode défenseur:
    sudo python3 main.py --mode defender --interface eth0 --sensitivity high

⚠️  AVERTISSEMENT:
    Utilisez cette plateforme uniquement dans un environnement contrôlé et éthique.
    Les attaques sur des réseaux sans autorisation sont ILLÉGALES.
        """
    )
    
    parser.add_argument('--mode', choices=['attacker', 'defender', 'interactive'],
                       default='interactive',
                       help='Mode d\'exécution')
    
    # Arguments pour le mode attaquant
    parser.add_argument('--attack', choices=['arp', 'syn'],
                       help='Type d\'attaque (arp ou syn)')
    parser.add_argument('--target', help='IP de la cible')
    parser.add_argument('--gateway', help='IP de la passerelle (pour ARP)')
    parser.add_argument('--port', type=int, help='Port cible (pour SYN)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Nombre de threads (pour SYN)')
    parser.add_argument('--interval', type=int, default=2,
                       help='Intervalle entre paquets en secondes (pour ARP)')
    parser.add_argument('--duration', type=int,
                       help='Durée de l\'attaque en secondes')
    
    # Arguments pour le mode défenseur
    parser.add_argument('--interface', help='Interface réseau')
    parser.add_argument('--sensitivity', choices=['low', 'medium', 'high'],
                       default='medium',
                       help='Sensibilité de la détection')
    
    args = parser.parse_args()
    
    # Créer la plateforme
    platform = CyberSecurityPlatform()
    
    # Mode interactif (par défaut)
    if args.mode == 'interactive':
        platform.interactive_mode()
    
    # Mode attaquant
    elif args.mode == 'attacker':
        if not args.attack:
            print("❌ Vous devez spécifier --attack (arp ou syn)")
            sys.exit(1)
        
        # Vérifier les permissions
        if os.geteuid() != 0:
            print("❌ Ce programme nécessite les privilèges root (sudo)")
            sys.exit(1)
        
        if args.attack == 'arp':
            if not args.target or not args.gateway:
                print("❌ Pour ARP Spoofing, spécifiez --target et --gateway")
                sys.exit(1)
            
            spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
            spoofer.start_attack(interval=args.interval)
        
        elif args.attack == 'syn':
            if not args.target or not args.port:
                print("❌ Pour SYN Flood, spécifiez --target et --port")
                sys.exit(1)
            
            flooder = SYNFlooder(args.target, args.port, args.threads)
            flooder.start_attack(duration=args.duration)
    
    # Mode défenseur
    elif args.mode == 'defender':
        # Vérifier les permissions
        if os.geteuid() != 0:
            print("❌ Ce programme nécessite les privilèges root (sudo)")
            sys.exit(1)
        
        detector = NetworkDetector(args.interface, args.sensitivity)
        detector.start_monitoring()


if __name__ == "__main__":
    main()
