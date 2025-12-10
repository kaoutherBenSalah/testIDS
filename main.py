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

# ============ IMPORTS ============
import sys                          # System utilities and path manipulation
import os                           # OS-level operations (permissions, environment)
import argparse                     # Command-line argument parsing
from pathlib import Path            # Path operations (cross-platform)

# Add project root to Python path so modules can be imported
sys.path.append(str(Path(__file__).parent))

# Import attack modules
from modules.arp_spoof import ARPSpoofer          # ARP spoofing Man-in-the-Middle attack
from modules.syn_flood import SYNFlooder          # TCP SYN flood Denial-of-Service attack
from modules.detector import NetworkDetector      # Intrusion detection system
# Import utility functions
from utils.logger import get_logger               # Logging utility
from utils.network_utils import (                 # Network helper functions
    get_local_ip,                                 # Get machine's IP address
    get_gateway_ip,                               # Get default gateway IP
    scan_network                                  # Scan network for active hosts
)


class CyberSecurityPlatform:
    """
    Main platform class for cybersecurity attack simulation and detection
    
    This class provides:
    - Interactive menu for user interaction
    - Attack launching (ARP spoofing, SYN flooding)
    - Network detection and monitoring
    - Network utilities (scanning, info display)
    """
    
    def __init__(self):
        """Initialize the platform with logger and version"""
        self.logger = get_logger("Platform")        # Get logger instance for this module
        self.version = "1.0.0"                       # Platform version
    
    def print_banner(self):
        """Display the platform banner with ASCII art"""
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
        # Print the banner to console
        print(banner)
    
    def print_menu(self):
        """Display the main interactive menu with all available options"""
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
        # Print the menu
        print(menu)
    
    def get_network_info(self):
        """Display local network information (IP, gateway, interfaces)"""
        # Display header
        print("\n" + "="*60)
        print("📡 INFORMATIONS RÉSEAU")
        print("="*60)
        
        try:
            # Get and display local IP address
            local_ip = get_local_ip()
            # Get and display default gateway IP
            gateway_ip = get_gateway_ip()
            
            print(f"Adresse IP locale: {local_ip}")
            print(f"Passerelle par défaut: {gateway_ip}")
            
            # Get list of network interfaces
            from utils.network_utils import get_network_interfaces
            interfaces = get_network_interfaces()
            print(f"\nInterfaces disponibles:")
            # Display each available network interface
            for iface in interfaces:
                print(f"  • {iface}")
        
        except Exception as e:
            # Log and display any errors
            print(f"❌ Erreur: {e}")
        
        # Display footer
        print("="*60)
    
    def interactive_mode(self):
        """Main interactive loop that displays menu and processes user input"""
        # Display the banner
        self.print_banner()
        
        # Check if running with root privileges (required for packet operations)
        if os.geteuid() != 0:
            print("\n⚠️  ATTENTION: Ce programme nécessite les privilèges root (sudo)")
            print("   Relancez avec: sudo python3 main.py\n")
            return
        
        # Main interactive loop
        while True:
            # Display the menu
            self.print_menu()
            
            try:
                # Get user input and remove whitespace
                choice = input("👉 Votre choix: ").strip()
                
                # Handle exit option
                if choice == "0":
                    print("\n👋 Au revoir!\n")
                    break
                
                # Option 1: Launch ARP Spoofing attack
                elif choice == "1":
                    self._launch_arp_attack()
                
                # Option 2: Launch SYN Flooding attack
                elif choice == "2":
                    self._launch_syn_attack()
                
                # Option 3: Launch detection system
                elif choice == "3":
                    self._launch_detector()
                
                # Option 4: Scan network
                elif choice == "4":
                    self._scan_network()
                
                # Option 5: Display network info
                elif choice == "5":
                    self.get_network_info()
                
                # Invalid choice
                else:
                    print("\n❌ Choix invalide!\n")
            
            # Handle Ctrl+C gracefully
            except KeyboardInterrupt:
                print("\n\n👋 Au revoir!\n")
                break
            
            # Handle any other errors
            except Exception as e:
                print(f"\n❌ Erreur: {e}\n")
                self.logger.error(f"Erreur dans le menu: {e}")
    
    def _launch_arp_attack(self):
        """Prompt for ARP spoofing attack parameters and execute the attack"""
        print("\n" + "="*60)
        print("⚡ ATTAQUE ARP SPOOFING")
        print("="*60)
        
        try:
            # Prompt user for target IP (the victim)
            target = input("IP de la victime: ").strip()
            # Prompt user for gateway IP (the router)
            gateway = input("IP de la passerelle: ").strip()
            # Prompt user for network interface (optional, auto-detect if empty)
            interface = input("Interface (laisser vide pour auto): ").strip() or None
            # Prompt user for interval between packets
            interval = input("Intervalle en secondes (défaut 2): ").strip()
            # Convert interval to int, default to 2 if empty
            interval = int(interval) if interval else 2
            
            # Warn the user before starting the attack
            print("\n⚠️  L'attaque va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            # Create ARPSpoofer instance with provided parameters
            spoofer = ARPSpoofer(target, gateway, interface)
            # Start the ARP spoofing attack
            spoofer.start_attack(interval=interval)
        
        except Exception as e:
            # Log and display any errors that occur
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur ARP attack: {e}")
    
    def _launch_syn_attack(self):
        """Prompt for SYN flooding attack parameters and execute the attack"""
        print("\n" + "="*60)
        print("💥 ATTAQUE SYN FLOODING")
        print("="*60)
        
        try:
            # Prompt user for target IP
            target = input("IP de la cible: ").strip()
            # Prompt user for target port
            port = int(input("Port de la cible: ").strip())
            # Prompt user for number of threads (for parallel packet sending)
            threads = input("Nombre de threads (défaut 10): ").strip()
            # Convert threads to int, default to 10 if empty
            threads = int(threads) if threads else 10
            # Prompt user for attack duration (optional)
            duration = input("Durée en secondes (laisser vide pour infini): ").strip()
            # Convert duration to int or None if empty
            duration = int(duration) if duration else None
            
            # Warn the user before starting the attack
            print("\n⚠️  L'attaque va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            # Create SYNFlooder instance with provided parameters
            flooder = SYNFlooder(target, port, threads)
            # Start the SYN flooding attack
            flooder.start_attack(duration=duration)
        
        except Exception as e:
            # Log and display any errors that occur
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur SYN attack: {e}")
    
    def _launch_detector(self):
        """Prompt for detection system parameters and start monitoring"""
        print("\n" + "="*60)
        print("🛡️  SYSTÈME DE DÉTECTION")
        print("="*60)
        
        try:
            # Prompt user for network interface (optional)
            interface = input("Interface à surveiller (laisser vide pour auto): ").strip() or None
            # Prompt user for sensitivity level
            sensitivity = input("Sensibilité (low/medium/high, défaut medium): ").strip() or "medium"
            
            # Validate sensitivity level
            if sensitivity not in ['low', 'medium', 'high']:
                print("⚠️  Sensibilité invalide, utilisation de 'medium'")
                sensitivity = 'medium'
            
            # Inform user that detector is starting
            print("\n👁️  Le détecteur va démarrer. Appuyez sur Ctrl+C pour arrêter.\n")
            input("Appuyez sur Entrée pour continuer...")
            
            # Create NetworkDetector instance with provided parameters
            detector = NetworkDetector(interface, sensitivity)
            # Start the network monitoring
            detector.start_monitoring()
        
        except Exception as e:
            # Log and display any errors that occur
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur detector: {e}")
    
    def _scan_network(self):
        """Prompt for network range and scan for active hosts"""
        print("\n" + "="*60)
        print("🔍 SCAN DU RÉSEAU")
        print("="*60)
        
        try:
            # Prompt user for network CIDR range
            network = input("Plage réseau (défaut 192.168.1.0/24): ").strip()
            # Use default network if user doesn't provide one
            network = network if network else "192.168.1.0/24"
            
            # Execute network scan
            hosts = scan_network(network)
            
            # If hosts were found, display them in a table
            if hosts:
                print(f"\n✅ {len(hosts)} hôte(s) trouvé(s):\n")
                # Print table header
                print(f"{'IP':<20} {'MAC':<20}")
                print("-" * 40)
                # Print each discovered host
                for host in hosts:
                    print(f"{host['ip']:<20} {host['mac']:<20}")
            else:
                # No hosts found message
                print("\n⚠️  Aucun hôte trouvé")
        
        except Exception as e:
            # Log and display any errors that occur
            print(f"\n❌ Erreur: {e}\n")
            self.logger.error(f"Erreur scan: {e}")
        
        # Display footer
        print("="*60)


def main():
    """Main entry point: Parse arguments and execute requested mode"""
    # Create argument parser with custom help text
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
    
    # Define mode argument: how the program will run
    parser.add_argument('--mode', choices=['attacker', 'defender', 'interactive'],
                       default='interactive',
                       help='Mode d\'exécution')
    
    # ============ Arguments for attack mode ============
    # Type of attack to execute
    parser.add_argument('--attack', choices=['arp', 'syn'],
                       help='Type d\'attaque (arp ou syn)')
    # Target IP address for the attack
    parser.add_argument('--target', help='IP de la cible')
    # Gateway IP (required for ARP spoofing to know where to send packets)
    parser.add_argument('--gateway', help='IP de la passerelle (pour ARP)')
    # Target port (required for SYN flooding)
    parser.add_argument('--port', type=int, help='Port cible (pour SYN)')
    # Number of concurrent threads for SYN flood attack
    parser.add_argument('--threads', type=int, default=10,
                       help='Nombre de threads (pour SYN)')
    # Interval between ARP packets
    parser.add_argument('--interval', type=int, default=2,
                       help='Intervalle entre paquets en secondes (pour ARP)')
    # Duration of the attack in seconds
    parser.add_argument('--duration', type=int,
                       help='Durée de l\'attaque en secondes')
    
    # ============ Arguments for defender/detection mode ============
    # Network interface to monitor
    parser.add_argument('--interface', help='Interface réseau')
    # Sensitivity level for attack detection
    parser.add_argument('--sensitivity', choices=['low', 'medium', 'high'],
                       default='medium',
                       help='Sensibilité de la détection')
    
    # Parse command-line arguments
    args = parser.parse_args()
    
    # Create platform instance
    platform = CyberSecurityPlatform()
    
    # ============ MODE: INTERACTIVE (default) ============
    # User sees the menu and can choose options
    if args.mode == 'interactive':
        platform.interactive_mode()
    
    # ============ MODE: ATTACKER ============
    # Execute an attack based on parameters
    elif args.mode == 'attacker':
        # Ensure attack type is specified
        if not args.attack:
            print("❌ Vous devez spécifier --attack (arp ou syn)")
            sys.exit(1)
        
        # Check for root privileges (required for packet manipulation)
        if os.geteuid() != 0:
            print("❌ Ce programme nécessite les privilèges root (sudo)")
            sys.exit(1)
        
        # -------- ARP Spoofing Attack --------
        if args.attack == 'arp':
            # Validate that required parameters are provided
            if not args.target or not args.gateway:
                print("❌ Pour ARP Spoofing, spécifiez --target et --gateway")
                sys.exit(1)
            
            # Create and start ARP spoofer
            spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
            spoofer.start_attack(interval=args.interval)
        
        # -------- SYN Flooding Attack --------
        elif args.attack == 'syn':
            # Validate that required parameters are provided
            if not args.target or not args.port:
                print("❌ Pour SYN Flood, spécifiez --target et --port")
                sys.exit(1)
            
            # Create and start SYN flooder
            flooder = SYNFlooder(args.target, args.port, args.threads)
            flooder.start_attack(duration=args.duration)
    
    # ============ MODE: DEFENDER ============
    # Run the intrusion detection system
    elif args.mode == 'defender':
        # Check for root privileges (required for packet sniffing)
        if os.geteuid() != 0:
            print("❌ Ce programme nécessite les privilèges root (sudo)")
            sys.exit(1)
        
        # Create and start network detector
        detector = NetworkDetector(args.interface, args.sensitivity)
        detector.start_monitoring()


# ============ SCRIPT ENTRY POINT ============
# Only run main() if this file is executed directly (not imported)
if __name__ == "__main__":
    main()
