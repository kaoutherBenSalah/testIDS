"""
Module de gestion des logs pour la plateforme de cybersécurité
Gère les logs console et fichiers avec rotation
"""

import logging
import os
from datetime import datetime
from pathlib import Path


class SecurityLogger:
    """Classe pour gérer les logs de sécurité"""
    
    def __init__(self, name="SecurityPlatform", log_dir="logs"):
        """
        Initialise le logger
        
        Args:
            name (str): Nom du logger
            log_dir (str): Répertoire pour stocker les logs
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Créer le logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Éviter les doublons de handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Configure les handlers pour console et fichier"""
        
        # Format des logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler console (coloré si possible)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Handler fichier (tous les logs)
        date_str = datetime.now().strftime('%Y%m%d')
        log_file = self.log_dir / f"{self.name}_{date_str}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Handler pour les alertes critiques
        alert_file = self.log_dir / f"ALERTS_{date_str}.log"
        alert_handler = logging.FileHandler(alert_file, encoding='utf-8')
        alert_handler.setLevel(logging.WARNING)
        alert_handler.setFormatter(formatter)
        
        # Ajouter les handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(alert_handler)
    
    def info(self, message):
        """Log un message d'information"""
        self.logger.info(message)
    
    def debug(self, message):
        """Log un message de debug"""
        self.logger.debug(message)
    
    def warning(self, message):
        """Log un avertissement"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log une erreur"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log une alerte critique"""
        self.logger.critical(message)
    
    def attack_detected(self, attack_type, details):
        """
        Log spécifique pour une attaque détectée
        
        Args:
            attack_type (str): Type d'attaque (ARP_SPOOFING, SYN_FLOOD, etc.)
            details (dict): Détails de l'attaque
        """
        message = f"🚨 ATTAQUE DÉTECTÉE: {attack_type}"
        for key, value in details.items():
            message += f"\n  - {key}: {value}"
        
        self.critical(message)
    
    def attack_started(self, attack_type, target):
        """
        Log le démarrage d'une attaque
        
        Args:
            attack_type (str): Type d'attaque
            target (str): Cible de l'attaque
        """
        self.warning(f"⚡ Attaque lancée: {attack_type} vers {target}")
    
    def attack_stopped(self, attack_type, stats=None):
        """
        Log l'arrêt d'une attaque
        
        Args:
            attack_type (str): Type d'attaque
            stats (dict): Statistiques de l'attaque
        """
        message = f"🛑 Attaque arrêtée: {attack_type}"
        if stats:
            for key, value in stats.items():
                message += f"\n  - {key}: {value}"
        
        self.info(message)


# Instance globale du logger
main_logger = SecurityLogger("SecurityPlatform")


def get_logger(name=None):
    """
    Récupère une instance du logger
    
    Args:
        name (str): Nom du logger (optionnel)
    
    Returns:
        SecurityLogger: Instance du logger
    """
    if name:
        return SecurityLogger(name)
    return main_logger


if __name__ == "__main__":
    # Test du logger
    logger = get_logger("TestModule")
    
    logger.info("Test d'information")
    logger.debug("Test de debug")
    logger.warning("Test d'avertissement")
    logger.error("Test d'erreur")
    
    logger.attack_detected("ARP_SPOOFING", {
        "Source IP": "192.168.1.100",
        "Target IP": "192.168.1.1",
        "MAC Address": "aa:bb:cc:dd:ee:ff",
        "Timestamp": datetime.now().isoformat()
    })
    
    print(f"\n✅ Logs créés dans le dossier: {Path('logs').absolute()}")
