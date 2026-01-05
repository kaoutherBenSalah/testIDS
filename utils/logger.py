"""

import logging
import os
from datetime import datetime
from pathlib import Path

class SecurityLogger:
    
    def __init__(self, name="SecurityPlatform", log_dir="logs"):
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        date_str = datetime.now().strftime('%Y%m%d')
        log_file = self.log_dir / f"{self.name}_{date_str}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        alert_file = self.log_dir / f"ALERTS_{date_str}.log"
        alert_handler = logging.FileHandler(alert_file, encoding='utf-8')
        alert_handler.setLevel(logging.WARNING)
        alert_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(alert_handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def attack_detected(self, attack_type, details):
        """
        message = f"🚨 ATTAQUE DÉTECTÉE: {attack_type}"
        for key, value in details.items():
            message += f"\n  - {key}: {value}"
        
        self.critical(message)
    
    def attack_started(self, attack_type, target):
        """
        self.warning(f"⚡ Attaque lancée: {attack_type} vers {target}")
    
    def attack_stopped(self, attack_type, stats=None):
        """
        message = f"🛑 Attaque arrêtée: {attack_type}"
        if stats:
            for key, value in stats.items():
                message += f"\n  - {key}: {value}"
        
        self.info(message)

main_logger = SecurityLogger("SecurityPlatform")

def get_logger(name=None):
    """
    if name:
        return SecurityLogger(name)
    return main_logger

if __name__ == "__main__":
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
