"""
Firewall Blocker - Cross-platform packet blocking
Supports Linux (iptables) and Windows (netsh)
"""

import subprocess
import platform
from typing import Optional
from utils.logger import get_logger


class FirewallBlocker:
    """Cross-platform firewall blocking for attacker IPs."""
    
    def __init__(self):
        self.logger = get_logger("FirewallBlocker")
        self.os_type = platform.system().lower()
        self.blocked_ips = set()
    
    def block_ip(self, ip: str, reason: str = "IDS alert") -> bool:
        """Block an IP address using system firewall."""
        if not ip or ip in self.blocked_ips:
            return False
        
        try:
            if self.os_type == "linux":
                success = self._block_linux(ip)
            elif self.os_type == "windows":
                success = self._block_windows(ip)
            else:
                self.logger.warning(f"Unsupported OS: {self.os_type}")
                return False
            
            if success:
                self.blocked_ips.add(ip)
                self.logger.info(f"✅ BLOCKED {ip} (reason: {reason})")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to block {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        if not ip or ip not in self.blocked_ips:
            return False
        
        try:
            if self.os_type == "linux":
                success = self._unblock_linux(ip)
            elif self.os_type == "windows":
                success = self._unblock_windows(ip)
            else:
                return False
            
            if success:
                self.blocked_ips.discard(ip)
                self.logger.info(f"✅ UNBLOCKED {ip}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to unblock {ip}: {e}")
            return False
    
    def _block_linux(self, ip: str) -> bool:
        """Block IP using iptables (Linux)."""
        # Drop all packets from this IP
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def _unblock_linux(self, ip: str) -> bool:
        """Unblock IP using iptables (Linux)."""
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def _block_windows(self, ip: str) -> bool:
        """Block IP using Windows Firewall."""
        rule_name = f"IDS_Block_{ip.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def _unblock_windows(self, ip: str) -> bool:
        """Unblock IP using Windows Firewall."""
        rule_name = f"IDS_Block_{ip.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    
    def list_blocked(self):
        """Return list of currently blocked IPs."""
        return list(self.blocked_ips)


__all__ = ["FirewallBlocker"]
