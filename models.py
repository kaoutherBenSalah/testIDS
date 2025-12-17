"""
Simplified User & Database Models
Uses JSON files instead of SQLite for zero-config database
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash

# Database file
DB_PATH = Path(__file__).parent / 'data' / 'users.json'
DB_PATH.parent.mkdir(exist_ok=True)

# IDS whitelist persistence
WHITELIST_PATH = Path(__file__).parent / 'data' / 'ids_whitelist.json'
WHITELIST_PATH.parent.mkdir(exist_ok=True)

DEFAULT_WHITELIST = {
    '192.168.111.1',
    '192.168.111.2',
    '192.168.111.254',
    '192.168.111.12',
}

# In-memory stores for runtime data
active_attacks = {}  # {attack_id: {'type': 'arp', 'target': '192.168.189.20', ...}}
active_scanners = {}  # {scan_id: {'hosts': [], 'status': 'in_progress'}}
active_sniffers = {}  # {sniffer_id: {'packets': [], 'status': 'capturing'}}

# IDS runtime state
ids_monitor = None  # Will hold a modules.ids_monitor.IDSMonitor instance
firewall_blocker = None  # Will hold a modules.firewall_blocker.FirewallBlocker instance
ids_alerts: List[Dict[str, object]] = []
ids_blocks: List[Dict[str, object]] = []
ids_stats = {
    'total_alerts': 0,
    'blocks_requested': 0,
    'blocks_executed': 0,
}
ids_whitelist = set()

# Attack logs stored in memory (reset on restart)
attack_logs = []  # [{'type': 'ARP', 'target': '192.168.189.20', 'status': 'running', ...}]


class User:
    """Simple user class for Flask-Login compatibility"""
    
    def __init__(self, username, role='ATTACKER'):
        self.username = username
        self.id = username  # Flask-Login requires id
        self.role = role
        self.is_active = True
        self.is_authenticated = True
    
    def is_attacker(self):
        """Check if user can launch attacks"""
        return self.role == 'ATTACKER'
    
    def is_defender(self):
        """Check if user can view detections"""
        return self.role == 'DEFENDER'
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


def load_users_db():
    """Load users from JSON file"""
    try:
        if DB_PATH.exists():
            with open(DB_PATH, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_users_db(users):
    """Save users to JSON file"""
    with open(DB_PATH, 'w') as f:
        json.dump(users, f, indent=2)


def get_user_by_username(username):
    """Get user object by username"""
    users = load_users_db()
    if username in users:
        user_data = users[username]
        user = User(username, user_data['role'])
        return user
    return None


def create_default_users():
    """Create default users for testing"""
    users = load_users_db()
    
    defaults = {
        'attacker': {'password': generate_password_hash('attack123'), 'role': 'ATTACKER'},
        'defender': {'password': generate_password_hash('defend123'), 'role': 'DEFENDER'},
    }
    
    for username, data in defaults.items():
        if username not in users:
            users[username] = data
    
    save_users_db(users)


def get_or_create_users():
    """Create default users if they don't exist"""
    create_default_users()


# ============================================================================
# IDS WHITELIST HELPERS
# ============================================================================


def _load_ids_whitelist() -> set:
    """Load whitelist from disk, falling back to defaults on first run."""
    if WHITELIST_PATH.exists():
        try:
            with open(WHITELIST_PATH, 'r') as f:
                data = json.load(f)
                return set(data) if isinstance(data, list) else set(DEFAULT_WHITELIST)
        except Exception:
            # On any error, fall back to defaults but do not fail startup
            return set(DEFAULT_WHITELIST)
    return set(DEFAULT_WHITELIST)


def _save_ids_whitelist(whitelist: set):
    """Persist whitelist to disk."""
    try:
        with open(WHITELIST_PATH, 'w') as f:
            json.dump(sorted(list(whitelist)), f, indent=2)
    except Exception:
        # Do not crash on persistence issues; IDS can still run
        pass


def list_ids_whitelist() -> List[str]:
    return sorted(list(ids_whitelist))


def add_to_ids_whitelist(ip: str) -> bool:
    if not ip:
        return False
    ids_whitelist.add(ip)
    _save_ids_whitelist(ids_whitelist)
    return True


def remove_from_ids_whitelist(ip: str) -> bool:
    if ip in ids_whitelist:
        ids_whitelist.remove(ip)
        _save_ids_whitelist(ids_whitelist)
        return True
    return False


def verify_password(username, password):
    """Verify username and password"""
    users = load_users_db()
    if username in users:
        return check_password_hash(users[username]['password'], password)
    return False


# ============================================================================
# ATTACK LOG FUNCTIONS
# ============================================================================

def log_attack(attack_type, target_ip, gateway_ip=None, status='running'):
    """Log an attack"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': attack_type,
        'target_ip': target_ip,
        'gateway_ip': gateway_ip,
        'status': status
    }
    attack_logs.append(log_entry)
    return log_entry


def get_attack_logs():
    """Get all attack logs"""
    return attack_logs


# ============================================================================
# IDS HELPERS
# ============================================================================


def register_ids_monitor(monitor):
    """Attach the global IDS monitor instance."""
    global ids_monitor
    ids_monitor = monitor
    return ids_monitor


def record_ids_alert(alert: Dict[str, object]):
    """Persist an IDS alert in memory and bump stats."""
    ids_alerts.append(alert)
    ids_stats['total_alerts'] += 1
    return alert


def list_ids_alerts(limit: Optional[int] = None):
    """Return the most recent IDS alerts."""
    alerts = ids_alerts[-limit:] if limit else ids_alerts
    return list(alerts)


def ack_ids_alert(alert_id: str) -> bool:
    """Mark an alert as acknowledged."""
    for alert in ids_alerts:
        if alert.get('id') == alert_id:
            alert['acknowledged'] = True
            return True
    return False


def request_block(entity: Dict[str, object]):
    """Record a defender-requested block/stop action (no enforcement yet)."""
    ids_blocks.append(entity)
    ids_stats['blocks_requested'] += 1
    return entity


# Initialize on import
from datetime import datetime
get_or_create_users()
ids_whitelist.update(_load_ids_whitelist())
