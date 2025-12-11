"""
Simplified User & Database Models
Uses JSON files instead of SQLite for zero-config database
"""

import json
import os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

# Database file
DB_PATH = Path(__file__).parent / 'data' / 'users.json'
DB_PATH.parent.mkdir(exist_ok=True)

# In-memory stores for runtime data
active_attacks = {}  # {attack_id: {'type': 'arp', 'target': '192.168.189.20', ...}}
active_scanners = {}  # {scan_id: {'hosts': [], 'status': 'in_progress'}}
active_sniffers = {}  # {sniffer_id: {'packets': [], 'status': 'capturing'}}

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
        return self.role in ['ATTACKER', 'ADMIN']
    
    def is_defender(self):
        """Check if user can view detections"""
        return self.role in ['DEFENDER', 'ADMIN']
    
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
        'admin': {'password': generate_password_hash('admin123'), 'role': 'ADMIN'},
    }
    
    for username, data in defaults.items():
        if username not in users:
            users[username] = data
    
    save_users_db(users)


def get_or_create_users():
    """Create default users if they don't exist"""
    create_default_users()


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


# Initialize on import
from datetime import datetime
get_or_create_users()
