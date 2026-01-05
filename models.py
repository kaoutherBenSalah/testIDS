"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = Path(__file__).parent / 'data' / 'users.json'
DB_PATH.parent.mkdir(exist_ok=True)

active_attacks = {}  # {attack_id: {'type': 'arp', 'target': '192.168.189.20', ...}}
active_scanners = {}  # {scan_id: {'hosts': [], 'status': 'in_progress'}}
active_sniffers = {}  # {sniffer_id: {'packets': [], 'status': 'capturing'}}
blocked_ips = set()  # Track IPs that have been blocked

ids_monitor = None  # Will hold a modules.ids_monitor.IDSMonitor instance
firewall_blocker = None  # Will hold a modules.firewall_blocker.FirewallBlocker instance
ids_alerts: List[Dict[str, object]] = []
ids_blocks: List[Dict[str, object]] = []
ids_stats = {
    'total_alerts': 0,
    'blocks_requested': 0,
    'blocks_executed': 0,
}

attack_logs = []  # [{'type': 'ARP', 'target': '192.168.189.20', 'status': 'running', ...}]

class User:
    
    def __init__(self, username, role='ATTACKER'):
        self.username = username
        self.id = username  # Flask-Login requires id
        self.role = role
        self.is_active = True
        self.is_authenticated = True
    
    def is_attacker(self):
        return self.role == 'ATTACKER'
    
    def is_defender(self):
        return self.role == 'DEFENDER'
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

def load_users_db():
    try:
        if DB_PATH.exists():
            with open(DB_PATH, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_users_db(users):
    with open(DB_PATH, 'w') as f:
        json.dump(users, f, indent=2)

def get_user_by_username(username):
    users = load_users_db()
    if username in users:
        user_data = users[username]
        user = User(username, user_data['role'])
        return user
    return None

def create_default_users():
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
    create_default_users()

def verify_password(username, password):
    users = load_users_db()
    if username in users:
        return check_password_hash(users[username]['password'], password)
    return False

def log_attack(attack_type, target_ip, gateway_ip=None, status='running'):
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
    return attack_logs

def register_ids_monitor(monitor):
    global ids_monitor
    ids_monitor = monitor
    return ids_monitor

def record_ids_alert(alert: Dict[str, object]):
    ids_alerts.append(alert)
    ids_stats['total_alerts'] += 1
    return alert

def list_ids_alerts(limit: Optional[int] = None):
    alerts = ids_alerts[-limit:] if limit else ids_alerts
    return list(alerts)

def ack_ids_alert(alert_id: str) -> bool:
    for alert in ids_alerts:
        if alert.get('id') == alert_id:
            alert['acknowledged'] = True
            return True
    return False

def request_block(entity: Dict[str, object]):
    ids_blocks.append(entity)
    ids_stats['blocks_requested'] += 1
    return entity

from datetime import datetime
get_or_create_users()
