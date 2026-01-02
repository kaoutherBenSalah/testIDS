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
from modules.dns_spoof import DNSSpoofer
import models
from models import active_attacks, log_attack

attacks_bp = Blueprint('attacks', __name__)


# ============================================================================
# MIDDLEWARE: Check User Role
# ============================================================================

def require_attacker(f):
    """Decorator to require attacker role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'ATTACKER':
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
                # Use ARPSpoofer.start_attack (per module API) instead of non-existent start
                spoofer.start_attack(interval=interval)
            except Exception as e:
                print(f"ARP Attack Error: {e}")
        
        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()
        
        # Store in memory
        active_attacks[attack_id] = {
            'object': spoofer,
            'type': 'ARP',
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
        # Use ARPSpoofer.stop_attack to restore ARP tables properly
        spoofer.stop_attack()
        
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
        target_ips = data.get('target_ips') or []
        target_ip_single = data.get('target_ip')
        if target_ip_single:
            target_ips.append(target_ip_single)
        target_ports = data.get('target_ports') or []
        if not target_ports and data.get('target_port'):
            target_ports.append(int(data.get('target_port')))
        if not target_ports:
            target_ports = [80]
        num_threads = data.get('threads', 10)
        rate_limit = data.get('rate_limit_pps')
        spoof_pool = data.get('spoof_ips') or []
        random_spoof_count = int(data.get('random_spoof_count') or 0)
        
        # Validate
        if not target_ips:
            return jsonify({'error': 'Missing parameter: target_ip or target_ips'}), 400
        
        # Create unique attack ID
        attack_id = f"syn_{target_ips[0]}_{target_ports[0]}"
        
        # Check if already running
        if attack_id in active_attacks:
            return jsonify({'error': 'Attack already running'}), 400
        
        # Create SYN flooder
        flooder = SYNFlooder(
            target_ips,
            target_ports,
            num_threads,
            spoof_pool=spoof_pool,
            rate_limit_pps=rate_limit,
            spoof_pool_size=random_spoof_count,
        )
        
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
            'type': 'SYN',
            'target_ip': ','.join(target_ips),
            'target_port': ','.join(map(str, target_ports)),
            'packets_sent': 0,
            'status': 'running'
        }
        
        # Log attack
        log_attack('SYN_FLOODING', ','.join(target_ips), None, 'running')
        
        return jsonify({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'SYN flooding attack started against {','.join(target_ips)}:{','.join(map(str,target_ports))}'
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
# DNS SPOOFING ENDPOINTS
# ============================================================================

@attacks_bp.route('/dns/start', methods=['POST'])
@require_attacker
def start_dns_attack():
    """Start DNS spoofing attack"""
    try:
        data = request.get_json()
        attacker_ip = data.get('attacker_ip')
        target_domains = data.get('target_domains', ['google.com', 'facebook.com'])
        interface = data.get('interface')
        
        # Validate
        if not attacker_ip:
            return jsonify({'error': 'Missing parameter: attacker_ip'}), 400
        
        # Create unique attack ID
        attack_id = f"dns_{attacker_ip}"
        
        # Check if already running
        if attack_id in active_attacks:
            return jsonify({'error': 'DNS attack already running'}), 400
        
        # Create DNS spoofer
        spoofer = DNSSpoofer(attacker_ip, target_domains, interface)
        
        # Start attack
        spoofer.start_attack()
        
        # Store in memory
        active_attacks[attack_id] = {
            'object': spoofer,
            'type': 'DNS',
            'attacker_ip': attacker_ip,
            'target_domains': target_domains,
            'packets_spoofed': 0,
            'status': 'running'
        }
        
        # Log attack
        log_attack('DNS_SPOOFING', attacker_ip, ','.join(target_domains), 'running')
        
        return jsonify({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'DNS spoofing attack started (attacker IP: {attacker_ip})',
            'target_domains': target_domains
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@attacks_bp.route('/dns/stop', methods=['POST'])
@require_attacker
def stop_dns_attack():
    """Stop DNS spoofing attack"""
    try:
        data = request.get_json()
        attack_id = data.get('attack_id') or list(
            [k for k, v in active_attacks.items() if v['type'] == 'DNS']
        )[0] if any(v['type'] == 'DNS' for v in active_attacks.values()) else None
        
        if not attack_id or attack_id not in active_attacks:
            return jsonify({'error': 'Attack not found'}), 404
        
        attack_info = active_attacks[attack_id]
        spoofer = attack_info['object']
        
        # Stop attack
        spoofer.stop_attack()
        
        # Update memory
        del active_attacks[attack_id]
        
        return jsonify({
            'status': 'stopped',
            'message': f'DNS spoofing attack stopped',
            'packets_spoofed': spoofer.packets_spoofed
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
        import subprocess
        attacks = {}
        
        for attack_id, attack_info in active_attacks.items():
            target_ip = attack_info.get('target_ip') or attack_info.get('attacker_ip')
            is_blocked = target_ip in models.blocked_ips
            packets = attack_info.get('packets_sent', 0) or attack_info.get('packets_spoofed', 0)
            
            # Check if attack target is reachable (sign of successful attack)
            success = False
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', target_ip], 
                                      capture_output=True, timeout=2)
                success = result.returncode == 0
            except:
                success = False
            
            attacks[attack_id] = {
                'type': attack_info['type'],
                'target_ip': target_ip,
                'packets_sent': packets,
                'status': 'BLOCKED ❌' if is_blocked else attack_info['status'],
                'is_blocked': is_blocked,
                'success': success,  # Target is reachable (attack working)
            }
        
        return jsonify({'attacks': attacks}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
