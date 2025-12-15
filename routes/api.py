"""
API Routes - Scanner, Sniffer, Network Info
Flask Blueprint for utility endpoints
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
import threading
import uuid
import sys
import psutil
from typing import Optional
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.network_scanner import NetworkScanner
from modules.traffic_sniffer import TrafficSniffer
from utils.network_utils import get_local_ip, get_gateway_ip, list_interfaces_detailed, get_default_network_range
from models import active_scanners, active_sniffers

api_bp = Blueprint('api', __name__)


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
# NETWORK SCANNER ENDPOINTS
# ============================================================================

@api_bp.route('/scan/start', methods=['POST'])
@require_attacker
def start_scan():
    """Start network scanning"""
    try:
        data = request.get_json()
        interface = data.get('interface')
        network_range = data.get('network_range') or get_default_network_range(interface) or '192.168.189.0/24'
        full_scan = data.get('full_scan', False)
        
        # Create scanner
        scanner = NetworkScanner(interface=interface)
        scan_id = str(uuid.uuid4())
        
        # Start scan in background
        def run_scan():
            try:
                hosts = scanner.identify_active_machines(network_range, full_scan)
                active_scanners[scan_id]['hosts'] = [h.to_dict() if hasattr(h, 'to_dict') else h for h in hosts]
                active_scanners[scan_id]['status'] = 'completed'
            except Exception as e:
                active_scanners[scan_id]['error'] = str(e)
                active_scanners[scan_id]['status'] = 'error'
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        # Store scan
        active_scanners[scan_id] = {
            'object': scanner,
            'network_range': network_range,
            'interface': interface,
            'hosts': [],
            'status': 'in_progress'
        }
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Scanning {network_range} on {interface or "auto"}...'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/scan/results/<scan_id>', methods=['GET'])
@require_attacker
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        if scan_id not in active_scanners:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = active_scanners[scan_id]
        
        return jsonify({
            'scan_id': scan_id,
            'hosts': scan['hosts'],
            'status': scan['status']
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/scan/stop', methods=['POST'])
@require_attacker
def stop_scan():
    """Signal a running scan to stop"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        if not scan_id or scan_id not in active_scanners:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = active_scanners[scan_id]
        scanner_obj = scan.get('object')
        if hasattr(scanner_obj, 'stop'):
            scanner_obj.stop()
        scan['status'] = 'stopped'
        
        return jsonify({'status': 'stopped', 'message': 'Scan stop requested'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/scan/interfaces', methods=['GET'])
@require_attacker
def list_interfaces():
    """List network interfaces with ip/cidr/gateway info."""
    try:
        return jsonify({
            'interfaces': list_interfaces_detailed(),
            'default_range': get_default_network_range()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# TRAFFIC SNIFFER ENDPOINTS
# ============================================================================

@api_bp.route('/sniff/start', methods=['POST'])
@require_attacker
def start_sniffer():
    """Start traffic sniffing"""
    try:
        data = request.get_json()
        bpf_filter = data.get('filter')
        interface = data.get('interface')
        
        # Create sniffer and attach callback to keep packets in memory
        sniffer = TrafficSniffer(interface=interface)
        sniffer_id = str(uuid.uuid4())
        
        def run_sniff():
            try:
                sniffer.start_sniffing(filter_str=bpf_filter)
            except Exception as e:
                print(f"Sniffer Error: {e}")
        
        thread = threading.Thread(target=run_sniff, daemon=True)
        thread.start()
        
        # Store sniffer
        active_sniffers[sniffer_id] = {
            'object': sniffer,
            'filter': bpf_filter,
            'packets': [],
            'status': 'capturing'
        }
        
        return jsonify({
            'sniffer_id': sniffer_id,
            'status': 'started',
            'message': 'Traffic sniffer started'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/sniff/packets/<sniffer_id>', methods=['GET'])
@require_attacker
def get_packets(sniffer_id):
    """Get captured packets"""
    try:
        if sniffer_id not in active_sniffers:
            return jsonify({'error': 'Sniffer not found'}), 404
        
        sniffer_info = active_sniffers[sniffer_id]
        sniffer = sniffer_info['object']
        
        packets = sniffer.get_packets(limit=50)
        
        return jsonify({
            'sniffer_id': sniffer_id,
            'packets': packets,
            'status': 'capturing' if sniffer.is_sniffing else 'stopped'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/sniff/stop', methods=['POST'])
@require_attacker
def stop_sniffer():
    """Stop traffic sniffer"""
    try:
        data = request.get_json()
        sniffer_id = data.get('sniffer_id')
        
        if sniffer_id not in active_sniffers:
            return jsonify({'error': 'Sniffer not found'}), 404
        
        sniffer = active_sniffers[sniffer_id]['object']
        sniffer.stop_sniffing()
        
        del active_sniffers[sniffer_id]
        
        return jsonify({
            'status': 'stopped',
            'message': 'Sniffer stopped'
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SYSTEM INFO ENDPOINT
# ============================================================================

@api_bp.route('/network/info', methods=['GET'])
def get_network_info():
    """Get system and network information"""
    try:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_usage = psutil.virtual_memory().percent
        
        return jsonify({
            'local_ip': get_local_ip(),
            'gateway_ip': get_gateway_ip(),
            'active_attacks': len(active_scanners),  # Reuse for count
            'active_scans': len(active_sniffers),
            'cpu_usage': round(cpu_usage, 2),
            'ram_usage': round(ram_usage, 2)
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
