"""
Cybersecurity Platform - Attacker Interface Views

Complete attacker-side views with:
- Network Scanner
- ARP Spoofing
- SYN Flooding
- Traffic Sniffer
- Real-time Statistics
"""

import json
import sys
import os
import uuid
import threading
from pathlib import Path
from datetime import datetime
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view
from rest_framework.response import Response

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from modules.arp_spoof import ARPSpoofer
from modules.syn_flood import SYNFlooder
from modules.network_scanner import NetworkScanner
from modules.traffic_sniffer import TrafficSniffer
from utils.network_utils import get_local_ip, get_gateway_ip
from .models import AttackLog, User, UserRole

# Global storage for running attacks and scanners
active_attacks = {}  # {attack_id: {'object': attack_obj, 'type': 'arp'|'syn', 'data': {...}}}
active_scanners = {}  # {scan_id: {'object': scanner_obj, 'data': {...}}}
active_sniffers = {}  # {sniffer_id: {'object': sniffer_obj, 'data': {...}}}


def check_attacker_role(user):
    """Check if user has attacker permissions"""
    return user.is_authenticated and user.is_attacker()


@login_required(login_url='login')
def attacker_dashboard(request):
    """
    Main attacker interface dashboard
    
    Shows network info, active machines, and attack controls
    """
    if not check_attacker_role(request.user):
        return redirect('login')
    
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip()
    
    context = {
        'local_ip': local_ip,
        'gateway_ip': gateway_ip,
        'active_attacks': len(active_attacks),
        'active_scans': len(active_scanners),
    }
    
    return render(request, 'attacker.html', context)


# ============================================================================
# API ENDPOINTS - ATTACKER INTERFACE FUNCTIONS
# ============================================================================

@api_view(['POST'])
def start_arp_attack(request):
    """
    START ARP SPOOFING ATTACK ENDPOINT
    
    Initiates an ARP Spoofing (Man-in-the-Middle) attack against a target IP
    by poisoning the ARP tables of both the target and gateway.
    
    Required Parameters:
        - target_ip (str): IP address of the victim machine
        - gateway_ip (str): IP address of the network gateway/router
    
    Optional Parameters:
        - interface (str): Network interface to use (e.g., 'eth0', 'wlan0')
        - interval (int): Time between ARP packets in seconds (default: 2)
    
    Returns:
        - On Success (200): {
            'status': 'started',
            'attack_id': str (unique identifier),
            'message': str (confirmation message)
          }
        - On Error (400/500): {'error': str (error description)}
    
    Attack Process:
        1. Validates input parameters
        2. Creates ARPSpoofer object with target and gateway IPs
        3. Launches attack in a background thread
        4. Stores attack reference for status tracking
        5. Returns attack ID for stop/monitoring operations
    """
    try:
        # Extract parameters from request
        target_ip = request.data.get('target_ip')
        gateway_ip = request.data.get('gateway_ip')
        interface = request.data.get('interface', None)
        interval = int(request.data.get('interval', 2))
        
        # Validate required parameters
        if not target_ip or not gateway_ip:
            return Response({'error': 'Missing required parameters'}, status=400)
        
        # Create ARP Spoofer object
        spoofer = ARPSpoofer(target_ip, gateway_ip, interface)
        
        # Start attack in background thread to avoid blocking request
        attack_thread = threading.Thread(
            target=spoofer.start_attack,
            args=(interval, True),
            daemon=True
        )
        attack_thread.start()
        
        # Store attack reference using unique attack ID
        attack_id = f"arp_{target_ip}"
        active_attacks[attack_id] = {
            'type': 'arp',
            'spoofer': spoofer,
            'thread': attack_thread
        }
        
        return Response({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'ARP Spoofing attack started against {target_ip}'
        })
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)




@api_view(['POST'])
def stop_arp_attack(request):
    """
    STOP ARP SPOOFING ATTACK ENDPOINT
    
    Terminates an active ARP Spoofing attack and restores ARP tables to normal.
    
    Required Parameters:
        - attack_id (str): The unique identifier of the attack to stop
    
    Returns:
        - On Success (200): {
            'status': 'stopped',
            'message': str (confirmation message)
          }
        - On Error (404/500): {'error': str (error description)}
    
    Cleanup Process:
        1. Finds the active attack by attack_id
        2. Calls stop_attack() to restore ARP tables
        3. Removes attack from active_attacks tracking
        4. Confirms restoration completion
    """
    try:
        # Get attack ID to identify which attack to stop
        attack_id = request.data.get('attack_id')
        
        # Check if attack exists in active attacks
        if attack_id in active_attacks:
            attack = active_attacks[attack_id]
            
            # Stop the spoofer (restores ARP tables automatically)
            attack['spoofer'].stop_attack()
            
            # Remove from tracking
            del active_attacks[attack_id]
            
            return Response({
                'status': 'stopped',
                'message': 'ARP attack stopped and tables restored'
            })
        
        # Attack not found
        return Response({'error': 'Attack not found'}, status=404)
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)





@api_view(['POST'])
def start_syn_attack(request):
    """
    START SYN FLOODING ATTACK ENDPOINT
    
    Initiates a SYN Flooding (Denial of Service) attack against a target IP.
    This attack floods the target with TCP SYN packets, exhausting server resources.
    
    Required Parameters:
        - target_ip (str): IP address of the target server
    
    Optional Parameters:
        - target_port (int): TCP port to attack (default: 80)
        - num_threads (int): Number of concurrent attack threads (default: 10)
        - duration (int): Attack duration in seconds (default: infinite)
    
    Returns:
        - On Success (200): {
            'status': 'started',
            'attack_id': str (unique identifier),
            'message': str (confirmation message)
          }
        - On Error (400/500): {'error': str (error description)}
    
    Attack Process:
        1. Validates target IP and port parameters
        2. Creates SYNFlooder object with thread configuration
        3. Launches attack in a background thread
        4. Stores attack reference for status tracking and stopping
        5. Returns attack ID for monitoring and termination
    """
    try:
        # Extract parameters from request
        target_ip = request.data.get('target_ip')
        target_port = int(request.data.get('target_port', 80))
        num_threads = int(request.data.get('num_threads', 10))
        duration = request.data.get('duration', None)
        if duration:
            duration = int(duration)
        
        # Validate required parameter
        if not target_ip:
            return Response({'error': 'Missing target IP'}, status=400)
        
        # Create SYN Flooder object
        flooder = SYNFlooder(target_ip, target_port, num_threads)
        
        # Start attack in background thread
        attack_thread = threading.Thread(
            target=flooder.start_attack,
            args=(duration,),
            daemon=True
        )
        attack_thread.start()
        
        # Store attack reference for tracking
        attack_id = f"syn_{target_ip}_{target_port}"
        active_attacks[attack_id] = {
            'type': 'syn',
            'flooder': flooder,
            'thread': attack_thread
        }
        
        return Response({
            'status': 'started',
            'attack_id': attack_id,
            'message': f'SYN Flood attack started against {target_ip}:{target_port}'
        })
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
def stop_syn_attack(request):
    """
    STOP SYN FLOODING ATTACK ENDPOINT
    
    Terminates an active SYN Flooding attack.
    
    Required Parameters:
        - attack_id (str): The unique identifier of the attack to stop
    
    Returns:
        - On Success (200): {
            'status': 'stopped',
            'message': str (confirmation message)
          }
        - On Error (404/500): {'error': str (error description)}
    
    Cleanup Process:
        1. Identifies the active SYN attack by attack_id
        2. Calls stop_attack() to terminate packet sending
        3. Removes attack from active_attacks tracking
        4. Confirms termination
    """
    try:
        # Get attack ID to identify which attack to stop
        attack_id = request.data.get('attack_id')
        
        # Check if attack exists
        if attack_id in active_attacks:
            attack = active_attacks[attack_id]
            
            # Stop the flooder (halts packet transmission)
            attack['flooder'].stop_attack()
            
            # Remove from tracking
            del active_attacks[attack_id]
            
            return Response({
                'status': 'stopped',
                'message': 'SYN Flood attack stopped'
            })
        
        # Attack not found
        return Response({'error': 'Attack not found'}, status=404)
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)





@api_view(['GET'])
def get_attack_stats(request):
    """
    GET ATTACK STATISTICS ENDPOINT
    
    Retrieves real-time statistics for all active attacks.
    
    Parameters:
        - None required
    
    Returns:
        - Success (200): {
            'attacks': {
              'attack_id': {
                'type': str ('ARP Spoofing' or 'SYN Flood'),
                'packets_sent': int (number of packets),
                'is_running': bool (current status)
              },
              ...
            }
          }
        - Error (500): {'error': str (error description)}
    
    Statistics Provided:
        - attack_id: Unique identifier for the attack
        - type: Type of attack (ARP or SYN)
        - packets_sent: Total packets sent since attack start
        - is_running: Current execution status (True/False)
    """
    try:
        stats = {}
        
        # Iterate through all active attacks
        for attack_id, attack_data in active_attacks.items():
            if attack_data['type'] == 'arp':
                # Get ARP spoofer statistics
                spoofer = attack_data['spoofer']
                stats[attack_id] = {
                    'type': 'ARP Spoofing',
                    'packets_sent': spoofer.packets_sent,
                    'is_running': spoofer.is_running
                }
            elif attack_data['type'] == 'syn':
                # Get SYN flooder statistics
                flooder = attack_data['flooder']
                stats[attack_id] = {
                    'type': 'SYN Flood',
                    'packets_sent': flooder.packets_sent,
                    'is_running': flooder.is_running
                }
        
        return Response({'attacks': stats})
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# ============================================================================
# NETWORK SCANNER API ENDPOINTS
# ============================================================================

@require_http_methods(["POST"])
@login_required
@csrf_exempt
def start_network_scan(request):
    """
    START NETWORK SCAN ENDPOINT
    
    Scans a network range for active hosts and open ports
    
    Required Parameters:
        - network_range (str): Network range in CIDR (e.g., '192.168.1.0/24')
    
    Optional Parameters:
        - full_scan (bool): Include port scanning (slower, default: False)
    
    Returns:
        - Success: {
            'status': 'scanning',
            'scan_id': str,
            'message': str
          }
    """
    try:
        if not check_attacker_role(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Parse JSON or form data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST
        
        network_range = data.get('network_range')
        full_scan = data.get('full_scan', False)
        
        if not network_range:
            return JsonResponse({'error': 'Missing network_range parameter'}, status=400)
        
        # Create scanner
        scanner = NetworkScanner()
        
        # Start scan in background thread
        scan_id = f"scan_{str(uuid.uuid4())[:8]}"
        
        if full_scan:
            scan_thread = threading.Thread(
                target=scanner.identify_active_machines,
                args=(network_range,),
                daemon=True
            )
        else:
            scan_thread = threading.Thread(
                target=scanner.scan_subnet,
                args=(network_range,),
                daemon=True
            )
        
        scan_thread.start()
        
        # Store scanner reference
        active_scanners[scan_id] = {
            'scanner': scanner,
            'network_range': network_range,
            'thread': scan_thread,
            'start_time': datetime.now()
        }
        
        return JsonResponse({
            'status': 'scanning',
            'scan_id': scan_id,
            'message': f'Scanning network {network_range}...'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
@login_required
def get_scan_results(request, scan_id):
    """
    GET NETWORK SCAN RESULTS
    
    Retrieves results from a completed or in-progress network scan
    
    Parameters:
        - scan_id (str): The scan identifier
    
    Returns:
        - Success: {
            'status': 'completed' or 'scanning',
            'hosts': [...],
            'count': int
          }
    """
    try:
        if scan_id not in active_scanners:
            return JsonResponse({'error': 'Scan not found'}, status=404)
        
        scan_data = active_scanners[scan_id]
        scanner = scan_data['scanner']
        
        # Convert hosts to JSON-serializable format
        hosts = [host.to_dict() for host in scanner.discovered_hosts]
        
        is_complete = not scan_data['thread'].is_alive()
        
        return JsonResponse({
            'status': 'completed' if is_complete else 'scanning',
            'hosts': hosts,
            'count': len(hosts)
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# TRAFFIC SNIFFER API ENDPOINTS
# ============================================================================

@require_http_methods(["POST"])
@login_required
@csrf_exempt
def start_traffic_sniff(request):
    """
    START TRAFFIC SNIFFER ENDPOINT
    
    Starts capturing network traffic with optional filtering
    
    Optional Parameters:
        - filter (str): BPF filter (e.g., 'tcp port 80')
        - count (int): Max packets to capture
    
    Returns:
        - Success: {'status': 'sniffing', 'sniffer_id': str}
    """
    try:
        if not check_attacker_role(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Parse request data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST
        
        filter_str = data.get('filter', None)
        count = int(data.get('count', 0))
        
        # Create sniffer
        sniffer = TrafficSniffer()
        sniffer_id = f"sniff_{str(uuid.uuid4())[:8]}"
        
        # Start sniffing
        sniffer.start_sniffing(filter_str=filter_str, count=count)
        
        # Store sniffer reference
        active_sniffers[sniffer_id] = {
            'sniffer': sniffer,
            'filter': filter_str,
            'start_time': datetime.now()
        }
        
        return JsonResponse({
            'status': 'sniffing',
            'sniffer_id': sniffer_id,
            'message': f'Capturing traffic{" (filter: " + filter_str + ")" if filter_str else ""}...'
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
@login_required
def get_sniffed_packets(request, sniffer_id):
    """
    GET CAPTURED PACKETS
    
    Returns packets captured by a traffic sniffer
    
    Parameters:
        - sniffer_id (str): The sniffer identifier
    
    Returns:
        - Success: {
            'status': 'sniffing' or 'stopped',
            'packets': [...],
            'count': int,
            'stats': {...}
          }
    """
    try:
        if sniffer_id not in active_sniffers:
            return JsonResponse({'error': 'Sniffer not found'}, status=404)
        
        sniff_data = active_sniffers[sniffer_id]
        sniffer = sniff_data['sniffer']
        
        packets = sniffer.intercept_traffic()
        stats = sniffer.get_statistics()
        
        return JsonResponse({
            'status': 'sniffing' if sniffer.is_sniffing else 'stopped',
            'packets': packets[-50:],  # Return last 50 packets (for performance)
            'count': len(packets),
            'stats': stats
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
@login_required
@csrf_exempt
def stop_traffic_sniff(request):
    """Stop traffic sniffer"""
    try:
        sniffer_id = request.data.get('sniffer_id') if request.content_type == 'application/json' else request.POST.get('sniffer_id')
        
        if sniffer_id not in active_sniffers:
            return JsonResponse({'error': 'Sniffer not found'}, status=404)
        
        sniffer_data = active_sniffers[sniffer_id]
        sniffer = sniffer_data['sniffer']
        sniffer.stop_sniffing()
        
        return JsonResponse({'status': 'stopped', 'message': 'Traffic sniffer stopped'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# SYSTEM INFO ENDPOINTS
# ============================================================================

@api_view(['GET'])
@login_required
def get_network_info(request):
    """Get local network information"""
    try:
        if not check_attacker_role(request.user):
            return Response({'error': 'Permission denied'}, status=403)
        
        return Response({
            'local_ip': get_local_ip(),
            'gateway_ip': get_gateway_ip(),
            'active_attacks': len(active_attacks),
            'active_scans': len(active_scanners),
            'active_sniffers': len(active_sniffers)
        })
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)


