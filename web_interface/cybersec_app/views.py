"""
MINIMIZED Cybersecurity Platform - Attacker Interface Views

This module provides the API endpoints for the attacker interface.
It handles ARP Spoofing and SYN Flooding attack controls.

Endpoints:
- Attacker Interface Page View
- ARP Spoofing Attack Control (Start/Stop)
- SYN Flooding Attack Control (Start/Stop)
- Attack Statistics Monitoring
- Network Information Retrieval
"""

import json
import sys
import os
from pathlib import Path
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
import threading

# Add project root to Python path for module imports
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from modules.arp_spoof import ARPSpoofer
from modules.syn_flood import SYNFlooder
from utils.network_utils import get_local_ip, get_gateway_ip

# Global storage for running attacks
# Maps attack IDs to attack objects and metadata
active_attacks = {}


def attacker_view(request):
    """
    Render the main attacker interface page.
    
    This view displays the ARP Spoofing and SYN Flooding attack panels,
    allowing users to configure and launch network attacks.
    
    Args:
        request: Django HTTP request object
    
    Returns:
        Rendered attacker.html template
    """
    return render(request, 'attacker.html')


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

