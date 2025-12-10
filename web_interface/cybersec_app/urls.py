"""
URL Configuration for Attacker Interface
Minimized endpoints for ARP Spoofing and SYN Flooding attacks
"""

from django.urls import path
from . import views

urlpatterns = [
    # Main attacker interface page
    path('attacker/', views.attacker_view, name='attacker'),
    
    # ARP Spoofing Attack API Endpoints
    path('api/attack/arp/start/', views.start_arp_attack, name='api_start_arp'),
    path('api/attack/arp/stop/', views.stop_arp_attack, name='api_stop_arp'),
    
    # SYN Flooding Attack API Endpoints
    path('api/attack/syn/start/', views.start_syn_attack, name='api_start_syn'),
    path('api/attack/syn/stop/', views.stop_syn_attack, name='api_stop_syn'),
    
    # Attack Statistics API Endpoint
    path('api/attack/stats/', views.get_attack_stats, name='api_attack_stats'),
]
