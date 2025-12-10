"""
URL Configuration for IDS Platform
Complete attacker and authentication endpoints
"""

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # ========== AUTHENTICATION ==========
    path('', views.attacker_dashboard, name='dashboard'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    # ========== ATTACKER INTERFACE ==========
    path('attacker/', views.attacker_dashboard, name='attacker'),
    
    # ========== ARP SPOOFING ==========
    path('api/attack/arp/start/', views.start_arp_attack, name='api_start_arp'),
    path('api/attack/arp/stop/', views.stop_arp_attack, name='api_stop_arp'),
    
    # ========== SYN FLOODING ==========
    path('api/attack/syn/start/', views.start_syn_attack, name='api_start_syn'),
    path('api/attack/syn/stop/', views.stop_syn_attack, name='api_stop_syn'),
    
    # ========== ATTACK STATISTICS ==========
    path('api/attack/stats/', views.get_attack_stats, name='api_attack_stats'),
    
    # ========== NETWORK SCANNER ==========
    path('api/scan/start/', views.start_network_scan, name='api_start_scan'),
    path('api/scan/results/<str:scan_id>/', views.get_scan_results, name='api_scan_results'),
    
    # ========== TRAFFIC SNIFFER ==========
    path('api/sniff/start/', views.start_traffic_sniff, name='api_start_sniff'),
    path('api/sniff/packets/<str:sniffer_id>/', views.get_sniffed_packets, name='api_sniff_packets'),
    path('api/sniff/stop/', views.stop_traffic_sniff, name='api_stop_sniff'),
    
    # ========== SYSTEM INFO ==========
    path('api/network/info/', views.get_network_info, name='api_network_info'),
]
