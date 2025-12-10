#!/usr/bin/env python
"""
Standalone User Creation Script for IDS Platform

This script creates three default users for testing the platform:
- ATTACKER: Has access to attack simulation features
- DEFENDER: Has access to detection and monitoring features  
- ADMIN: Has full administrative access

Run this from the project root:
    python create_users_standalone.py

The script will only create users that don't already exist.
"""

import os                           # OS operations
import sys                          # System utilities
import django                       # Django framework

# ============ DJANGO SETUP ============
# Set the Django settings module before importing models
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'web_interface.settings')
# Add project root to Python path for proper imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Initialize Django
django.setup()

# Import Django models after Django is configured
from web_interface.cybersec_app.models import User, UserRole

def create_users():
    """Create default users for the IDS platform"""
    # Display script header
    print("\n" + "="*70)
    print("Creating Default Users for IDS Platform")
    print("="*70 + "\n")
    
    # Initialize counters for statistics
    users_created = 0                # Count of newly created users
    users_existing = 0               # Count of users that already existed
    
    # ============ CREATE ATTACKER USER ============
    # This user represents the attacker/red team
    attacker_username = 'attacker'
    attacker_password = 'attack123'
    
    # Check if attacker user already exists
    if not User.objects.filter(username=attacker_username).exists():
        # Create new attacker user
        attacker = User.objects.create_user(
            username=attacker_username,
            password=attacker_password,
            email='attacker@ids.local',
            first_name='Red',
            last_name='Team',
            role=UserRole.ATTACKER,            # Set role to ATTACKER
            machine_type='kali'                # Simulating Kali Linux machine
        )
        print(f'✅ Created ATTACKER user:')
        print(f'   Username: {attacker_username}')
        print(f'   Password: {attacker_password}')
        print(f'   Role: {attacker.get_role_display()}\n')
        users_created += 1
    else:
        # User already exists
        print(f'⚠️  User "{attacker_username}" already exists\n')
        users_existing += 1
    
    # ============ CREATE DEFENDER USER ============
    # This user represents the defender/blue team
    defender_username = 'defender'
    defender_password = 'defend123'
    
    # Check if defender user already exists
    if not User.objects.filter(username=defender_username).exists():
        # Create new defender user
        defender = User.objects.create_user(
            username=defender_username,
            password=defender_password,
            email='defender@ids.local',
            first_name='Blue',
            last_name='Team',
            role=UserRole.DEFENDER,            # Set role to DEFENDER
            machine_type='ubuntu'              # Simulating Ubuntu machine
        )
        print(f'✅ Created DEFENDER user:')
        print(f'   Username: {defender_username}')
        print(f'   Password: {defender_password}')
        print(f'   Role: {defender.get_role_display()}\n')
        users_created += 1
    else:
        # User already exists
        print(f'⚠️  User "{defender_username}" already exists\n')
        users_existing += 1
    
    # ============ CREATE ADMIN USER ============
    # This user has full system access
    admin_username = 'admin'
    admin_password = 'admin123'
    
    # Check if admin user already exists
    if not User.objects.filter(username=admin_username).exists():
        # Create new superuser (admin) using create_superuser method
        # create_superuser is a special method that creates admin users
        admin = User.objects.create_superuser(
            username=admin_username,
            password=admin_password,
            email='admin@ids.local',
            first_name='Admin',
            last_name='User',
            role=UserRole.ADMIN                # Set role to ADMIN
        )
        print(f'✅ Created ADMIN user:')
        print(f'   Username: {admin_username}')
        print(f'   Password: {admin_password}')
        print(f'   Role: {admin.get_role_display()}\n')
        users_created += 1
    else:
        # User already exists
        print(f'⚠️  User "{admin_username}" already exists\n')
        users_existing += 1
    
    # ============ DISPLAY SUMMARY ============
    print("="*70)
    print(f'Summary:')
    print(f'  Users Created: {users_created}')
    print(f'  Users Existing: {users_existing}')
    print("="*70 + "\n")
    
    # Display access information for attacker machine
    print('🎯 ATTACKER machine:')
    print(f'   Login: {attacker_username} / {attacker_password}')
    print('   Access: http://192.168.189.10:8000/attacker/\n')
    
    print('✅ Done!\n')

# ============ SCRIPT ENTRY POINT ============
# Only run create_users() if this script is executed directly
if __name__ == '__main__':
    create_users()
