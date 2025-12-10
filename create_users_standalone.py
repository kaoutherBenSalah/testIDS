#!/usr/bin/env python
"""
Standalone script to create default users for IDS Platform
Run this from the project root: python create_users_standalone.py
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'web_interface.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

django.setup()

from web_interface.cybersec_app.models import User, UserRole

def create_users():
    print("\n" + "="*70)
    print("Creating Default Users for IDS Platform")
    print("="*70 + "\n")
    
    users_created = 0
    users_existing = 0
    
    # Create Attacker User
    attacker_username = 'attacker'
    attacker_password = 'attack123'
    
    if not User.objects.filter(username=attacker_username).exists():
        attacker = User.objects.create_user(
            username=attacker_username,
            password=attacker_password,
            email='attacker@ids.local',
            first_name='Red',
            last_name='Team',
            role=UserRole.ATTACKER,
            machine_type='kali'
        )
        print(f'✅ Created ATTACKER user:')
        print(f'   Username: {attacker_username}')
        print(f'   Password: {attacker_password}')
        print(f'   Role: {attacker.get_role_display()}\n')
        users_created += 1
    else:
        print(f'⚠️  User "{attacker_username}" already exists\n')
        users_existing += 1
    
    # Create Defender User
    defender_username = 'defender'
    defender_password = 'defend123'
    
    if not User.objects.filter(username=defender_username).exists():
        defender = User.objects.create_user(
            username=defender_username,
            password=defender_password,
            email='defender@ids.local',
            first_name='Blue',
            last_name='Team',
            role=UserRole.DEFENDER,
            machine_type='ubuntu'
        )
        print(f'✅ Created DEFENDER user:')
        print(f'   Username: {defender_username}')
        print(f'   Password: {defender_password}')
        print(f'   Role: {defender.get_role_display()}\n')
        users_created += 1
    else:
        print(f'⚠️  User "{defender_username}" already exists\n')
        users_existing += 1
    
    # Create Admin User
    admin_username = 'admin'
    admin_password = 'admin123'
    
    if not User.objects.filter(username=admin_username).exists():
        admin = User.objects.create_superuser(
            username=admin_username,
            password=admin_password,
            email='admin@ids.local',
            first_name='Admin',
            last_name='User',
            role=UserRole.ADMIN
        )
        print(f'✅ Created ADMIN user:')
        print(f'   Username: {admin_username}')
        print(f'   Password: {admin_password}')
        print(f'   Role: {admin.get_role_display()}\n')
        users_created += 1
    else:
        print(f'⚠️  User "{admin_username}" already exists\n')
        users_existing += 1
    
    # Summary
    print("="*70)
    print(f'Summary:')
    print(f'  Users Created: {users_created}')
    print(f'  Users Existing: {users_existing}')
    print("="*70 + "\n")
    
    print('🎯 ATTACKER machine:')
    print(f'   Login: {attacker_username} / {attacker_password}')
    print('   Access: http://192.168.189.10:8000/attacker/\n')
    
    print('✅ Done!\n')

if __name__ == '__main__':
    create_users()
