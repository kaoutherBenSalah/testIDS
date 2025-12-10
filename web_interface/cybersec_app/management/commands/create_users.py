"""
Django Management Command: Create Default Users
Creates attacker and defender users for the IDS platform

Usage:
    python manage.py create_users
"""

from django.core.management.base import BaseCommand
from django.conf import settings
from web_interface.cybersec_app.models import User, UserRole


class Command(BaseCommand):
    help = 'Creates default users for attacker and defender'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('\n' + '='*70))
        self.stdout.write(self.style.SUCCESS('Creating Default Users for IDS Platform'))
        self.stdout.write(self.style.SUCCESS('='*70 + '\n'))
        
        # Determine machine type
        machine_type = settings.MACHINE_TYPE
        self.stdout.write(f"Machine Type: {machine_type}\n")
        
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
            self.stdout.write(self.style.SUCCESS(
                f'✅ Created ATTACKER user:\n'
                f'   Username: {attacker_username}\n'
                f'   Password: {attacker_password}\n'
                f'   Role: {attacker.get_role_display()}\n'
            ))
            users_created += 1
        else:
            self.stdout.write(self.style.WARNING(
                f'⚠️  User "{attacker_username}" already exists\n'
            ))
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
            self.stdout.write(self.style.SUCCESS(
                f'✅ Created DEFENDER user:\n'
                f'   Username: {defender_username}\n'
                f'   Password: {defender_password}\n'
                f'   Role: {defender.get_role_display()}\n'
            ))
            users_created += 1
        else:
            self.stdout.write(self.style.WARNING(
                f'⚠️  User "{defender_username}" already exists\n'
            ))
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
            self.stdout.write(self.style.SUCCESS(
                f'✅ Created ADMIN user:\n'
                f'   Username: {admin_username}\n'
                f'   Password: {admin_password}\n'
                f'   Role: {admin.get_role_display()}\n'
            ))
            users_created += 1
        else:
            self.stdout.write(self.style.WARNING(
                f'⚠️  User "{admin_username}" already exists\n'
            ))
            users_existing += 1
        
        # Summary
        self.stdout.write(self.style.SUCCESS('='*70))
        self.stdout.write(self.style.SUCCESS(f'Summary:'))
        self.stdout.write(self.style.SUCCESS(f'  Users Created: {users_created}'))
        self.stdout.write(self.style.SUCCESS(f'  Users Existing: {users_existing}'))
        self.stdout.write(self.style.SUCCESS('='*70 + '\n'))
        
        if machine_type == 'attacker':
            self.stdout.write(self.style.SUCCESS(
                '🎯 This is an ATTACKER machine.\n'
                f'   Login with: {attacker_username} / {attacker_password}\n'
                '   Access: http://localhost:8000/attacker/\n'
            ))
        elif machine_type == 'defender':
            self.stdout.write(self.style.SUCCESS(
                '🛡️  This is a DEFENDER machine.\n'
                f'   Login with: {defender_username} / {defender_password}\n'
                '   Access: http://localhost:8000/defender/\n'
            ))
        
        self.stdout.write(self.style.SUCCESS('Done!\n'))
