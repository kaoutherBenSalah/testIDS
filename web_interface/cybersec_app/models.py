"""
Models for IDS Platform
Includes User model, AttackLog, DetectionLog, and Configuration
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class UserRole(models.TextChoices):
    """User role choices"""
    ATTACKER = 'ATTACKER', 'Attacker'
    DEFENDER = 'DEFENDER', 'Defender'
    ADMIN = 'ADMIN', 'Admin'


class User(AbstractUser):
    """
    Custom User model with role-based permissions
    
    Roles:
    - ATTACKER: Can launch attacks, scan networks
    - DEFENDER: Can monitor attacks, configure IDS
    - ADMIN: Full access to both sides
    """
    
    role = models.CharField(
        max_length=10,
        choices=UserRole.choices,
        default=UserRole.ATTACKER,
        help_text="User's role in the system"
    )
    
    machine_type = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="Machine this user is associated with (kali/defender)"
    )
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def is_attacker(self):
        """Check if user has attacker role"""
        return self.role == UserRole.ATTACKER or self.role == UserRole.ADMIN
    
    def is_defender(self):
        """Check if user has defender role"""
        return self.role == UserRole.DEFENDER or self.role == UserRole.ADMIN
    
    def is_admin_user(self):
        """Check if user has admin role"""
        return self.role == UserRole.ADMIN


class AttackLog(models.Model):
    """Log of attack activities"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attack_logs')
    attack_type = models.CharField(max_length=50)  # ARP_SPOOFING, SYN_FLOOD
    target_ip = models.GenericIPAddressField()
    gateway_ip = models.GenericIPAddressField(null=True, blank=True)
    target_port = models.IntegerField(null=True, blank=True)
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    packets_sent = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='running')  # running, stopped, completed
    notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'attack_logs'
        ordering = ['-start_time']
    
    def __str__(self):
        return f"{self.attack_type} on {self.target_ip} at {self.start_time}"


class DetectionLog(models.Model):
    """Log of IDS detections"""
    
    alert_type = models.CharField(max_length=50)  # ARP_SPOOFING, SYN_FLOOD
    severity = models.CharField(max_length=20)  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    target_ip = models.GenericIPAddressField()
    detected_at = models.DateTimeField(default=timezone.now)
    details = models.JSONField(default=dict)
    is_blocked = models.BooleanField(default=False)
    blocked_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'detection_logs'
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.alert_type} detected on {self.target_ip}"


class Configuration(models.Model):
    """System configuration key-value store"""
    
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    category = models.CharField(max_length=50)  # attack, defense, general
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'configurations'
        ordering = ['category', 'key']
    
    def __str__(self):
        return f"{self.key} = {self.value}"
