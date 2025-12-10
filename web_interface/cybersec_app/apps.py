"""
App configuration
"""

from django.apps import AppConfig


class CybersecAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'web_interface.cybersec_app'
    verbose_name = 'Cybersecurity Platform'
