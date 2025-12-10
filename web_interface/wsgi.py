"""
WSGI config for web_interface project.
"""

import os
import sys
from pathlib import Path
from django.core.wsgi import get_wsgi_application

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'web_interface.settings')

application = get_wsgi_application()
