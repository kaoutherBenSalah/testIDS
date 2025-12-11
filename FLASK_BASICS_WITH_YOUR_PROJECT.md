# Flask Basics - Explained with YOUR IDS Project

## Table of Contents
1. [What is Flask?](#what-is-flask)
2. [Flask vs Django](#flask-vs-django)
3. [Your Project Structure](#your-project-structure)
4. [Core Flask Concepts](#core-flask-concepts)
5. [How YOUR Project Uses Flask](#how-your-project-uses-flask)

---

## What is Flask?

**Flask** is a lightweight web framework for Python. Think of it as a toolkit for building web applications.

### Flask = A Collection of Tools
- **Request/Response Handler**: Listens for HTTP requests from browsers/clients
- **Template Engine**: Renders HTML pages with Python variables
- **Routing System**: Maps URLs to Python functions
- **Session Management**: Remembers who is logged in
- **Blueprint System**: Organizes code into modules

### Why Flask?
- ✅ Minimal and flexible (you decide the structure)
- ✅ Perfect for learning
- ✅ Easy to extend with plugins
- ✅ Great for REST APIs and web apps
- ✅ Used in production by many companies

---

## Flask vs Django

| Aspect | Flask | Django |
|--------|-------|--------|
| **Size** | Lightweight (~1000 lines) | Heavy (~50,000 lines) |
| **Learning Curve** | Easy | Steep |
| **Database** | You choose | Built-in ORM |
| **Admin Panel** | None by default | Included |
| **Best For** | APIs, MVPs, learning | Large enterprise projects |
| **Your Project** | ✅ Perfect fit | Overkill |

---

## Your Project Structure

```
testIDS/
├── app.py                 # Main Flask application (the heart!)
├── models.py              # User data (JSON-based, no database)
├── requirements-flask.txt # Dependencies
├── routes/
│   ├── attacks.py        # ARP/SYN attack endpoints
│   └── api.py            # Scanner/Sniffer API endpoints
├── modules/              # Attack tools
│   ├── arp_spoof.py
│   ├── syn_flood.py
│   ├── network_scanner.py
│   └── traffic_sniffer.py
├── utils/                # Helper functions
│   ├── network_utils.py
│   └── logger.py
└── templates/            # HTML pages shown to users
    ├── login.html
    ├── base.html
    ├── attacker.html
    ├── defender.html
    └── ...
```

**Key Files:**
- `app.py` = The main Flask app (routes + config)
- `routes/*.py` = URL endpoints (what happens when you click buttons)
- `templates/*.html` = What users see in their browser
- `modules/*.py` = The actual attack/scan tools

---

## Core Flask Concepts

### 1. **The Flask App (app.py)**

```python
from flask import Flask

app = Flask(__name__)  # Create a Flask application instance
app.secret_key = 'your-secret-key'  # For session encryption
```

**What does this do?**
- `app` = Your entire web application
- `Flask(__name__)` = Initialize Flask with the current module's name
- `secret_key` = Encrypts cookies/sessions so users can't tamper with them

### 2. **Routes (URL Mapping)**

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle form submission
        return redirect(url_for('dashboard'))
    return render_template('login.html')
```

**Breaking it down:**
- `@app.route('/login', ...)` = "When user visits `/login`, run this function"
- `methods=['GET', 'POST']` = Accept both viewing the page (GET) and submitting forms (POST)
- `render_template('login.html')` = Send the HTML file to the browser
- `redirect(url_for('dashboard'))` = Send user to another page

**In YOUR Project:**
```python
# app.py - Lines 73-80
@app.route('/logout')
def logout():
    session.clear()  # Clear user login info
    return redirect(url_for('login'))  # Go back to login page
```

### 3. **Templates (HTML + Python)**

**login.html:**
```html
<form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
```

**app.py:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')  # Get "username" from form
    password = request.form.get('password')  # Get "password" from form
    
    if verify_password(username, password):
        session['user_id'] = username  # Remember this user
        return redirect(url_for('dashboard'))
```

**The Flow:**
1. User fills in form → Browser sends POST request
2. Flask receives request → Extracts form data
3. Flask checks password → Sets session cookie
4. Flask redirects → User sees dashboard

### 4. **Sessions (Remembering Users)**

```python
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:  # Not logged in?
        return redirect(url_for('login'))
    
    username = session['user_id']  # Get logged-in user
    role = session.get('user_role')  # Get user's role (ATTACKER/DEFENDER)
```

**How it works:**
1. After login, Flask sets a **session cookie** in browser
2. Browser automatically sends this cookie with every request
3. Flask reads the cookie → Knows who is visiting
4. Cookie expires → User must log in again

**In YOUR Project:**
```python
# app.py - Lines 78-80
session['user_id'] = username
session['user_role'] = user_record['role']
```

### 5. **Blueprints (Organizing Routes)**

Flask apps can have hundreds of routes. **Blueprints** let you organize them into modules.

```python
# routes/attacks.py
from flask import Blueprint

attacks_bp = Blueprint('attacks', __name__)

@attacks_bp.route('/arp/start', methods=['POST'])
def start_arp_attack():
    # Handle ARP attack
    pass

@attacks_bp.route('/syn/start', methods=['POST'])
def start_syn_attack():
    # Handle SYN attack
    pass
```

Then in `app.py`:
```python
from routes.attacks import attacks_bp
app.register_blueprint(attacks_bp, url_prefix='/api/attack')
```

**Result:**
- `/api/attack/arp/start` → Calls `start_arp_attack()`
- `/api/attack/syn/start` → Calls `start_syn_attack()`

**Benefits:**
- ✅ Organized code (attacks separate from scanning)
- ✅ Reusable (can use blueprint in multiple apps)
- ✅ Scalable (easy to add more blueprints)

### 6. **Request & Response**

```python
from flask import request, jsonify

@app.route('/api/data', methods=['POST'])
def handle_data():
    # Get JSON data from request
    data = request.get_json()
    target_ip = data.get('target_ip')
    
    # Do something...
    result = scan_network(target_ip)
    
    # Send JSON response
    return jsonify({'status': 'success', 'result': result}), 200
```

**Request:** What client sends to server
```
POST /api/data
Content-Type: application/json

{"target_ip": "192.168.1.1"}
```

**Response:** What server sends back
```
HTTP 200
Content-Type: application/json

{"status": "success", "result": [...]}
```

### 7. **Decorators (Middleware)**

Decorators are functions that wrap other functions. Flask uses them to add functionality.

```python
from functools import wraps

def require_attacker(f):
    """Only ATTACKER users can access this"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'ATTACKER':
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)
    return decorated_function

@api_bp.route('/attack/arp/start', methods=['POST'])
@require_attacker  # Apply this decorator
def start_arp_attack():
    # Only runs if user is ATTACKER
    pass
```

**How it works:**
1. When endpoint is called, decorator runs first
2. If user is not ATTACKER → Return error (403)
3. If user is ATTACKER → Run the actual function

---

## How YOUR Project Uses Flask

### 1. **User Authentication (Login System)**

**File:** `app.py` (Lines 48-80)

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check against users.json
        if verify_password(username, password):
            session['user_id'] = username
            session['user_role'] = user_record['role']
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')
```

**What happens:**
1. User goes to `/login`
2. Flask shows `login.html` template
3. User fills in username/password
4. Flask receives POST request
5. Flask checks `models.py` for user record
6. If valid → Sets session → Redirects to dashboard
7. If invalid → Shows error message

### 2. **Role-Based Dashboards**

**File:** `app.py` (Lines 95-125)

```python
@app.route('/attacker')
def attacker_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'ATTACKER':
        return redirect(url_for('login'))
    
    return render_template(
        'attacker.html',
        username=session.get('user_id'),
        local_ip=get_local_ip(),
        gateway_ip=get_gateway_ip()
    )
```

**What happens:**
1. User clicks "Attacker" button
2. Flask checks: "Is user logged in?" and "Is their role ATTACKER?"
3. If NOT → Go back to login
4. If YES → Show `attacker.html` with network info

### 3. **Attack Endpoints (REST API)**

**File:** `routes/attacks.py`

```python
@attacks_bp.route('/arp/start', methods=['POST'])
@require_attacker
def start_arp_attack():
    data = request.get_json()
    
    # Extract attack parameters
    target_ip = data.get('target_ip')
    gateway_ip = data.get('gateway_ip')
    
    # Create attack object
    spoofer = ARPSpoofer(target_ip, gateway_ip)
    attack_id = str(uuid.uuid4())
    
    # Start attack in background thread
    thread = threading.Thread(target=spoofer.start_attack, daemon=True)
    thread.start()
    
    # Save attack info
    active_attacks[attack_id] = {
        'object': spoofer,
        'target_ip': target_ip,
        'status': 'running'
    }
    
    # Send response to client
    return jsonify({
        'attack_id': attack_id,
        'message': f'ARP attack started against {target_ip}'
    }), 200
```

**What happens:**
1. Frontend sends JSON: `{"target_ip": "192.168.1.100", "gateway_ip": "192.168.1.1"}`
2. Flask receives POST request to `/api/attack/arp/start`
3. Flask checks user is ATTACKER (@require_attacker)
4. Flask extracts IP addresses from JSON
5. Flask creates ARPSpoofer object
6. Flask starts attack in **background thread** (non-blocking)
7. Flask saves attack info in memory (`active_attacks`)
8. Flask sends JSON response with attack_id
9. Frontend receives response and updates UI

### 4. **Scanner API**

**File:** `routes/api.py` (Lines 50-70)

```python
@api_bp.route('/scan/start', methods=['POST'])
@require_attacker
def start_scan():
    data = request.get_json()
    network_range = data.get('network_range')
    
    scanner = NetworkScanner()
    scan_id = str(uuid.uuid4())
    
    # Run scan in background
    def run_scan():
        hosts = scanner.identify_active_machines(network_range)
        active_scanners[scan_id]['hosts'] = [h.to_dict() for h in hosts]
        active_scanners[scan_id]['status'] = 'completed'
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    # Store scan
    active_scanners[scan_id] = {
        'object': scanner,
        'hosts': [],
        'status': 'in_progress'
    }
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started'
    }), 200
```

**Key Pattern:**
- Take request → Start long operation in background → Return immediately
- Frontend polls `/api/scan/results/{scan_id}` to check progress
- When status = 'completed', show results

### 5. **Sniffer API**

**File:** `routes/api.py` (Lines 105-150)

```python
@api_bp.route('/sniff/start', methods=['POST'])
def start_sniffer():
    data = request.get_json()
    filter_str = data.get('filter')
    
    sniffer = TrafficSniffer()
    sniffer_id = str(uuid.uuid4())
    
    # Start sniffing in background
    def run_sniff():
        sniffer.start_sniffing(filter_str=filter_str)
    
    thread = threading.Thread(target=run_sniff, daemon=True)
    thread.start()
    
    # Store sniffer
    active_sniffers[sniffer_id] = {
        'object': sniffer,
        'status': 'capturing'
    }
    
    return jsonify({'sniffer_id': sniffer_id}), 200

@api_bp.route('/sniff/packets/<sniffer_id>', methods=['GET'])
def get_packets(sniffer_id):
    sniffer = active_sniffers[sniffer_id]['object']
    packets = sniffer.get_packets(limit=50)
    
    return jsonify({
        'packets': packets,
        'status': 'capturing'
    }), 200
```

**Pattern:**
1. Start sniffing → Save in memory → Return sniffer_id
2. Frontend calls `/sniff/packets/{id}` repeatedly
3. Flask returns captured packets in JSON format
4. Frontend updates UI with new packets

---

## The Complete Request-Response Flow

### Example: Starting an ARP Attack

**STEP 1: Frontend (JavaScript)**
```javascript
// attacker.html
async function startARPAttack() {
    const response = await fetch('/api/attack/arp/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target_ip: '192.168.1.100',
            gateway_ip: '192.168.1.1'
        })
    });
    const data = await response.json();
    console.log('Attack started:', data.attack_id);
}
```

**STEP 2: Flask Receives Request**
```python
# routes/attacks.py
@attacks_bp.route('/arp/start', methods=['POST'])
@require_attacker
def start_arp_attack():
    # Flask receives:
    # URL: /api/attack/arp/start
    # Method: POST
    # Body: {"target_ip": "192.168.1.100", "gateway_ip": "192.168.1.1"}
    # Session: {'user_id': 'attacker', 'user_role': 'ATTACKER'}
```

**STEP 3: Flask Processes**
```python
    data = request.get_json()  # Parse JSON body
    target_ip = data.get('target_ip')  # "192.168.1.100"
    gateway_ip = data.get('gateway_ip')  # "192.168.1.1"
    
    spoofer = ARPSpoofer(target_ip, gateway_ip)  # Create attack object
    attack_id = str(uuid.uuid4())  # Generate unique ID
    
    # Start in background so Flask doesn't block
    thread = threading.Thread(target=spoofer.start_attack, daemon=True)
    thread.start()
    
    # Remember this attack
    active_attacks[attack_id] = {'object': spoofer, ...}
```

**STEP 4: Flask Sends Response**
```python
    return jsonify({
        'attack_id': attack_id,
        'message': 'ARP attack started'
    }), 200
    
    # Sends back:
    # Status: 200 OK
    # Body: {"attack_id": "abc123...", "message": "ARP attack started"}
```

**STEP 5: Frontend Gets Response**
```javascript
    const data = await response.json();
    console.log('Attack ID:', data.attack_id);  // "abc123..."
    
    // Now periodically check attack status
    setInterval(async () => {
        const stats = await fetch('/api/attack/stats');
        const attacks = await stats.json();
        // Update UI with current attacks
    }, 2000);
```

---

## Summary: What Flask Does in YOUR Project

| Component | Flask Role |
|-----------|-----------|
| **Login** | Validates credentials, creates sessions |
| **Dashboards** | Checks role, renders appropriate HTML |
| **Attack Endpoints** | Receives attack parameters, starts threads, returns IDs |
| **Scanner API** | Starts background scan, returns progress when polled |
| **Sniffer API** | Captures packets, returns them when requested |
| **Security** | Protects routes with @require_attacker decorator |

**The Key Pattern:**
1. Frontend sends JSON request
2. Flask receives and validates
3. Flask starts long operation in **background thread**
4. Flask returns immediately with ID
5. Frontend polls Flask for updates
6. Flask sends back live data

This is how your Flask app handles network attacks without freezing!

---

## Important Files to Know

| File | Purpose |
|------|---------|
| `app.py` | Login, session, dashboard routes |
| `models.py` | User data, password hashing |
| `routes/attacks.py` | ARP/SYN attack endpoints |
| `routes/api.py` | Scanner/Sniffer endpoints |
| `modules/*.py` | Actual attack/scan tools |
| `templates/*.html` | What users see |

## Next Steps to Learn

1. **Try modifying routes:** Change `/attacker` to `/attacker-panel`
2. **Add a new template:** Create `templates/about.html` and add a route
3. **Add a decorator:** Create a custom decorator to check user role
4. **Read the docs:** https://flask.palletsprojects.com/
