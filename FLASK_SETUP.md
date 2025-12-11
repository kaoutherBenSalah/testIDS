# testIDS - Flask Version Setup Guide

## 🚀 Quick Start

### 1. Create Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements-flask.txt
```

### 3. Run Flask App

```bash
python app.py
```

**Output:**
```
============================================================
🔐 testIDS - Flask Version
============================================================
📍 Local IP: 192.168.189.10
🔌 Gateway: 192.168.189.2

👤 Default Users:
   - attacker / attack123 (ATTACKER)
   - defender / defend123 (DEFENDER)
   - admin / admin123 (ADMIN)

🚀 Running on: http://localhost:5000
============================================================
```

### 4. Access Web Interface

- **URL**: `http://localhost:5000/login`
- **Username**: `attacker`
- **Password**: `attack123`

---

## 🎯 How It Works

### Architecture

```
app.py (Flask main app)
├── routes/attacks.py (ARP, SYN endpoints)
├── routes/api.py (Scanner, Sniffer, System Info)
├── models.py (User, active attacks storage)
├── templates/ (HTML templates)
└── modules/ (Attack modules - pure Python)
```

### Key Features

✅ **No Database Migration** - Uses JSON files + in-memory storage
✅ **Simple Authentication** - Flask sessions (no ORM)
✅ **Attack Execution** - Threading with global state dict
✅ **Real-time Monitoring** - AJAX polling every 2 seconds
✅ **Shield CPU** - Live CPU/RAM monitoring

---

## 🔧 Development

### Project Structure

```
testIDS/
├── app.py                    # Flask app entry point
├── models.py                 # User & state management
├── requirements-flask.txt    # Flask dependencies
├── routes/                   # API endpoints (blueprints)
│   ├── __init__.py
│   ├── attacks.py           # ARP, SYN attack endpoints
│   └── api.py               # Scanner, Sniffer, Info endpoints
├── templates/               # HTML templates
│   ├── base.html           # Base template
│   ├── login.html          # Login page
│   ├── attacker.html       # Attacker dashboard
│   └── defender.html       # Defender dashboard
├── modules/                 # Pure Python attack modules
│   ├── arp_spoof.py
│   ├── syn_flood.py
│   ├── network_scanner.py
│   ├── traffic_sniffer.py
│   └── detector.py
├── utils/                   # Utility functions
│   ├── network_utils.py
│   └── logger.py
├── logs/                    # Log files
└── data/                    # JSON data (auto-created)
    └── users.json          # User credentials
```

### Default Users

**All users created automatically on first run:**

| Username | Password | Role |
|----------|----------|------|
| attacker | attack123 | ATTACKER (launch attacks) |
| defender | defend123 | DEFENDER (monitor attacks) |
| admin | admin123 | ADMIN (full access) |

**To reset users**: Delete `data/users.json` and restart app.

---

## 🔐 Authentication

### How It Works

1. User submits username/password to `/login`
2. Flask validates against `data/users.json`
3. Session created with `user_id` and `user_role`
4. All routes check `session['user_role']` via `@require_attacker` decorator

### Adding New Users

Edit `models.py`, in `create_default_users()`:

```python
defaults = {
    'username': {'password': generate_password_hash('password'), 'role': 'ATTACKER'},
    # Add new users here
}
```

Then restart app.

---

## 🎭 Attack Modules

### Available Attacks

#### 1. **ARP Spoofing** (Man-in-the-Middle)
- **File**: `modules/arp_spoof.py`
- **Endpoint**: `POST /api/attack/arp/start`
- **Parameters**:
  - `target_ip`: Victim IP (e.g., 192.168.189.20)
  - `gateway_ip`: Gateway IP (e.g., 192.168.189.2)
  - `interface`: Network interface (eth0)
  - `interval`: Seconds between packets (default 2)

**Direct Python Usage:**
```python
from modules.arp_spoof import ARPSpoofer

spoofer = ARPSpoofer('192.168.189.20', '192.168.189.2', 'eth0')
spoofer.start(interval=2)
# ... attack running ...
spoofer.stop()  # Restores ARP tables
```

#### 2. **SYN Flooding** (DoS Attack)
- **File**: `modules/syn_flood.py`
- **Endpoint**: `POST /api/attack/syn/start`
- **Parameters**:
  - `target_ip`: Target IP
  - `target_port`: Port to flood (default 80)
  - `threads`: Number of threads (default 10)

**Direct Python Usage:**
```python
from modules.syn_flood import SYNFlooder

flooder = SYNFlooder('192.168.189.20', 80, num_threads=10)
flooder.start()
# ... attack running ...
flooder.stop()
```

#### 3. **Network Scanner**
- **File**: `modules/network_scanner.py`
- **Endpoint**: `POST /api/scan/start`
- **Parameters**:
  - `network_range`: CIDR notation (e.g., 192.168.189.0/24)
  - `full_scan`: Include port scanning (slower)

#### 4. **Traffic Sniffer**
- **File**: `modules/traffic_sniffer.py`
- **Endpoint**: `POST /api/sniff/start`
- **Parameters**:
  - `filter`: BPF filter (e.g., "tcp port 80")

---

## 📊 API Endpoints

### Attack Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/attack/arp/start` | Start ARP spoofing |
| POST | `/api/attack/arp/stop` | Stop ARP attack |
| POST | `/api/attack/syn/start` | Start SYN flooding |
| POST | `/api/attack/syn/stop` | Stop SYN attack |
| GET | `/api/attack/stats` | Get active attack stats |

### Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/start` | Start network scan |
| GET | `/api/scan/results/<id>` | Get scan results |
| POST | `/api/sniff/start` | Start traffic sniffer |
| GET | `/api/sniff/packets/<id>` | Get captured packets |
| POST | `/api/sniff/stop` | Stop sniffer |
| GET | `/api/network/info` | Get CPU/RAM/network info |

---

## 🧪 Testing Attacks

### Local Testing (Windows/Linux)

**Test ARP Spoofing:**
```python
from modules.arp_spoof import ARPSpoofer
import time

spoofer = ARPSpoofer('192.168.189.20', '192.168.189.2')
spoofer.start(interval=2)
time.sleep(10)
spoofer.stop()
```

**Test SYN Flooding:**
```python
from modules.syn_flood import SYNFlooder
import time

flooder = SYNFlooder('192.168.189.20', 80, num_threads=5)
flooder.start()
time.sleep(5)
flooder.stop()
```

### Verification Commands (Kali VM)

**Check ARP table:**
```bash
arp -a | grep 192.168.189
```

**Monitor SYN_RECV states:**
```bash
ss -tn | grep SYN-RECV | wc -l
```

**Network info:**
```bash
ip addr show eth0
ip route show
```

---

## 🚀 Deploying to Kali VM

### 1. Copy Files to Kali

```bash
# On Kali VM
git clone <your-repo> testids-flask
cd testids-flask
```

### 2. Setup & Run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-flask.txt

# IMPORTANT: Run as root for packet access!
sudo python app.py
```

### 3. Access from Windows Host

- **URL**: `http://192.168.189.10:5000/login`
- **Username**: `attacker`
- **Password**: `attack123`

---

## ⚠️ Important Notes

### Root Privileges Required

Attacks require raw socket access:

```bash
# Kali Linux
sudo python app.py

# macOS
sudo python3 app.py

# Linux non-Kali
sudo python3 app.py
```

### Firewall & Network Setup

- Ensure VMs are on same network (192.168.189.0/24)
- Check attacker can reach victim:
  ```bash
  ping 192.168.189.20
  ```

### Data Storage

- **Users**: `data/users.json` (auto-created)
- **Logs**: `logs/` directory
- **No migration needed** - Flask + JSON!

---

## 🐛 Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "No module named 'flask'" | Flask not installed | `pip install Flask` |
| "Attack started but no packets" | Not running as root | `sudo python app.py` |
| "Port 5000 already in use" | Another app using port | Change `port=8000` in app.py |
| "Cannot find module 'modules'" | sys.path issue | Check sys.path.insert() in app.py |
| Connection refused on Kali | Firewall blocking | `sudo ufw allow 5000` |

---

## 📚 Further Learning

**Read these files in order:**

1. [README.md](../README.md) - Project overview
2. [COMPLETE_CODE_EXPLANATION.md](../docs/COMPLETE_CODE_EXPLANATION.md) - Detailed code breakdown
3. `app.py` - Flask app structure
4. `models.py` - User & state management
5. `routes/attacks.py` - Attack endpoints
6. `modules/arp_spoof.py` - Attack implementation

---

**Version**: 2.0 (Flask)  
**Python**: 3.8+  
**License**: Educational Use Only
