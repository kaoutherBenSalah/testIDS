# IDS Platform - Complete System Explanation

## 🎯 What This System Does

This is a **cybersecurity training platform** where you can:
- **Launch network attacks** from a Kali VM (attacker)
- **Monitor and detect attacks** from an Ubuntu VM (defender)
- **Practice on a victim** RedHat VM that gets attacked

Think of it like a **safe sandbox** for learning how attacks work and how to defend against them.

---

## 🏗️ The Big Picture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   ATTACKER      │         │     VICTIM      │         │   DEFENDER      │
│   (Kali VM)     │────────>│   (RedHat VM)   │<────────│  (Ubuntu VM)    │
│ 192.168.189.10  │ attacks │ 192.168.189.20  │ monitors│ 192.168.189.30  │
│                 │         │                 │         │                 │
│ Django :8000    │         │ httpd, vsftpd   │         │ Django :8001    │
│ Attacker UI     │         │ (services)      │         │ Defender UI     │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                           │                           │
        └───────────────────────────┴───────────────────────────┘
                        VMware VMnet8 NAT
                     (192.168.189.0/24 network)
```

**3 machines, 2 roles, 1 network:**
- **Attacker** (you): Launch ARP spoofing, SYN floods, scan networks, sniff traffic
- **Victim** (target): Gets attacked, runs normal services (web server, FTP)
- **Defender** (monitor): Detects attacks, sees alerts, analyzes patterns (to be built)

---

## 📦 Components Breakdown

### 1. **Database Models** (What gets stored)

| Model | Purpose | Example |
|-------|---------|---------|
| **User** | Who's using the system | `attacker`, `defender`, `admin` with roles |
| **AttackLog** | Record of attacks launched | "ARP spoof on 192.168.189.20 at 21:45, sent 1500 packets" |
| **DetectionLog** | Record of attacks detected | "SYN flood detected from 192.168.189.10, HIGH severity" |
| **Configuration** | System settings | `{"arp_threshold": 100, "alert_email": "admin@ids.local"}` |

### 2. **Django Views** (The brains - what happens when you click buttons)

| View | URL | What it does |
|------|-----|--------------|
| `attacker_dashboard` | `/attacker/` | Shows the attacker UI with all tabs |
| `arp_attack_start` | `/api/attack/arp/start/` | Starts ARP spoofing attack |
| `arp_attack_stop` | `/api/attack/arp/stop/` | Stops ARP attack, restores victim's ARP table |
| `syn_attack_start` | `/api/attack/syn/start/` | Starts SYN flood attack |
| `start_scan` | `/api/scan/start/` | Scans network for live hosts |
| `start_sniffer` | `/api/sniff/start/` | Captures live network traffic |
| `get_network_info` | `/api/network/info/` | Returns system info (IP, gateway, etc.) |

### 3. **Attack Modules** (The weapons - what actually sends the packets)

| Module | What it attacks | How |
|--------|-----------------|-----|
| **arp_spoof.py** | Victim's ARP table | Sends fake ARP replies to poison the cache |
| **syn_flood.py** | Victim's TCP services | Floods with SYN packets to exhaust connections |
| **network_scanner.py** | Network discovery | ARP sweep + optional port scan |
| **traffic_sniffer.py** | Packet capture | Uses Scapy to sniff live traffic |
| **detector.py** | Attack detection | Analyzes packets for suspicious patterns (to be completed) |

### 4. **Utilities** (Helper functions)

- **network_utils.py**: Get local IP, gateway, MAC addresses, validate IPs
- **logger.py**: Write to log files for debugging

---

## 🔄 How an Attack Works (Step-by-Step)

### Example: ARP Spoofing Attack

```
1. YOU (in browser):
   └─> Open http://192.168.189.10:8000/attacker/
   └─> Fill form: Victim=192.168.189.20, Gateway=192.168.189.2
   └─> Click "Start"

2. BROWSER (JavaScript):
   └─> Sends POST request to /api/attack/arp/start/
   └─> Includes CSRF token + form data (victim_ip, gateway_ip, interval)

3. DJANGO VIEW (views.py):
   └─> Receives POST request
   └─> Validates: Is user logged in? Is user an attacker? Are IPs valid?
   └─> Calls: ARPSpoofer.start(victim_ip, gateway_ip, interface, interval)
   └─> Creates: AttackLog entry in database (status='running')
   └─> Returns: JSON response {"success": true, "message": "Attack started"}

4. ATTACK MODULE (arp_spoof.py):
   └─> Creates new thread
   └─> In loop every 2 seconds:
       ├─> Craft fake ARP reply: "Hey victim, I'm the gateway (but with MY MAC)"
       ├─> Craft fake ARP reply: "Hey gateway, I'm the victim (but with MY MAC)"
       ├─> Send both packets using Scapy
       ├─> Increment packets_sent counter
       └─> Repeat until stop() is called

5. VICTIM (RedHat VM):
   └─> Receives fake ARP replies
   └─> Updates its ARP table: gateway IP now maps to attacker's MAC
   └─> All traffic to gateway now goes through attacker (man-in-the-middle!)

6. YOU (verify):
   └─> On victim VM: run `arp -a`
   └─> See: 192.168.189.2 (gateway) → shows attacker's MAC address (NOT router's MAC)
   └─> On attacker UI: "Attack Statistics" shows packets climbing
   └─> On Sniffer tab: filter "arp" → see the fake ARP replies

7. STOP ATTACK:
   └─> Click "Stop & Restore"
   └─> Django calls ARPSpoofer.stop()
   └─> Module sends correct ARP replies to restore victim's table
   └─> AttackLog updated: end_time, status='stopped'
```

---

## 🧠 Key Concepts

### 1. **ARP Spoofing (Poisoning)**
- **Normal**: Victim asks "Who has 192.168.189.2?" → Gateway replies "I do, my MAC is AA:BB:CC:DD:EE:FF"
- **Attack**: Attacker replies first "I'm the gateway, my MAC is 11:22:33:44:55:66" (lies!)
- **Result**: Victim sends all internet traffic to attacker instead of real gateway
- **Impact**: Man-in-the-middle (MITM) → attacker can read/modify all traffic

### 2. **SYN Flood**
- **Normal**: Client sends SYN → Server replies SYN-ACK → Client sends ACK → Connection established
- **Attack**: Attacker sends millions of SYN packets but never sends final ACK
- **Result**: Server's connection queue fills up with half-open connections
- **Impact**: Denial of Service (DoS) → legitimate users can't connect

### 3. **Network Scanning**
- **ARP Sweep**: Send ARP "who-has" to every IP in range, see who replies
- **Port Scan**: Try connecting to common ports (22, 80, 443, 21) on each host
- **Result**: Map of all live devices and their open services

### 4. **Traffic Sniffing**
- **Promiscuous Mode**: Network card captures ALL packets (not just ones addressed to you)
- **BPF Filter**: Berkeley Packet Filter → "only show me packets matching X"
  - `tcp port 80` = only HTTP traffic
  - `arp` = only ARP packets
  - `host 192.168.189.20` = only packets to/from victim
- **Result**: Live view of network traffic (like Wireshark)

---

## 📂 File Structure & Roles

```
testIDS/
├── manage.py                     # Django entry point (run commands)
├── db.sqlite3                    # Database (stores users, logs)
├── requirements.txt              # Python dependencies (Django, Scapy, etc.)
│
├── web_interface/                # Django project
│   ├── settings.py               # Configuration (ALLOWED_HOSTS, DATABASE, etc.)
│   ├── urls.py                   # URL routing (/ → login, /attacker/ → dashboard)
│   ├── wsgi.py / asgi.py         # Web server gateways
│   │
│   └── cybersec_app/             # Main Django app
│       ├── models.py             # Database models (User, AttackLog, etc.)
│       ├── views.py              # View functions (handle requests, call modules)
│       ├── urls.py               # App-specific URLs
│       ├── admin.py              # Django admin panel config
│       │
│       ├── templates/            # HTML pages
│       │   ├── attacker.html     # Attacker dashboard (tabs, forms, stats)
│       │   ├── defender.html     # Defender dashboard (to be built)
│       │   ├── login.html        # Login page
│       │   └── base.html         # Base template
│       │
│       ├── static/               # CSS, JavaScript
│       │   ├── css/styles.css
│       │   └── js/main.js
│       │
│       └── management/commands/  # Custom Django commands
│           └── create_users.py   # python manage.py create_users
│
├── modules/                      # Attack/defense modules
│   ├── arp_spoof.py              # ARP spoofing logic
│   ├── syn_flood.py              # SYN flood logic
│   ├── network_scanner.py        # Network scanning logic
│   ├── traffic_sniffer.py        # Packet capture logic
│   └── detector.py               # IDS detection logic (to be built)
│
├── utils/                        # Helper utilities
│   ├── logger.py                 # Logging functions
│   └── network_utils.py          # Network helper functions
│
└── docs/                         # Documentation
    ├── SETUP_COMMANDS.md         # Step-by-step VM setup
    ├── SYSTEM_EXPLAINED.md       # This file!
    └── simple_class_diagram.puml # Class diagram
```

---

## 🚀 Usage Flow

### First-Time Setup
1. **Deploy VMs**: 3 VMs on VMnet8 NAT (Kali, RedHat, Ubuntu)
2. **Set Static IPs**: Attacker=.10, Victim=.20, Defender=.30
3. **Clone project** on Kali and Ubuntu
4. **Install dependencies**: `pip install -r requirements.txt`
5. **Run migrations**: `python manage.py migrate`
6. **Create users**: `python create_users_standalone.py`

### Daily Use (Attacker)
1. **Start server**: `python manage.py runserver 192.168.189.10:8000`
2. **Login**: Browser → `http://192.168.189.10:8000/login` (attacker/attack123)
3. **Launch attack**: Attacks tab → fill form → Start
4. **Verify**: Check victim VM's ARP table or connection state
5. **Monitor**: Sniffer tab → see live packets
6. **Stop**: Click "Stop" button
7. **Review**: Attack Statistics shows packets sent

### Daily Use (Defender - to be built)
1. **Start server**: `python manage.py runserver 192.168.189.30:8001`
2. **Login**: Browser → `http://192.168.189.30:8001/login` (defender/defend123)
3. **Monitor dashboard**: See alerts, logs, statistics
4. **Analyze**: Review DetectionLog entries
5. **Block**: Optionally block attacker IP (future feature)

---

## 🔐 Security Notes

**This is for EDUCATIONAL USE ONLY on your own isolated network.**

- ✅ **Safe**: Use in your own VMware NAT network (isolated from real internet)
- ✅ **Legal**: Practice on VMs you own
- ❌ **Illegal**: Attack real networks, devices you don't own, or production systems
- ❌ **Dangerous**: Running this on a real network can disrupt services and violate laws

**Why it's isolated:**
- VMnet8 NAT = private virtual network (like 192.168.189.0/24)
- Only VMs on that network can see each other
- Your host Windows/Mac can access VMs, but VMs can't attack your host
- Real internet devices are safe

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `create_users` command not found | Use `python create_users_standalone.py` instead |
| `ALLOWED_HOSTS` error | Add your IP to `ALLOWED_HOSTS` in settings.py or use `*` |
| `no such table: users` | Run `python manage.py migrate` first |
| Scapy import error | Install: `pip install scapy` |
| Attack not working | Check: Are VMs on same network? Can they ping each other? |
| ARP not poisoning | Run attacker as root: `sudo python manage.py runserver` |
| SYN flood no effect | Check victim's firewall, ensure port is open |

---

## 🎓 Learning Path

**Beginner:**
1. Understand the 3-VM setup (attacker, victim, defender)
2. Launch an ARP spoof attack
3. Verify on victim: `arp -a` shows attacker's MAC
4. Use Sniffer tab to see ARP packets

**Intermediate:**
1. Launch SYN flood, monitor victim's `ss -tn | grep SYN-RECV`
2. Scan the network, see all devices
3. Capture HTTP traffic with BPF filter `tcp port 80`
4. Read `arp_spoof.py` to understand the code

**Advanced:**
1. Build the Defender UI (dashboard, alerts, logs)
2. Implement real IDS detection in `detector.py`
3. Add more attack types (DNS spoofing, port scanning)
4. Create alerts and auto-blocking features
5. Log to database and create analysis reports

---

## 📚 Next Steps

1. **Complete Defender UI**: Build dashboard to show DetectionLog entries
2. **Real IDS Detection**: Implement algorithms in `detector.py` to detect attacks
3. **Alerting**: Email/SMS notifications when attack detected
4. **Auto-blocking**: Automatically block attacker IPs using iptables
5. **Reporting**: Generate PDF reports of attacks and defenses
6. **More attacks**: DNS spoofing, ICMP flood, port scanning
7. **Machine Learning**: Use ML to detect anomalies

---

## 🔗 Related Files

- [SETUP_COMMANDS.md](../SETUP_COMMANDS.md) - VM deployment guide
- [simple_class_diagram.puml](simple_class_diagram.puml) - Architecture diagram
- [views.py](../web_interface/cybersec_app/views.py) - API endpoints
- [arp_spoof.py](../modules/arp_spoof.py) - ARP attack implementation
- [attacker.html](../web_interface/cybersec_app/templates/attacker.html) - Attacker UI

---

**Questions?** Review the code, read comments, experiment safely, and learn! 🚀
