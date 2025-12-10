# IDS Cybersecurity Platform - Complete System Guide
## ⚔️ Attacker-Side Implementation

**Author**: Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane  
**Course**: 4-ING-J-SSIR4 - Mini Projet Sécurité & Sûreté Informatique  
**School**: Engineering School, 2025/2026

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Quick Start](#quick-start)
4. [Installation & Setup](#installation--setup)
5. [User Roles & Permissions](#user-roles--permissions)
6. [Web Interface Guide](#web-interface-guide)
7. [API Endpoints Reference](#api-endpoints-reference)
8. [Attack Modules](#attack-modules)
9. [Network Scanner](#network-scanner)
10. [Traffic Sniffer](#traffic-sniffer)
11. [Database Models](#database-models)
12. [Troubleshooting](#troubleshooting)
13. [Testing the System](#testing-the-system)

---

## Project Overview

### What is This?

This is a **complete cybersecurity simulation platform** built with Django designed for:
- **Educational learning** about network attacks and defense
- **Authorized penetration testing** in controlled environments
- **IDS (Intrusion Detection System) evaluation** on network security

### Key Features

✅ **Network Attack Simulation**
- ARP Spoofing (Man-in-the-Middle attacks)
- SYN Flooding (Denial of Service)
- Live traffic sniffing
- Network reconnaissance

✅ **Web-Based Interface**
- Real-time attack control dashboard
- Live statistics and monitoring
- Network scanner with host discovery
- Packet capture and analysis (Wireshark-like)

✅ **Role-Based Access Control**
- Attacker (offensive security)
- Defender (defensive security / IDS operator)
- Admin (system administrator)

✅ **Complete Database Logging**
- Attack history tracking
- Detection alerts
- System configuration storage

---

## System Architecture

### Network Layout

```
┌─────────────────────────────────────────────────────┐
│          VMware NAT Network (192.168.189.0/24)      │
├─────────────────────────────────────────────────────┤
│                                                       │
│  [Kali Linux - Attacker]          [Ubuntu - IDS]    │
│  192.168.189.10                    192.168.189.30   │
│  Django Port 8000                  Django Port 8001  │
│                                                       │
│  ⚔️ Attack Tools          vs         🛡️ Detection   │
│  - ARP Spoofing                      - Alert System  │
│  - SYN Flooding                      - Log Analysis  │
│  - Network Scanner                   - Stats        │
│  - Traffic Sniffer                                   │
│                                                       │
│         [Ubuntu - Victim/Target]                    │
│         192.168.189.20                              │
│         (No Django - Just Services)                 │
│                                                       │
└─────────────────────────────────────────────────────┘
```

### Application Stack

```
Frontend Layer:
├─ HTML5 Templates (attacker.html, defender.html, login.html)
├─ CSS3 Styling (modern gradient, responsive design)
└─ JavaScript (real-time AJAX updates, WebSocket-ready)

Backend Layer:
├─ Django 4.2+ (Web Framework)
├─ Django REST Framework (API endpoints)
├─ Django Channels (WebSocket support)
├─ Django ORM (Database models)
└─ Custom User Model (Role-based authentication)

Attack Module Layer:
├─ modules/arp_spoof.py (ARPSpoofer class)
├─ modules/syn_flood.py (SYNFlooder class)
├─ modules/network_scanner.py (NetworkScanner class)
├─ modules/traffic_sniffer.py (TrafficSniffer class)
└─ modules/detector.py (NetworkDetector class)

Utility Layer:
├─ utils/network_utils.py (IP/MAC address helpers)
└─ utils/logger.py (Logging system)

Database Layer:
└─ SQLite (db.sqlite3)
   ├─ User (custom, with roles)
   ├─ AttackLog (attack history)
   ├─ DetectionLog (alert history)
   └─ Configuration (system settings)
```

### Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Web Framework | Django | 4.2+ |
| API Framework | Django REST Framework | 3.14+ |
| Real-time Communication | Django Channels | 4.0+ |
| Network Tools | Scapy | 2.5.0+ |
| Database | SQLite | (included) |
| Python | Python | 3.10+ |
| Server | Daphne ASGI | 4.2.1 |

---

## Quick Start

### For the Impatient

```bash
# 1. Navigate to project
cd /path/to/testIDS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Setup database
python manage.py migrate
python manage.py create_users

# 4. Start server
python manage.py runserver 0.0.0.0:8000

# 5. Login and start attacking
# Go to http://localhost:8000/login/
# Username: attacker
# Password: attack123
```

### Default Credentials

| Role | Username | Password | Access |
|------|----------|----------|--------|
| 🔴 Attacker | `attacker` | `attack123` | http://localhost:8000/attacker/ |
| 🟢 Defender | `defender` | `defend123` | http://localhost:8000/defender/ (coming soon) |
| ⚙️ Admin | `admin` | `admin123` | http://localhost:8000/admin/ |

---

## Installation & Setup

### Prerequisites

- Python 3.10+ installed
- pip package manager
- Linux, Windows, or macOS
- Administrator/root access (for network operations)

### Step 1: Install Python Dependencies

```bash
cd testIDS

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### Required Packages

```
Django==4.2.0
djangorestframework==3.14.0
channels==4.0.0
scapy==2.5.0
psutil==5.9.8
colorama==0.4.6
daphne==4.2.1
```

### Step 2: Database Setup

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create default users (IMPORTANT!)
python manage.py create_users
```

### Step 3: Run the Application

```bash
# Development server
python manage.py runserver 0.0.0.0:8000

# For production (requires additional setup)
# Use Gunicorn + Daphne + Supervisor
```

### Step 4: Access the Application

1. **Login Page**: http://localhost:8000/login/
2. **Attacker Dashboard**: http://localhost:8000/attacker/
3. **Django Admin**: http://localhost:8000/admin/

---

## User Roles & Permissions

### Role Hierarchy

```
┌─────────────────────────────────────────────┐
│                   ADMIN                      │
│          (All permissions)                   │
├─────────────────────────────────────────────┤
│       ATTACKER    │       DEFENDER          │
│  (Launch attacks) │ (Monitor detection)     │
└─────────────────────────────────────────────┘
```

### Role Details

#### 🔴 ATTACKER Role
- **Purpose**: Perform simulated attacks on the network
- **Permissions**:
  - Start/Stop ARP spoofing attacks
  - Start/Stop SYN flooding attacks
  - Perform network reconnaissance (scanning)
  - Sniff network traffic
  - View attack statistics and logs
  - View network information
  - Cannot view detection logs or defender dashboard

#### 🟢 DEFENDER Role
- **Purpose**: Monitor and detect attacks using IDS
- **Permissions**:
  - View detection alerts in real-time
  - View attack logs
  - Analyze detected anomalies
  - Access IDS statistics dashboard
  - Configure detection sensitivity
  - Cannot launch attacks
  - Cannot view attacker dashboard

#### ⚙️ ADMIN Role
- **Purpose**: System administration
- **Permissions**:
  - All ATTACKER and DEFENDER permissions
  - Manage users and roles
  - Access Django admin panel
  - Modify system configuration
  - View all logs and statistics
  - Database access and management

---

## Web Interface Guide

### Login Page

**URL**: `http://localhost:8000/login/`

The login page displays:
- Default credentials for each role
- Form fields for username and password
- Error messages if login fails
- Responsive design for all devices

```html
<!-- Login Form -->
Username: attacker
Password: attack123
[Login Button]
```

### Attacker Dashboard

**URL**: `http://localhost:8000/attacker/`

Access only after successful login as ATTACKER role.

#### Tab 1: 🎯 Active Attacks

This tab contains two main attack modules:

**A. ARP Spoofing Attack**

```
Input Fields:
  ├─ Victim IP: 192.168.189.20
  ├─ Gateway IP: 192.168.189.2
  ├─ Interface: eth0 (auto-detected if blank)
  └─ Interval: 2 (seconds between packets)

Controls:
  ├─ [Start ARP Attack] - Begins poisoning ARP tables
  └─ [Stop & Restore] - Restores ARP tables to normal

Output:
  └─ Status box showing attack status
```

**What it Does**:
1. Sends spoofed ARP replies to victim
2. Associates attacker's MAC with gateway's IP
3. Routes all traffic through attacker (MITM)
4. Maintains poisoning with periodic packets
5. Restores ARP tables when stopped

**Requirements**:
- Root/Administrator access
- Network interface with ARP capability
- Same network as victim and gateway

---

**B. SYN Flooding Attack**

```
Input Fields:
  ├─ Target IP: 192.168.189.20
  ├─ Target Port: 80
  ├─ Threads: 10
  └─ Duration: (optional, 0=infinite)

Controls:
  ├─ [Start SYN Flood] - Begins flooding attack
  └─ [Stop Attack] - Terminates all threads

Output:
  └─ Status box with attack metrics
```

**What it Does**:
1. Creates multiple threads
2. Generates random source IPs
3. Sends continuous TCP SYN packets
4. Each thread sends flood without waiting for response
5. Exhausts server resources (DOS attack)

**Parameters**:
- **Target IP**: Server to attack
- **Port**: Service port (80=HTTP, 443=HTTPS, etc.)
- **Threads**: Number of parallel attack threads
- **Duration**: Seconds to run (0=infinite until manual stop)

---

**C. Live Attack Statistics**

```
Table showing:
┌─────────────────────────────────────────┐
│ Attack Type │ Target │ Packets Sent │ Status
├─────────────────────────────────────────┤
│ ARP Spoofing│ 192... │ 150 packets │ Running
│ SYN Flood   │ 192... │ 45000 pkts  │ Running
└─────────────────────────────────────────┘

Updated every 2 seconds automatically
```

---

#### Tab 2: 🔍 Network Scanner

**Purpose**: Discover active hosts and services on the network

```
Input Fields:
  ├─ Network Range (CIDR): 192.168.189.0/24
  └─ ☐ Full Scan (includes port scanning - slower)

Controls:
  ├─ [Start Scan] - Begins network reconnaissance
  └─ [Stop Scan] - Terminates scan

Results Table:
┌──────────────────────────────────────────────┐
│ IP Address      │ MAC Address │ Hostname │ Ports
├──────────────────────────────────────────────┤
│ 192.168.189.1   │ 08:00:27... │ gateway  │ 53, 67
│ 192.168.189.20  │ 08:00:27... │ ubuntu   │ 22, 80, 443
│ 192.168.189.30  │ 08:00:27... │ defender │ 22, 8001
└──────────────────────────────────────────────┘

Updated every 2 seconds as scan progresses
```

**Scan Types**:

1. **Quick Scan** (default)
   - ARP ping sweep to find active hosts
   - Fast, no port information
   - Good for host discovery

2. **Full Scan** (with checkbox)
   - ARP scan + TCP port scanning
   - Includes service detection
   - Much slower but comprehensive

**Discovered Information**:
- IP Address (target identification)
- MAC Address (physical address, helps MITM)
- Hostname (DNS reverse lookup)
- Open Ports (services running)
- OS Guess (simple OS detection)

---

#### Tab 3: 📦 Traffic Sniffer

**Purpose**: Capture and analyze network packets in real-time

```
Input Fields:
  ├─ BPF Filter: tcp port 80    (optional)
  └─ Max Packets: 0              (0=unlimited)

Controls:
  ├─ [Start Sniffing]
  └─ [Stop Sniffing]

Live Packet Display:
┌────────────────────────────────────────────────────────┐
│ Time     │ Proto │ Source → Destination │ Info
├────────────────────────────────────────────────────────┤
│ 21:27:45 │ TCP   │ 192...20:443→80     │ SYN
│ 21:27:46 │ ARP   │ 192...10→192...2    │ Who-has
│ 21:27:47 │ ICMP  │ 192...20→8.8.8.8    │ Echo Req
│ 21:27:48 │ DNS   │ 192...20→192...1    │ A google.com
└────────────────────────────────────────────────────────┘

Stats Panel:
  TCP: 245  │ UDP: 89  │ ICMP: 12 │ ARP: 34
  DNS: 15   │ HTTP: 8  │ HTTPS: 2
```

**BPF Filter Examples**:

```
tcp port 80          # HTTP traffic
tcp port 443         # HTTPS traffic
host 192.168.189.20  # Traffic to/from specific IP
tcp and dst port 22  # SSH traffic
src net 192.168      # Traffic from subnet
udp and port 53      # DNS queries
icmp                 # Ping packets
arp                  # ARP traffic
```

**Displayed Information**:
- **Time**: Packet timestamp
- **Protocol**: Layer 4 protocol (TCP, UDP, ICMP, ARP)
- **Source**: Source IP:port
- **Destination**: Destination IP:port
- **Info**: Protocol-specific details (SYN, HTTP method, DNS query, etc.)

---

#### Tab 4: ℹ️ System Information

**Quick Reference Dashboard**

```
Network Info:
  ├─ Local IP: 192.168.189.10
  ├─ Gateway: 192.168.189.2
  ├─ Active Attacks: 2
  ├─ Active Scans: 0
  └─ Sniffers Running: 1

User Info:
  ├─ Username: attacker
  ├─ Role: Attacker
  ├─ Email: attacker@ids.local
  └─ Name: Attack User

Quick Guide:
  ├─ ARP Spoofing: MITM via ARP poisoning
  ├─ SYN Flooding: DOS via TCP exhaustion
  ├─ Scanner: Network reconnaissance
  └─ Sniffer: Packet capture & analysis
```

---

## API Endpoints Reference

### Authentication

#### Login
```
POST /login/
Parameters:
  - username: string
  - password: string

Response (Success):
  200 OK
  Redirect to dashboard

Response (Failure):
  401 Unauthorized
  Error message displayed
```

#### Logout
```
GET /logout/

Response:
  302 Redirect to login
```

---

### ARP Spoofing

#### Start Attack
```
POST /api/attack/arp/start/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "target_ip": "192.168.189.20",
  "gateway_ip": "192.168.189.2",
  "interface": "eth0",
  "interval": 2
}

Response (Success - 200):
{
  "status": "started",
  "attack_id": "arp_192.168.189.20_192.168.189.2",
  "message": "ARP spoofing attack started against 192.168.189.20"
}

Response (Error - 400/500):
{
  "error": "Error message describing the problem"
}
```

#### Stop Attack
```
POST /api/attack/arp/stop/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "attack_id": "arp_192.168.189.20_192.168.189.2"
}

Response (Success - 200):
{
  "status": "stopped",
  "message": "ARP spoofing attack stopped, ARP tables restored"
}
```

---

### SYN Flooding

#### Start Attack
```
POST /api/attack/syn/start/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "target_ip": "192.168.189.20",
  "target_port": 80,
  "num_threads": 10,
  "duration": null
}

Response (Success - 200):
{
  "status": "started",
  "attack_id": "syn_192.168.189.20_80",
  "message": "SYN Flood attack started against 192.168.189.20:80"
}
```

#### Stop Attack
```
POST /api/attack/syn/stop/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "attack_id": "syn_192.168.189.20_80"
}

Response (Success - 200):
{
  "status": "stopped",
  "message": "SYN Flood attack stopped (12345 packets sent)"
}
```

#### Get Statistics
```
GET /api/attack/stats/

Response (200):
{
  "attacks": {
    "arp_192.168.189.20_192.168.189.2": {
      "type": "ARP Spoofing",
      "target_ip": "192.168.189.20",
      "gateway_ip": "192.168.189.2",
      "packets_sent": 350,
      "is_running": true
    },
    "syn_192.168.189.20_80": {
      "type": "SYN Flood",
      "target_ip": "192.168.189.20",
      "target_port": 80,
      "packets_sent": 45000,
      "is_running": true
    }
  }
}
```

---

### Network Scanner

#### Start Scan
```
POST /api/scan/start/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "network_range": "192.168.189.0/24",
  "full_scan": false
}

Response (Success - 200):
{
  "scan_id": "scan_1234567890",
  "status": "started",
  "message": "Network scan started"
}
```

#### Get Scan Results
```
GET /api/scan/results/<scan_id>/

Response (200):
{
  "scan_id": "scan_1234567890",
  "status": "in_progress",  # or "completed"
  "count": 3,
  "hosts": [
    {
      "ip": "192.168.189.1",
      "mac": "08:00:27:00:00:00",
      "hostname": "gateway",
      "open_ports": [53, 67],
      "os_guess": "Unknown"
    },
    {
      "ip": "192.168.189.20",
      "mac": "08:00:27:a0:b1:c2",
      "hostname": "ubuntu-victim",
      "open_ports": [22, 80, 443],
      "os_guess": "Linux"
    }
  ]
}
```

---

### Traffic Sniffer

#### Start Sniffer
```
POST /api/sniff/start/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "filter": "tcp port 80",  # optional, null for all traffic
  "count": 0                 # 0 = unlimited
}

Response (Success - 200):
{
  "sniffer_id": "sniffer_1234567890",
  "status": "started",
  "message": "Traffic sniffer started"
}
```

#### Get Captured Packets
```
GET /api/sniff/packets/<sniffer_id>/

Response (200):
{
  "sniffer_id": "sniffer_1234567890",
  "status": "capturing",
  "count": 15,
  "packets": [
    {
      "timestamp": "2025-12-10 21:27:45.123",
      "protocol": "TCP",
      "src": "192.168.189.20",
      "dst": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 443,
      "info": "SYN, seq=12345, win=65535"
    },
    {
      "timestamp": "2025-12-10 21:27:46.456",
      "protocol": "DNS",
      "src": "192.168.189.20",
      "dst": "192.168.189.1",
      "info": "A google.com"
    }
  ],
  "stats": {
    "total_packets": 245,
    "protocol_stats": {
      "TCP": 145,
      "UDP": 89,
      "ICMP": 10,
      "ARP": 1,
      "DNS": 50,
      "HTTP": 8,
      "HTTPS": 2
    }
  }
}
```

#### Stop Sniffer
```
POST /api/sniff/stop/
Headers:
  Content-Type: application/json
  X-CSRFToken: <csrf-token>

Body:
{
  "sniffer_id": "sniffer_1234567890"
}

Response (Success - 200):
{
  "status": "stopped",
  "message": "Traffic sniffer stopped"
}
```

---

### System Information

#### Get Network Info
```
GET /api/network/info/

Response (200):
{
  "local_ip": "192.168.189.10",
  "gateway_ip": "192.168.189.2",
  "active_attacks": 2,
  "active_scans": 0,
  "active_sniffers": 1
}
```

---

## Attack Modules

### Module 1: ARP Spoofing (modules/arp_spoof.py)

**Class**: `ARPSpoofer`

```python
# Initialize
from modules.arp_spoof import ARPSpoofer

spoofer = ARPSpoofer(
    victim_ip="192.168.189.20",
    gateway_ip="192.168.189.2",
    interface="eth0"
)

# Start attack
spoofer.start()

# Stop attack (and restore ARP tables)
spoofer.stop()
```

**Methods**:
- `start(interval=2)` - Begins poisoning ARP tables
- `stop()` - Restores ARP tables to original state
- `sniff_packets()` - Captures traffic between victim and gateway (legacy)

**How it Works**:
1. Gets attacker's MAC address
2. Sends ARP reply: "I am 192.168.189.2 (gateway), my MAC is <attacker>"
3. Sends ARP reply: "I am 192.168.189.20 (victim), my MAC is <attacker>"
4. Victim and gateway now route through attacker
5. Attacker can intercept, modify, or drop traffic
6. On stop: Sends ARP replies restoring correct MAC mappings

**Requirements**:
- Root/administrator access
- Same network segment as victim and gateway
- ARP must be used (not IPv6)

---

### Module 2: SYN Flooding (modules/syn_flood.py)

**Class**: `SYNFlooder`

```python
from modules.syn_flood import SYNFlooder

flooder = SYNFlooder(
    target_ip="192.168.189.20",
    target_port=80,
    num_threads=10
)

# Start attacking
flooder.start(duration=60)  # 60 seconds

# Stop and get stats
packets = flooder.stop()
print(f"Sent {packets} SYN packets")
```

**Methods**:
- `start(duration=None)` - Begin flooding
- `stop()` - Stop and return packet count
- `send_packets()` - Single thread method (called internally)

**How it Works**:
1. Creates N threads (each is a pseudo-client)
2. Each thread generates random source IP
3. Sends TCP SYN packets to target:port
4. Never completes handshake (doesn't send ACK)
5. Server allocates resource for each SYN
6. Server runs out of connections, denies real users

**Parameters**:
- `target_ip`: Victim IP address
- `target_port`: Service port (80=web, 443=HTTPS, 22=SSH)
- `num_threads`: Parallel attack threads (more = stronger)
- `duration`: Attack duration in seconds (None=infinite)

---

### Module 3: Network Scanner (modules/network_scanner.py)

**Classes**: `NetworkScanner`, `Host`

```python
from modules.network_scanner import NetworkScanner

scanner = NetworkScanner()

# Discover active hosts
hosts = scanner.identify_active_machines("192.168.189.0/24")

for host in hosts:
    print(f"{host.ip} ({host.mac}) - {host.hostname}")
    print(f"  Open ports: {host.open_ports}")
```

**Methods**:
- `scan_subnet(network_range)` - ARP scan for active hosts
- `scan_ports(ip_address)` - TCP port scan on single host
- `identify_active_machines(network_range, full_scan=False)` - Combined scan
- `ping_sweep(network_range)` - ICMP ping sweep

**Host Class**:
```python
class Host:
    ip: str                    # IP address
    mac: str                   # MAC address
    hostname: str              # DNS reverse lookup
    open_ports: List[int]      # Open port numbers
    os_guess: str              # Linux, Windows, Unknown
    
    def to_dict(self):        # Convert to JSON
        return {...}
```

---

### Module 4: Traffic Sniffer (modules/traffic_sniffer.py)

**Class**: `TrafficSniffer`

```python
from modules.traffic_sniffer import TrafficSniffer

sniffer = TrafficSniffer(
    filter="tcp port 80",  # BPF filter (optional)
    max_packets=100
)

# Start capturing
sniffer.start()

# ... capture happens in background ...

# Get captured packets
packets = sniffer.get_packets(limit=50)  # Last 50 packets
stats = sniffer.get_statistics()

# Stop capturing
sniffer.stop_sniffing()
```

**Methods**:
- `start()` - Begin packet capture in background thread
- `stop_sniffing()` - Stop capture
- `get_packets(limit=50)` - Get last N captured packets
- `get_statistics()` - Get protocol statistics
- `analyze_packet(packet)` - Analyze single packet details

**Packet Information**:
```python
{
    "timestamp": "2025-12-10 21:27:45.123",
    "protocol": "TCP",      # TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS
    "src": "192.168.189.20",
    "dst": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 443,
    "info": "SYN, seq=..., win=..."
}
```

---

## Network Scanner

### Quick Scan vs Full Scan

```
┌─────────────────────────────────────────┐
│       Network Scanner Comparison        │
├─────────────────┬───────────────────────┤
│ Quick Scan      │ Full Scan             │
├─────────────────┼───────────────────────┤
│ • ARP ping only │ • ARP ping            │
│ • ~2-5 seconds  │ • TCP port scan       │
│ • Host list     │ • Service detection   │
│ • No ports      │ • OS detection        │
│ • Fast          │ • 30-60+ seconds      │
│                 │ • Comprehensive       │
└─────────────────┴───────────────────────┘
```

### Scan Results Interpretation

```
IP Address: 192.168.189.20
├─ Active: Green indicator
├─ MAC Address: 08:00:27:a0:b1:c2
├─ Hostname: ubuntu-20.04-server
│   └─ Obtained via reverse DNS lookup
├─ Open Ports: 22, 80, 443, 3306
│   ├─ 22: SSH server
│   ├─ 80: HTTP web server
│   ├─ 443: HTTPS web server
│   └─ 3306: MySQL database
└─ OS Guess: Linux
    └─ Based on TTL values and port responses
```

### CIDR Notation Guide

```
192.168.189.0/24     # 192.168.189.0-255 (256 hosts)
192.168.0.0/16       # 192.168.0.0-65535 (65536 hosts)
10.0.0.0/8           # 10.0.0.0-10.255.255.255 (16M hosts)
192.168.189.0/25     # 192.168.189.0-127 (128 hosts)
192.168.189.128/25   # 192.168.189.128-255 (128 hosts)
```

---

## Traffic Sniffer

### BPF (Berkeley Packet Filter) Guide

**Syntax**:
```
protocol [direction] [host|net|port] [value]
```

**Examples**:
```
# Protocol filters
tcp                  # Only TCP packets
udp                  # Only UDP packets
icmp                 # Only ICMP (ping)
arp                  # Only ARP packets

# Host/Network filters
host 192.168.189.20  # Only traffic to/from this IP
src 192.168.189.20   # Only from this source
dst 192.168.189.20   # Only to this destination
net 192.168.189.0/24 # Only from/to this subnet

# Port filters
port 80              # HTTP traffic
tcp port 22          # SSH traffic
udp port 53          # DNS queries
dst port 443         # To HTTPS port

# Combinations (AND/OR)
tcp and port 80      # TCP traffic on port 80
tcp or udp           # TCP or UDP packets
host 192.168.189.20 and port 443  # To/from IP on HTTPS
not arp              # Everything except ARP
```

### Protocol Detection

The sniffer automatically detects:

```
├─ Application Layer
│  ├─ HTTP (port 80)
│  ├─ HTTPS (port 443)
│  └─ DNS (port 53)
├─ Transport Layer
│  ├─ TCP
│  └─ UDP
├─ Network Layer
│  ├─ ICMP
│  └─ ARP
└─ Statistics
   ├─ Total packets
   └─ Protocol breakdown
```

---

## Database Models

### User Model (Custom)

```python
class User(AbstractUser):
    """Custom user model with role-based access"""
    
    ATTACKER = 'attacker'
    DEFENDER = 'defender'
    ADMIN = 'admin'
    
    ROLE_CHOICES = [
        (ATTACKER, 'Attacker'),
        (DEFENDER, 'Defender'),
        (ADMIN, 'Administrator'),
    ]
    
    role = CharField(max_length=20, choices=ROLE_CHOICES, default=ATTACKER)
    
    def is_attacker(self):
        return self.role == self.ATTACKER
    
    def is_defender(self):
        return self.role == self.DEFENDER
    
    def is_admin(self):
        return self.role == self.ADMIN
```

### AttackLog Model

```python
class AttackLog(Model):
    """Records of all attacks performed"""
    
    attack_type = CharField(max_length=50)  # 'ARP', 'SYN_FLOOD'
    attacker = ForeignKey(User, on_delete=CASCADE)
    target_ip = CharField(max_length=15)
    gateway_ip = CharField(max_length=15, null=True)
    target_port = IntegerField(null=True)
    packets_sent = IntegerField(default=0)
    status = CharField(max_length=20)  # 'started', 'stopped', 'completed'
    started_at = DateTimeField(auto_now_add=True)
    ended_at = DateTimeField(null=True)
    details = JSONField(default=dict)
```

### DetectionLog Model

```python
class DetectionLog(Model):
    """IDS alerts and detected anomalies"""
    
    alert_type = CharField(max_length=50)  # 'ARP_SPOOF', 'SYN_FLOOD'
    severity = CharField(max_length=10)    # 'LOW', 'MEDIUM', 'HIGH'
    source_ip = CharField(max_length=15)
    target_ip = CharField(max_length=15)
    packets_detected = IntegerField()
    details = JSONField(default=dict)
    detected_at = DateTimeField(auto_now_add=True)
    acknowledged = BooleanField(default=False)
```

---

## Troubleshooting

### Common Issues

#### Issue 1: "Permission Denied" When Starting Attack

**Problem**: Getting permission error even with administrator rights

**Solutions**:
```bash
# Linux/macOS - Run with sudo
sudo python manage.py runserver

# Windows - Run as Administrator
# Or use:
python manage.py runserver

# Check interface name
ip addr        # Linux
ipconfig       # Windows
ifconfig       # macOS
```

#### Issue 2: "Network Interface Not Found"

**Problem**: ARP spoof fails because interface doesn't exist

**Solution**:
```bash
# Find your interface name
ip link show          # Linux
ipconfig /all         # Windows
ifconfig              # macOS

# Use correct interface:
# eth0, eth1, wlan0 on Linux
# Ethernet, Wi-Fi on Windows via ipconfig
```

#### Issue 3: "Target Host Unreachable"

**Problem**: Scanner or attack can't reach target

**Check**:
```bash
# Test connectivity
ping 192.168.189.20

# Check ARP table
arp -a

# Check routing
route print      # Windows
route -n         # Linux

# Verify network range
# Use correct CIDR for your network
# 192.168.x.0/24 for most networks
```

#### Issue 4: "Django Connection Refused"

**Problem**: Can't access http://localhost:8000

**Solutions**:
```bash
# Check if server is running
netstat -tulpn | grep 8000

# Kill existing process
lsof -ti:8000 | xargs kill -9

# Restart server
python manage.py runserver 0.0.0.0:8000

# Check firewall
# Windows: Disable Windows Firewall for testing
# Linux: sudo ufw disable
```

#### Issue 5: "CSRF Token Missing"

**Problem**: API requests fail with CSRF error

**Solution**:
```javascript
// Get CSRF token from cookies
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

// Include in API requests
fetch('/api/attack/arp/start/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')
    },
    body: JSON.stringify({...})
});
```

---

## Testing the System

### 1. Test User Creation

```bash
python manage.py shell

from web_interface.cybersec_app.models import User

# List all users
for user in User.objects.all():
    print(f"{user.username}: {user.role}")

# Verify roles
attacker = User.objects.get(username='attacker')
print(attacker.is_attacker())  # Should print True
```

### 2. Test Login

```
1. Go to http://localhost:8000/login/
2. Enter username: attacker
3. Enter password: attack123
4. Click Login
5. Should redirect to /attacker/
```

### 3. Test Network Scanner

```
1. Go to Scanner tab
2. Enter network range: 192.168.189.0/24
3. Click "Start Scan"
4. Watch for discovered hosts
5. Scan should show active IPs with MAC addresses
```

### 4. Test ARP Attack (REQUIRES PROPER NETWORK)

```
Prerequisites:
- Same network as victim (192.168.x.x)
- Victim IP: 192.168.189.20
- Gateway IP: 192.168.189.2

Test Steps:
1. Go to Active Attacks tab
2. Enter Victim IP: 192.168.189.20
3. Enter Gateway IP: 192.168.189.2
4. Click "Start ARP Attack"
5. Should show "Attack Started"
6. On victim machine: Check ARP table
   arp -a        # Should show attacker MAC for gateway
7. Click "Stop & Restore"
8. ARP table should restore on victim
```

### 5. Test SYN Flood

```
1. Go to Active Attacks tab
2. Enter Target IP: 192.168.189.20
3. Enter Port: 80
4. Enter Threads: 5
5. Click "Start SYN Flood"
6. Check Attack Statistics - packets should increment
7. On target server, check netstat for SYN_RECV connections
8. Click "Stop Attack"
9. SYN connections should drop
```

### 6. Test Traffic Sniffer

```
1. Go to Traffic Sniffer tab
2. Leave filter empty (capture all)
3. Click "Start Sniffing"
4. Wait 5-10 seconds
5. Should see captured packets appearing
6. Modify filter: "tcp port 443"
7. Should see HTTPS traffic only
8. Click "Stop Sniffing"
```

---

## Production Deployment

### Important: Development vs Production

```
DEVELOPMENT (Current)
├─ Insecure settings (DEBUG=True)
├─ Simple SQLite database
├─ Development server (Daphne)
├─ Not suitable for production
└─ Use for testing only

PRODUCTION (Future)
├─ DEBUG=False
├─ PostgreSQL/MySQL database
├─ Gunicorn + Daphne + Nginx
├─ SSL/TLS certificates
├─ Proper user management
└─ Background workers (Celery)
```

### Production Checklist

- [ ] Set `DEBUG=False`
- [ ] Generate SECRET_KEY
- [ ] Use PostgreSQL database
- [ ] Set ALLOWED_HOSTS properly
- [ ] Use Gunicorn + Daphne
- [ ] Setup Nginx reverse proxy
- [ ] Enable HTTPS/SSL
- [ ] Configure logging
- [ ] Setup regular backups
- [ ] Monitor resource usage
- [ ] Setup alerts for attacks

---

## Conclusion

This IDS Cybersecurity Platform provides a complete, educational system for:
✅ Learning network attack techniques
✅ Understanding attack detection
✅ Evaluating security measures
✅ Authorized penetration testing

**Remember**: ⚠️ **Use only on authorized networks and with proper permissions!**

For questions or issues, contact the development team.

---

**Version**: 1.0.0  
**Last Updated**: December 2025  
**Compatibility**: Python 3.10+, Django 4.2+, Scapy 2.5.0+
