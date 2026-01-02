# 🛡️ testIDS - HIDS Setup Guide

## Project Overview

**testIDS** is an educational Intrusion Detection System where:
- **Attacker Machine (Kali Linux)** attacks the defender
- **Defender Machine** detects and blocks attacks on itself (HIDS)
- Both machines are on the **same network**

---

## 🎯 How It Works

### Attacks (Attacker Side - Kali Linux)
1. **ARP Spoofing** - Poisons ARP tables to intercept traffic (MITM)
2. **SYN Flooding** - Floods target with SYN packets to exhaust resources (DoS)

### Detection (Defender Side)
The defender **passively detects attacks on the network**:
- **ARP Spoof Detection** - Detects when ARP table is poisoned
- **SYN Flood Detection** - Detects abnormal SYN packet spike (150+ from 15+ sources)
- **Port Scan Detection** - Detects rapid port scanning (10+ ports in 10s)

### Blocking
When an attack is detected:
- Alert shown in dashboard
- Defender blocks attacker's IP via Windows Firewall

---

## 🖥️ Network Setup

```
Network: 192.168.1.0/24

Machine 1: Attacker (Kali Linux)
├─ IP: 192.168.1.100 (or whatever your Kali IP is)
├─ Flask port: 5000
└─ Roles: ATTACKER user

Machine 2: Defender (Windows/Linux)
├─ IP: 192.168.1.101 (or whatever your defender IP is)
├─ Flask port: 5000
└─ Roles: DEFENDER user
```

---

## 📋 Requirements

**On Both Machines:**
```bash
pip install -r requirements-flask.txt
```

**Requirements:**
- Python 3.7+
- Flask
- Scapy
- Flask-Login

**On Windows (Defender):**
- Windows Firewall (for IP blocking)
- Administrator privileges (for packet sniffing and firewall)

**On Kali (Attacker):**
- Root/sudo privileges (for packet manipulation)

---

## 🚀 Running the Project

### Step 1: Start Defender Machine First

```bash
# On Defender Machine (Windows or Linux)
python app.py
```

Output:
```
============================================================
🔐 IDS - Flask Version
============================================================
📍 Local IP: 192.168.1.101
🔌 Gateway: 192.168.1.1

👤 Default Users:
   - attacker / attack123 (ATTACKER)
   - defender / defend123 (DEFENDER)

🚀 Running on: http://localhost:5000
============================================================
```

**Access Defender Dashboard:**
```
http://192.168.1.101:5000/
```

Login with:
- Username: `defender`
- Password: `defend123`

---

### Step 2: Start Attacker Machine

```bash
# On Attacker Machine (Kali Linux)
python app.py
```

**Access Attacker Interface:**
```
http://192.168.1.100:5000/
```

Login with:
- Username: `attacker`
- Password: `attack123`

---

## 🎮 How to Use

### Defender Side

1. **Login** as `defender`
2. **Start IDS** - Click "Start IDS" button
   - Listens for attacks on this machine
3. **Monitor Alerts** - See real-time attacks in dashboard
4. **Block Attacker** - Click "Block" on any alert to block the attacker's IP

### Attacker Side

1. **Login** as `attacker`
2. **Choose Attack:**

#### Option A: ARP Spoofing
```
Target IP: 192.168.1.101 (Defender's IP)
Gateway IP: 192.168.1.1 (Your gateway)
Interval: 2 (seconds between spoofs)
Interface: eth0 (or your network interface)
```

#### Option B: SYN Flooding
```
Target IPs: 192.168.1.101 (Defender's IP) - select from scan results
Target Ports: 22 (SSH) or 80 (HTTP) - any open port
Threads: 50 (concurrent attack threads)
Rate Limit: 0 (unlimited packets/sec)
Random Bots: 100 (simulates botnet with 100 fake IPs)
Enable IP Spoofing: ✓ (uses scanned IPs as spoofed sources)
```

3. **Start Attack** - Click "Start" button
4. **Watch Defender Dashboard** - See CRITICAL alert within seconds
5. **Stop Attack** - Click "Stop"

---

## 🔧 Troubleshooting

### "Permission Denied" Error
**Solution:** Run with sudo/Administrator:
```bash
sudo python app.py          # Linux/Mac
python app.py (as Admin)    # Windows
```

### Packets Not Detected
**Problem:** IDS might not be sniffing the right interface
**Solution:**
1. Check your network interface name:
   - Windows: `ipconfig`
   - Linux: `ifconfig` or `ip addr`
2. Specify interface in IDS start:
   ```
   Interface: eth0
   Network range: 192.168.1.0/24
   ```

### Firewall Blocking Fails (Windows)
**Problem:** Windows Firewall can't be modified
**Solution:**
1. Run as Administrator
2. Manually add firewall rules in Windows Defender Firewall

### SYN Flood Not Causing Effect
**Problem:** SYN flood attack runs but victim shows no impact
**Solution:**
1. Target an **open port** on victim (SSH on 22, HTTP on 80)
2. Start service on victim first:
   ```bash
   # Start HTTP server on port 80
   sudo python3 -m http.server 80
   ```
3. Increase attack intensity:
   - Threads: 50
   - Random Bots: 100+
   - Rate Limit: 0 (unlimited)
4. Monitor victim's SYN queue:
   ```bash
   watch -n 1 'netstat -tan | grep SYN_RECV | wc -l'
   ```

---

## 📊 Alert Types

| Alert Type | Severity | What It Means |
|------------|----------|---------------|
| ARP_SPOOF_DETECTED | CRITICAL | ARP cache poisoned - MITM attack detected |
| SYN_FLOOD_DETECTED | CRITICAL | 150+ SYNs from 15+ sources - DoS attack |
| PORT_SCAN_DETECTED | HIGH | 10+ ports scanned in 10s - reconnaissance |

---

## 🔐 Default Credentials

| User | Password | Role |
|------|----------|------|
| attacker | attack123 | ATTACKER |
| defender | defend123 | DEFENDER |

---

## 📁 Project Structure

```
testIDS/
├── app.py                 # Main Flask app
├── models.py             # User/alert models
├── modules/
│   ├── arp_spoof.py      # ARP spoofing attack
│   ├── syn_flood.py      # SYN flood attack (multi-threaded, IP spoofing)
│   └── ids_monitor.py    # IDS detection engine (ARP/SYN/Port Scan)
├── routes/
│   ├── attacks.py        # Attack API endpoints
│   └── ids.py            # IDS control endpoints
├── templates/
│   ├── attacker.html     # Attacker dashboard
│   ├── defender.html     # Defender dashboard
│   └── login.html        # Login page
└── static/js/
    └── defender.js       # Real-time detection updates
```

---

## 🧪 Testing Checklist

- [ ] Both machines can ping each other
- [ ] Can login to both dashboards (attacker/attack123, defender/defend123)
- [ ] Defender: Start IDS (should say "running")
- [ ] Attacker: Scan network (discover devices)
- [ ] Attacker: Start ARP spoof on defender's IP
- [ ] Defender: See ARP SPOOF alert (CRITICAL)
- [ ] Attacker: Start SYN flood on port 22 with 100 random bots
- [ ] Defender: See SYN FLOOD alert (CRITICAL)
- [ ] Defender: Block attacker IP via firewall
- [ ] Verify attacks stop working after block

---

## 🛑 Stopping the Project

Press `CTRL+C` on both machines to stop Flask servers.

---

## 📝 Notes

- **No victim machine needed** - Defender IS the victim/target
- **Passive detection only** - IDS doesn't scan the network, only detects attacks on itself
- **Safe for shared networks** - Won't disrupt other devices
- **Educational only** - Do not use on networks you don't own!

---

## 📧 Support

If something doesn't work:
1. Check requirements are installed
2. Verify both machines are on same network
3. Check firewall isn't blocking localhost connections
4. Run with `python app.py` to see debug output
