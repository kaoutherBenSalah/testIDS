# 🛡️ testIDS - HIDS Setup Guide

## Project Overview

**testIDS** is an educational Intrusion Detection System where:
- **Attacker Machine (Kali Linux)** attacks the defender
- **Defender Machine** detects and blocks attacks on itself (HIDS)
- Both machines are on the **same network**

---

## 🎯 How It Works

### Attacks (Attacker Side - Kali Linux)
1. **ARP Spoofing** - Poisons ARP tables to intercept traffic
2. **DNS Spoofing** - Sends fake DNS responses to redirect domains
3. **SYN Flooding** - Sends massive TCP SYN packets (DoS attack)

### Detection (Defender Side)
The defender **passively detects attacks on itself**:
- **ARP Spoof Detection** - Detects when ARP table changes unexpectedly
- **DNS Spoof Detection** - Detects fake DNS responses
- **SYN Flood Detection** - Detects abnormal SYN packet spike
- **Port Scan Detection** - Detects rapid connection attempts

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

#### Option B: DNS Spoofing
```
Attacker IP: 192.168.1.100 (Your IP)
Target Domains: google.com,facebook.com (comma-separated)
Interface: eth0 (or your network interface)
```

#### Option C: SYN Flooding
```
Target IP: 192.168.1.101 (Defender's IP)
Port: 80 (any port)
Duration: 60 (seconds)
Threads: 10
```

3. **Start Attack** - Click "Start [Attack Type]"
4. **Watch Defender Dashboard** - See the alert pop up
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

### DNS Not Resolving Correctly
**Problem:** DNS spoof might not intercept if DNS cached
**Solution:**
1. Clear DNS cache:
   ```bash
   # Windows
   ipconfig /flushdns
   
   # Linux
   sudo systemctl restart systemd-resolved
   ```
2. Restart browser or use `nslookup` to test

---

## 📊 Alert Types

| Alert Type | Severity | What It Means |
|------------|----------|---------------|
| ARP_SPOOF_DETECTED | CRITICAL | Someone changed their MAC address for your IP |
| DNS_SPOOF_DETECTED | CRITICAL | Someone sent fake DNS responses |
| SYN_FLOOD_DETECTED | CRITICAL | Someone sent abnormal SYN packets |
| PORT_SCAN_DETECTED | HIGH | Someone scanned many ports rapidly |

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
│   ├── dns_spoof.py      # DNS spoofing attack
│   ├── syn_flood.py      # SYN flood attack
│   └── ids_monitor.py    # IDS detection engine
├── routes/
│   ├── attacks.py        # Attack endpoints
│   └── ids.py            # IDS control endpoints
├── templates/
│   ├── attacker.html     # Attacker UI
│   ├── defender.html     # Defender UI
│   └── login.html        # Login page
└── static/js/
    └── defender.js       # Dashboard logic
```

---

## 🧪 Testing Checklist

- [ ] Both machines can ping each other
- [ ] Can login to both dashboards
- [ ] Start IDS on defender (should say "running")
- [ ] Start ARP spoof on attacker (should send packets)
- [ ] Defender dashboard shows ARP alert
- [ ] Click "Block" button to block attacker
- [ ] Test DNS spoof and SYN flood similarly

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
