# 🛡️ HIDS Project - Professor Demo Guide

## Overview
This is a **Host-based Intrusion Detection System (HIDS)** that detects network attacks in real-time and blocks malicious IPs. The system consists of:
- **Attacker Machine** (Kali Linux) - Launches network attacks
- **Defender Machine** (Ubuntu/Debian) - Runs IDS, detects attacks, blocks attackers

---

## What Each Detection Means (For Professor)

### 🔍 **ARP SCAN**
- **What it is**: Attacker sends ARP (Address Resolution Protocol) requests to discover all devices on the network
- **Why it's suspicious**: Normal devices don't constantly probe the network; attackers do this as reconnaissance
- **Real-world impact**: Attacker maps out the network before launching further attacks

### ⚡ **SYN FLOOD**
- **What it is**: Attacker rapidly sends 500+ SYN packets from 20+ different sources in 10 seconds
- **Why it's suspicious**: This is a Denial-of-Service (DDoS) attack pattern; legitimate traffic doesn't behave like this
- **Real-world impact**: Overwhelms the system's resources, making it unresponsive to legitimate users

### 🌐 **DNS SPOOF**  
- **What it is**: Attacker intercepts DNS queries and sends fake IP responses
- **Why it's suspicious**: Redirects user to attacker's server (e.g., fake banking website)
- **Real-world impact**: Users unknowingly visit attacker's malicious site; phishing/credential theft

---

## Defender Dashboard - What Each Section Does

### IDS State Card
- **Status**: Shows if IDS is "running" or "stopped" (green = running)
- **Interface**: Which network interface is being monitored (eth0, wlan0, etc)
- **Range**: The network being protected (e.g., 192.168.1.0/24)
- **Started**: When the IDS was activated

### Detections Card
- **Real-time counters** showing:
  - 🔍 ARP scans detected
  - ⚡ SYN events detected  
  - 🌐 DNS spoofs detected

### IDS Configuration Section
- **Interface**: Which network card to monitor (auto-detect usually works)
- **SYN Threshold**: Minimum SYN packets to trigger alert (500+ recommended = less false positives)
- **SYN Window**: Time window to count packets (10 seconds)
- **Unique Sources Min**: Minimum different attackers needed (20+ = prevents normal traffic false positives)

### Blocked IPs Section
- **Shows all IPs we've blocked** with a big red "🚫" marker
- Click **Unblock** to remove IP from blocklist (for testing)
- This is the **proof** that blocking is happening!

### Live Alerts Section
- **Real-time alerts** from attacks
- Each alert shows:
  - Attack type (ARP_SCAN_DETECTED, SYN_FLOOD_DETECTED, DNS_SPOOF_DETECTED)
  - Source IP of attacker
  - Details about the attack
  - **Block button** to immediately block that IP
  - Timestamp of detection

---

## Attacker Dashboard - How to Run Demo

### 1. Network Scanner (Optional - shows discovered devices)
- Click "Start Scan" to discover all machines on network
- Shows IPs, hostnames, open ports

### 2. ARP Spoofing Attack
**Demo steps:**
1. Select attacker interface (eth0/wlan0)
2. Select victim and gateway from dropdowns (auto-filled from scan)
3. Click "Start"
4. **On Defender**: Watch ARP_SCAN_DETECTED appear in alerts
5. Click "Block" to block attacker's IP
6. **Visual proof**: Blocked IP appears in red "🚫" section

### 3. SYN Flood Attack
**Demo steps:**
1. Select target IPs (multi-select from scan results)
2. Enter ports (80,443 = web traffic)
3. Click "Start SYN Flood"
4. **On Defender**: Watch for SYN_FLOOD_DETECTED alerts (shows 500+ packets)
5. Click "Block" - attacker's IP gets blocked

### 4. DNS Spoofing Attack
**Demo steps:**
1. **Attacker IP** = Already auto-filled with your IP ✅
2. **Target Domains** = Already pre-filled (google.com, facebook.com) ✅
3. **Interface** = Select eth0 or wlan0
4. Click "Start DNS Spoof"
5. **On Defender**: Watch for DNS_SPOOF_DETECTED alerts
6. Click "Block" - attacker's IP gets blocked

---

## Step-by-Step Demo for Professor

### SETUP (Do before demo)
```bash
# On Defender machine:
cd /path/to/testIDS
python3 app.py

# On Attacker machine (Kali):
cd /path/to/testIDS
python3 app.py
```

Both should be running on localhost:5000

### DEMO SEQUENCE (5-10 minutes)

#### 1. Show Initial Dashboard (30 seconds)
- Open Defender dashboard - show empty state
- Explain detection types card shows 0/0/0 detections
- Show Blocked IPs section is empty

#### 2. Start IDS Monitoring (1 minute)
- Click "Start IDS" on Defender
- Show status changes to "running" (green)
- Explain we're now passively listening to network traffic

#### 3. Launch ARP Attack (2 minutes)
- Go to Attacker machine
- Click "Start" on ARP Spoofing card
- Watch Defender dashboard
- **LIVE ALERT** appears in red
- Click "Block" on alert
- **VISUAL PROOF**: Blocked IP appears in 🚫 section (red)
- Status shows "✅ Blocked X.X.X.X - IP added to firewall blacklist"

#### 4. Launch DNS Attack (2 minutes)
- Attacker machine: DNS attack already has IP pre-filled ✅
- Click "Start DNS Spoof"
- Defender dashboard shows: DNS_SPOOF_DETECTED alert
- Click "Block" on alert
- **VISUAL PROOF**: Second IP appears in Blocked IPs section

#### 5. Show Statistics (1 minute)
- Point out:
  - "Alerts" counter shows total attack detections
  - "Blocks requested" shows 2 (both attacks blocked)
  - Detection counters show 1 ARP, 1 DNS spoof

#### 6. Explain Why This Matters (1 minute)
- **Passive Detection**: IDS doesn't break the network (no aggressive scanning)
- **Immediate Response**: Blocks happen in real-time
- **Visual Evidence**: Blocked IPs section proves it's working
- **Auto-Learning**: DNS learns legitimate servers (8.8.8.8, 1.1.1.1) and only flags actual spoofs

---

## Key Talking Points for Professor

1. **Passive vs Aggressive**
   - ❌ Old approach: Constantly scan network = breaks network
   - ✅ New approach: Passively listen to traffic = zero disruption

2. **Smart Detection**
   - Thresholds prevent false positives (500 SYN packets minimum)
   - DNS learns legitimate servers instead of flagging everything

3. **Real-time Response**
   - User clicks "Block" → Firewall rule added immediately
   - Visible in Blocked IPs section (not just a log file)

4. **HIDS Focus**
   - Protects a single machine (the Defender)
   - Detects attacks targeting that machine
   - Not trying to monitor entire corporate network

---

## If Something Goes Wrong

### No Alerts Appearing
- Check: Is IDS showing "running" status?
- Check: Is interface correct? (eth0, wlan0, en0?)
- Check: Are both machines on same network?

### Block Button Doesn't Show Feedback
- Refresh the Defender dashboard
- IP should appear in Blocked IPs section after 2 seconds

### DNS Attack Not Working
- Check: Attacker IP field is filled (auto-filled with local IP)
- Check: At least one domain entered
- Check: Interface selector has a value

### Attacks Not Triggering
- **SYN**: Need 500+ packets AND 20+ different sources (check thresholds in IDS Controls)
- **DNS**: Attacker must intercept actual DNS queries (victim must try to visit domain)
- **ARP**: Should trigger immediately when spoof starts

---

## Technical Stack

- **Framework**: Flask (Python web framework)
- **Packet Analysis**: Scapy (network packet library)
- **Authentication**: Flask-Login
- **Frontend**: HTML/CSS/JavaScript
- **Firewall Blocking**: iptables (Linux) / Windows Firewall (via netsh)

---

## File Structure

```
testIDS/
├── app.py                    # Flask application (start here)
├── models.py                 # Data models for alerts/attacks
├── modules/
│   ├── ids_monitor.py        # Core IDS detection logic ⭐
│   ├── dns_spoof.py          # DNS spoofing attack
│   ├── arp_spoof.py          # ARP spoofing attack
│   └── syn_flood.py          # SYN flood attack
├── routes/
│   ├── ids.py                # Defender API endpoints
│   └── attacks.py            # Attacker API endpoints
├── templates/
│   ├── defender.html         # Defender dashboard
│   └── attacker.html         # Attacker dashboard
└── static/
    ├── js/defender.js        # Defender UI logic
    └── css/hacker-theme.css  # Dark theme styling
```

---

**Last Updated**: January 2, 2026  
**Branch**: `hids-refactor`  
**Ready for Demo**: ✅ YES
