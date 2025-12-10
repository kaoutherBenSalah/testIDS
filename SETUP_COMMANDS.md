# Complete Setup Commands (Network + All VMs)

## VMware Network Setup (VMnet8 NAT)
- Your VMnet8 already configured: gateway 192.168.189.2, subnet 192.168.189.0/24, usable 192.168.189.9–254.
- Ensure all three VMs attached to VMnet8 in VM settings (Edit > Virtual Network Adapter > VMnet8).

---

## VICTIM (RedHat) - 192.168.189.20

### 1. Set Static IP (on RedHat VM)
```bash
# Check current interface
ip link show

# Edit netplan (Ubuntu) or nmtui (RedHat). For RedHat:
sudo nmtui
# OR manually edit:
sudo nano /etc/sysconfig/network-scripts/ifcfg-ens33
# Add/modify:
# BOOTPROTO=none
# IPADDR=192.168.189.20
# NETMASK=255.255.255.0
# GATEWAY=192.168.189.2
# DNS1=8.8.8.8
sudo systemctl restart network
```

### 2. Verify IP
```bash
ip addr | grep 192.168.189
# Should show: 192.168.189.20/24
```

### 3. Install & Start Services
```bash
sudo dnf update -y
sudo dnf install -y httpd vsftpd
sudo systemctl enable --now httpd
sudo systemctl enable --now vsftpd
```

### 4. Open Firewall
```bash
sudo firewall-cmd --add-service=http --permanent
sudo firewall-cmd --add-service=https --permanent
sudo firewall-cmd --add-service=ftp --permanent
sudo firewall-cmd --reload

# Verify
sudo firewall-cmd --list-all
```

### 5. Disable SELinux (lab environment, quick)
```bash
sudo setenforce 0
# Permanent: edit /etc/selinux/config, set SELINUX=disabled, then reboot
```

### 6. Verify Services Listening
```bash
sudo netstat -tlnp | grep -E ':(80|21|443)'
# Or:
ss -tlnp | grep -E ':(80|21|443)'
```

---

## ATTACKER (Kali Linux) - 192.168.189.10

### 1. Set Static IP (on Kali VM)
```bash
# Check interface
ip link show

# Edit network config
sudo nano /etc/network/interfaces
# Add/modify:
# auto eth0
# iface eth0 inet static
#     address 192.168.189.10
#     netmask 255.255.255.0
#     gateway 192.168.189.2
#     dns-nameservers 8.8.8.8

sudo systemctl restart networking
# Or:
sudo ip addr add 192.168.189.10/24 dev eth0
sudo ip route add default via 192.168.189.2
```

### 2. Verify IP
```bash
ip addr | grep 192.168.189
# Should show: 192.168.189.10/24

ping 192.168.189.2   # Ping gateway
ping 192.168.189.20  # Ping victim
```

### 3. Install Python & Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# Verify
python3 --version  # Should be 3.8+
pip3 --version
```

### 4. Clone Project
```bash
cd ~
git clone https://github.com/kaoutherBenSalah/testIDS.git
cd testIDS
```

### 5. Setup Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Verify installs
pip list | grep -E 'Django|scapy|djangorestframework'
```

### 6. Database & Users
```bash
python manage.py migrate
python manage.py create_users

# Output should show:
# Users created:
# - attacker / attack123
# - defender / defend123
# - admin / admin123
```

### 7. Run Attacker Server
```bash
python manage.py runserver 0.0.0.0:8000

# In another terminal, verify:
curl http://192.168.189.10:8000/login
```

### 8. Access from Browser
- From Kali: `http://localhost:8000/login`
- From other VMs/Windows: `http://192.168.189.10:8000/login`
- Credentials: `attacker` / `attack123`

---

## DEFENDER (Ubuntu) - 192.168.189.30

### 1. Set Static IP (on Ubuntu VM)
```bash
# Check interface
ip link show

# Edit netplan (Ubuntu 20.04+)
sudo nano /etc/netplan/01-netcfg.yaml
# Add/modify:
# network:
#   version: 2
#   ethernets:
#     eth0:
#       dhcp4: no
#       addresses:
#         - 192.168.189.30/24
#       routes:
#         - to: 0.0.0.0/0
#           via: 192.168.189.2
#       nameservers:
#         addresses: [8.8.8.8]

sudo netplan apply
```

### 2. Verify IP
```bash
ip addr | grep 192.168.189
# Should show: 192.168.189.30/24

ping 192.168.189.2   # Gateway
ping 192.168.189.10  # Attacker
ping 192.168.189.20  # Victim
```

### 3. Install Python & Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

python3 --version
pip3 --version
```

### 4. Clone Project (or copy from Attacker)
```bash
cd ~
git clone https://github.com/kaoutherBenSalah/testIDS.git
cd testIDS
```

### 5. Setup Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Database & Users
```bash
python manage.py migrate
python manage.py create_users
```

### 7. Run Defender Server (Port 8001)
```bash
python manage.py runserver 0.0.0.0:8001

# In another terminal, verify:
curl http://192.168.189.30:8001/login
```

### 8. Access from Browser
- From Ubuntu: `http://localhost:8001/login`
- From other VMs/Windows: `http://192.168.189.30:8001/login`
- Credentials: `defender` / `defend123`

---

## Quick Verification Checklist

Run these from Attacker (Kali) to verify all is connected:

```bash
# 1. Check all IPs
ip addr show
echo "Attacker IP should be 192.168.189.10"

# 2. Ping all machines
ping -c 1 192.168.189.2   # Gateway
ping -c 1 192.168.189.20  # Victim
ping -c 1 192.168.189.30  # Defender

# 3. Check victim services
curl http://192.168.189.20          # Should show Apache default page
curl http://192.168.189.20:21 2>&1  # Should show FTP banner

# 4. Check attacker UI
curl http://192.168.189.10:8000/login | grep -o '<title>.*</title>'

# 5. Check defender UI (after setup)
curl http://192.168.189.30:8001/login | grep -o '<title>.*</title>'
```

---

## Troubleshooting

### No network connectivity between VMs
- Verify all VMs in VMware settings are on VMnet8.
- Check `ip addr` on each VM matches expected subnet 192.168.189.0/24.
- Ping gateway first: `ping 192.168.189.2`.

### Python/pip not found
- Ensure Python 3.8+ installed: `python3 --version`.
- Use `python3` and `pip3` (not `python`/`pip`).

### Django/Scapy import errors
- Activate venv: `source venv/bin/activate` (Kali/Ubuntu).
- Verify installs: `pip list | grep -E 'Django|scapy'`.
- Reinstall if needed: `pip install -r requirements.txt --force-reinstall`.

### Port 8000/8001 already in use
- Find process: `lsof -i :8000` or `ss -tlnp | grep 8000`.
- Kill: `sudo kill -9 <PID>`.
- Or use different port: `python manage.py runserver 0.0.0.0:8080`.

### Victim services not responding
- Check running: `sudo systemctl status httpd vsftpd`.
- Check ports: `sudo ss -tlnp | grep -E ':(80|21)'`.
- Check firewall: `sudo firewall-cmd --list-all`.

---

## Running Attacks (From Attacker UI at 192.168.189.10:8000)

### Tab 1: Active Attacks

#### ARP Spoofing Attack
1. Go to `http://192.168.189.10:8000/login`, login as `attacker` / `attack123`.
2. Click tab **"Attacks"**.
3. In "ARP Spoofing" card, fill:
   - **Victim IP**: `192.168.189.20` (RedHat)
   - **Gateway IP**: `192.168.189.2` (VMware gateway)
   - **Interface**: Leave blank (auto-detect) or enter `eth0`
   - **Interval**: `2` (seconds between ARP packets)
4. Click **"Start"**.
5. Observe:
   - Button changes to **"Stop"** (enabled).
   - Status box shows "✅ ARP spoofing attack started..."
   - **Attack Statistics** table updates with packets sent.

**How to verify it worked:**
- On **Victim** (RedHat 192.168.189.20), check ARP table:
  ```bash
  arp -a
  # Or:
  ip neigh show
  # Look for: 192.168.189.2 → should map to attacker's MAC (not gateway's real MAC)
  ```
- On **Attacker**, watch packets in real-time:
  - Switch to **"Sniffer"** tab, start with filter `arp`.
  - Should see ARP replies from attacker to victim & gateway.

---

#### SYN Flooding Attack
1. In "SYN Flooding" card, fill:
   - **Target IP**: `192.168.189.20` (RedHat)
   - **Port**: `80` (HTTP)
   - **Threads**: `10` (number of parallel attack threads)
   - **Duration**: Leave blank (infinite until manual stop)
2. Click **"Start"**.
3. Observe:
   - Status shows "✅ SYN Flood attack started..."
   - **Attack Statistics** shows packets sent climbing.

**How to verify it worked:**
- On **Victim**, check for SYN_RECV connections:
  ```bash
  sudo netstat -an | grep SYN_RECV | wc -l
  # Or:
  ss -tn | grep SYN-RECV | wc -l
  # Should show high number (e.g., 100+) while attack runs
  ```
- On **Victim**, monitor httpd:
  ```bash
  sudo tail -f /var/log/httpd/error_log
  # May show: connection limits or timeouts
  ```
- On **Attacker**, check packet count:
  - Observe **Attack Statistics** table; packets_sent should climb rapidly.

---

### Tab 2: Network Scanner

1. Click tab **"Scanner"**.
2. Fill:
   - **Network Range**: `192.168.189.0/24`
   - **Full Scan**: Unchecked (quick ARP sweep) or checked (includes port scan, slower)
3. Click **"Start Scan"**.
4. Watch **"Discovered Hosts"** table populate:
   - IP Address, MAC, Hostname, Open Ports.

**Expect to see:**
```
IP               MAC              Hostname        Ports
192.168.189.2    (router MAC)     gateway         53,67
192.168.189.20   (victim MAC)     redhat/ubuntu   22,80,21,443
192.168.189.10   (attacker MAC)   kali            (your machine)
```

---

### Tab 3: Traffic Sniffer

1. Click tab **"Sniffer"**.
2. Fill:
   - **BPF Filter**: `tcp port 80` (capture HTTP only) or leave blank (all traffic).
3. Click **"Start"**.
4. **Live Packet Capture** shows packets in real-time:
   ```
   Time          Protocol  Source→Destination  Info
   21:45:23      TCP       192...20→192...2    SYN
   21:45:23      ARP       192...10→192...2    Who-has
   21:45:24      TCP       192...20→8.8.8.8    ACK
   ```

**To verify attack traffic:**
- While **ARP attack** runs, start sniffer with filter `arp`.
  - Should see attacker's ARP replies flooding.
- While **SYN flood** runs, start sniffer with filter `tcp port 80`.
  - Should see hundreds of SYN packets from random source IPs to victim:80.

---

### Tab 4: System Info

Shows:
- **Local IP**: 192.168.189.10 (attacker's IP)
- **Gateway**: 192.168.189.2
- **Active Attacks**: Count of running attacks
- **User**: attacker, Admin, etc.

---

## nmcli Command for Kali Static IP (Quick)

If Kali uses NetworkManager:

```bash
# Find interface name
nmcli device show | grep DEVICE

# Create/modify connection for VMnet8 (e.g., ens33)
sudo nmcli connection add type ethernet ifname ens33 con-name VMnet8-Static \
  ipv4.method manual \
  ipv4.addresses 192.168.189.10/24 \
  ipv4.gateway 192.168.189.2 \
  ipv4.dns 8.8.8.8

# Activate
sudo nmcli connection up VMnet8-Static

# Verify
ip addr | grep 192.168.189
```

---

## Workflow Example: Attack → Detect → Verify

1. **Setup**:
   - Victim (RedHat) on 192.168.189.20, httpd running.
   - Attacker (Kali) on 192.168.189.10, UI at :8000.
   - Defender (Ubuntu) on 192.168.189.30 (optional, not yet built).

2. **Attack**:
   - Attacker UI → **Attacks** tab → ARP Spoof start → 192.168.189.20 & 192.168.189.2.

3. **Verify on Victim**:
   ```bash
   arp -a | grep 192.168.189.2
   # Should show attacker's MAC for gateway IP
   ```

4. **Monitor on Attacker**:
   - **Sniffer** tab → filter `arp` → see ARP replies flooding.

5. **Stats**:
   - **Attack Statistics** table shows packets_sent climbing.

6. **Stop**:
   - Click **"Stop & Restore"** → ARP tables restored on victim.

---

## Final Notes

- All VMs must be on the same VMnet8 NAT network.
- Static IPs prevent DHCP reassignment during testing.
- Attacker UI (port 8000) can attack Victim (192.168.189.20).
- Defender UI (port 8001) can monitor attacks (to be built).
- Admin panel optional: `http://192.168.189.10:8000/admin` (admin/admin123).

Keep these commands for future redeployment!
