# 🔴 Kali Linux Deployment Guide

## Quick Summary

Your testIDS Flask app is ready to deploy on your Kali machine (192.168.189.10). This guide walks you through setup step-by-step.

**Time Required**: 15 minutes  
**Difficulty**: Beginner-friendly  
**Prerequisites**: SSH access to Kali VM, Python 3.9+

---

## 📋 Deployment Checklist

- [ ] Copy project to Kali VM
- [ ] Install Python dependencies
- [ ] Test locally (localhost)
- [ ] Access from Windows (192.168.189.10:5000)
- [ ] Create Kali startup script
- [ ] (Optional) Set Kali to auto-start on boot
- [ ] (Optional) Setup victim/defender VMs for testing

---

## 🚀 Step-by-Step Deployment

### Step 1: Copy Project to Kali VM

**On Your Windows Machine:**

```powershell
# Option A: Via SCP (Recommended)
scp -r "C:\MINI PROJET PYTHON\testIDS" root@192.168.189.10:/root/testIDS

# Option B: Via SSH with Git
# If you cloned from GitHub:
# ssh root@192.168.189.10
# git clone https://github.com/YourUsername/testIDS.git
```

**Or manually via terminal:**

```bash
# SSH into Kali
ssh root@192.168.189.10

# Create directory
mkdir -p /root/testIDS
cd /root/testIDS

# Then copy files using SCP from another terminal on Windows
```

**Expected Result:**
```
/root/testIDS/
├── app.py
├── models.py
├── requirements-flask.txt
├── routes/
├── templates/
├── modules/
├── utils/
├── logs/
├── docs/
└── README.md
```

---

### Step 2: Install Python Packages

**SSH into Kali:**

```bash
ssh root@192.168.189.10
cd /root/testIDS
```

**Install dependencies:**

```bash
# Python 3
pip install -r requirements-flask.txt
```

**Expected output:**
```
Collecting Flask>=2.3.0
Collecting Werkzeug>=2.3.0
Collecting psutil>=5.9.0
Collecting scapy>=2.5.0
...
Successfully installed Flask-2.3.0 Werkzeug-2.3.0 psutil-5.9.0 scapy-2.5.0 ...
```

**Verify installation:**

```bash
python3 -c "import flask; print(f'Flask {flask.__version__}')"
```

---

### Step 3: Test Locally on Kali

```bash
cd /root/testIDS
python3 app.py
```

**Expected output:**
```
 _    _      _                _     _     ____
| |  | |    | |              | |   | |   / __ \
| |__| |___ | |_ ___ ___   __| |_  | |_ | |  | |  ___  ___
|  __  / __|| __/ _ / __| / _` | || __|| | | | | / _ \/ __|
| |  | \__ \| ||  __/\__ \| (_| | || |_ | |__| || (_) \__ \
|_|  |_|___/ \__\___||___/ \__,_| \__| \____/  \___/|___/
                                                 Network Tool

🚀 Flask Web Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Local IP: 192.168.189.10
 * Gateway: 192.168.1.1
 * Running on: http://192.168.189.10:5000
 * Default Users:
   - attacker / attack123 (Attacker role)
   - defender / defend123 (Defender role)
   - admin / admin123 (Admin role)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Success indicator**: You see "Running on: http://192.168.189.10:5000"

---

### Step 4: Access from Windows

**On Your Windows Machine:**

Open a browser and visit:
```
http://192.168.189.10:5000/login
```

**Login with:**
```
Username: attacker
Password: attack123
```

**You should see:**
- Login form accepts credentials ✅
- Dashboard loads with tabs (Attacks, Scanner, Sniffer, Info) ✅
- Attack buttons appear clickable ✅
- Shield CPU card shows CPU/RAM usage ✅

---

### Step 5: Test Attack Functions

**While running the Flask app on Kali:**

1. **Login** with attacker/attack123
2. **Go to Attacks tab**
3. **For ARP Spoofing test:**
   - Victim IP: 192.168.1.100 (any device on your network)
   - Gateway IP: 192.168.1.1
   - Click "Start ARP Attack"
   - Status should show "✅ ARP Attack Started"
   - View attacks in "Active Attacks" table

4. **For SYN Flooding test:**
   - Target IP: 8.8.8.8 (external host)
   - Target Port: 80
   - Num Threads: 5
   - Click "Start SYN Attack"
   - Status should show "✅ SYN Attack Started"

5. **For Network Scanner:**
   - Network Range: 192.168.1.0/24
   - Click "Scan"
   - Wait 30 seconds for results
   - Active hosts should appear in table

6. **For Traffic Sniffer:**
   - Filter (optional): tcp port 443
   - Click "Start Sniffer"
   - Open browser on another machine on your network
   - Packets should appear in real-time

---

## 📖 Kali Linux Setup (Detailed)

### If Kali is a Virtual Machine (VirtualBox/VMware)

**Network Configuration:**

1. **Set adapter to Bridged** (so Kali can talk to Windows):
   - VirtualBox: VM Settings → Network → Bridged Adapter
   - VMware: VM Settings → Network → Bridged

2. **Verify IP address:**
   ```bash
   ip addr show
   # Look for inet 192.168.X.X (not 127.0.0.1)
   ```

3. **Verify Windows can ping Kali:**
   ```powershell
   # From Windows PowerShell
   ping 192.168.189.10
   # Should get replies, not "unreachable"
   ```

### If Kali is on Bare Metal

Just follow the steps above - everything will work normally.

---

## 🔧 Creating a Kali Startup Script

**Create `/root/start_testids.sh`:**

```bash
#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo " _    _      _                _     _     ____"
echo "| |  | |    | |              | |   | |   / __ \\"
echo "| |__| |___ | |_ ___ ___   __| |_  | |_ | |  | |  ___  ___"
echo "|  __  / __|| __/ _ / __| / _\` | || __|| | | | | / _ \/ __|"
echo "| |  | \__ \| ||  __/\__ \| (_| | || |_ | |__| || (_) \__ \\"
echo "|_|  |_|___/ \__\___||___/ \__,_| \__| \____/  \___/|___/"
echo -e "${NC}"

echo -e "${YELLOW}Starting Flask IDS...${NC}"
cd /root/testIDS
python3 app.py
```

**Make it executable:**

```bash
chmod +x /root/start_testids.sh
```

**Run anytime:**

```bash
/root/start_testids.sh
```

---

## 🎯 Full Kali Setup (One Command)

Copy and paste this entire command in Kali terminal:

```bash
# Download/copy to /root/testIDS, install dependencies, and run
cd /root/testIDS && \
pip install -r requirements-flask.txt && \
echo "✅ Setup complete!" && \
python3 app.py
```

---

## 🧪 Testing Scenarios

### Scenario 1: Basic Network Connectivity

```bash
# From Kali
ping 8.8.8.8          # Internet access
ping 192.168.1.1      # Gateway
ifconfig              # Check IP is 192.168.189.10

# From Windows
ping 192.168.189.10   # Should get replies
```

### Scenario 2: Flask Web App

```bash
# On Kali, run app
python3 app.py

# From Windows, open in browser
http://192.168.189.10:5000/login

# Login with attacker/attack123
# Should see dashboard with tabs and buttons
```

### Scenario 3: ARP Spoofing Test (Safe)

```bash
# On Kali, start Flask app
python3 app.py

# In another Kali terminal, monitor ARP traffic:
arp-scan -l

# From Windows browser:
# 1. Login to http://192.168.189.10:5000
# 2. Go to Attacks tab
# 3. Fill in victim/gateway IPs
# 4. Click Start ARP Attack
# 5. Check Kali terminal for "ARP packets sent"

# To stop: Click Stop button in dashboard
```

### Scenario 4: SYN Flood Test (External Target)

```bash
# On Kali, start Flask app
python3 app.py

# From Windows browser:
# 1. Go to Attacks tab
# 2. Fill Target IP: 8.8.8.8, Port: 80
# 3. Click Start SYN Attack
# 4. Watch progress in "Active Attacks" table
# 5. Click Stop when done

# Note: Only do this on targets you own/control!
```

### Scenario 5: Sniffer Real-Time Test

```bash
# On Kali, start Flask app
python3 app.py

# From another machine on network:
# 1. Open browser and go to google.com
# 2. Go back to IDS dashboard, Sniffer tab
# 3. Leave Filter empty, click Start
# 4. Packets from that browser session appear in real-time!
# 5. Filter by: tcp port 443 to see HTTPS only
```

---

## 🐛 Troubleshooting

### Problem: "Connection refused" from Windows

**Cause**: Flask not running or port blocked

**Solution**:
```bash
# On Kali, check if app is running
ps aux | grep python

# If not running, start it:
cd /root/testIDS && python3 app.py

# Verify port 5000 is listening:
netstat -tulpn | grep 5000
```

### Problem: "Cannot find module scapy"

**Cause**: Dependencies not installed

**Solution**:
```bash
cd /root/testIDS
pip install -r requirements-flask.txt

# If that fails, install manually:
pip install flask werkzeug psutil scapy python-dateutil colorama
```

### Problem: ARP attack doesn't work

**Cause**: Usually requires root/sudo, or interfaces not set correctly

**Solution**:
```bash
# Make sure running as root:
sudo python3 app.py

# Or if using regular user:
sudo -u root python3 app.py

# Check available interfaces:
ip link show
# Use the right interface (eth0, wlan0, etc.)
```

### Problem: Can't access from Windows (IP unreachable)

**Cause**: Network not properly bridged or firewall blocking

**Solution**:
```bash
# On Kali
# 1. Check IP matches your network:
ip addr show

# 2. Disable firewall temporarily:
systemctl stop ufw  # Or sudo ufw disable

# 3. Check from Windows:
ping 192.168.189.10
# Should get replies

# 4. Then access app:
http://192.168.189.10:5000
```

### Problem: "Address already in use"

**Cause**: Another app is using port 5000

**Solution**:
```bash
# Find what's using port 5000:
netstat -tulpn | grep 5000

# Kill that process:
kill -9 <PID>

# Or change Flask port in app.py line:
# app.run(host='0.0.0.0', port=5001)  # Change to 5001
# Then access: http://192.168.189.10:5001
```

---

## 🔐 Security Notes

### Before Deploying to Production

1. **Change the secret key** in app.py:
   ```python
   # In app.py, line 15:
   # CHANGE FROM:
   app.secret_key = 'your-secret-key-change-in-production'
   # TO:
   app.secret_key = 'random-strong-key-min-32-chars'
   ```

2. **Change default passwords** in models.py:
   ```python
   # Change attacker/attack123, defender/defend123, etc.
   # See models.py: create_default_users() function
   ```

3. **Use HTTPS** (optional but recommended):
   ```bash
   # Generate self-signed certificate:
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
   
   # In app.py, change last line to:
   app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
   ```

4. **Firewall** (optional):
   ```bash
   # Only allow specific IPs to access port 5000:
   sudo ufw allow from 192.168.1.0/24 to any port 5000
   sudo ufw deny from any to any port 5000
   ```

---

## 📊 Performance Tips

### Running in Background (Detached)

```bash
# Option 1: Using nohup
nohup python3 app.py > app.log 2>&1 &

# Option 2: Using screen
screen -S testids python3 app.py
# Detach: Ctrl+A then D
# Reattach: screen -r testids

# Option 3: Using tmux
tmux new-session -d -s testids python3 app.py
# Reattach: tmux attach -t testids

# Check logs:
tail -f app.log
```

### Auto-Start on Kali Boot

**Create systemd service:**

```bash
sudo nano /etc/systemd/system/testids.service
```

**Paste:**
```ini
[Unit]
Description=testIDS Flask Application
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/testIDS
ExecStart=/usr/bin/python3 /root/testIDS/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable testids.service
sudo systemctl start testids.service

# Check status:
sudo systemctl status testids.service
```

---

## 📞 Quick Reference Commands

```bash
# SSH to Kali
ssh root@192.168.189.10

# Go to project
cd /root/testIDS

# Install dependencies
pip install -r requirements-flask.txt

# Run app
python3 app.py

# Stop app
Ctrl+C

# View logs (if running detached)
tail -f app.log

# Check if port 5000 is listening
netstat -tulpn | grep 5000

# Kill app running on port 5000
fuser -k 5000/tcp

# Update from GitHub (if using Git)
cd /root/testIDS && git pull origin main
```

---

## 🎯 Success Checklist

After following this guide:

- [ ] Project copied to `/root/testIDS` on Kali
- [ ] All packages installed (`pip install -r requirements-flask.txt`)
- [ ] Flask app runs without errors
- [ ] Can access `http://192.168.189.10:5000` from Windows
- [ ] Login works with attacker/attack123
- [ ] Dashboard shows all tabs (Attacks, Scanner, Sniffer, Info)
- [ ] Attack buttons are clickable
- [ ] Shield CPU monitoring shows live data
- [ ] All attack functions work (ARP, SYN, Scanner, Sniffer)

✅ **If all checkboxes are complete, deployment is successful!**

---

## 🚀 Next Steps

1. **Test with victim/defender VMs** (optional)
   - Set up Windows 7/10 as victim
   - Set up Linux as defender
   - Run attacks from testIDS dashboard

2. **Customize for your network**
   - Update gateway IP (currently 192.168.1.1)
   - Update network range for scanner
   - Add custom attack scenarios

3. **Add your own features**
   - More attack types
   - Custom detection rules
   - Database logging
   - Advanced dashboard charts

4. **Deploy to production** (if needed)
   - Use HTTPS
   - Setup authentication
   - Add rate limiting
   - Configure logging

---

## 📞 Support

If you encounter issues:

1. Check **Troubleshooting** section above
2. View app logs: `tail -f app.log` (if running detached)
3. Check Kali system logs: `journalctl -u testids` (if using systemd)
4. Verify network: `ping 192.168.189.10` from Windows
5. Check port: `netstat -tulpn | grep 5000` on Kali

---

**Version**: 1.0  
**Last Updated**: December 2025  
**Status**: ✅ Ready for Deployment
