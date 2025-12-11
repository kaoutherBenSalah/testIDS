# 🚀 QUICK START - Deploy to Kali Linux

## 30-Second Summary

Your testIDS Flask app is **clean and ready**. Copy to Kali and run.

---

## ⚡ Ultra-Quick Setup (Copy & Paste)

### On Kali Terminal (SSH from Windows):

```bash
# 1. Copy from Windows (run from Windows PowerShell, OR use GitHub)
scp -r "C:\MINI PROJET PYTHON\testIDS" root@192.168.189.10:/root/

# 2. SSH to Kali
ssh root@192.168.189.10

# 3. Install & Run (single command)
cd /root/testIDS && pip install -r requirements-flask.txt && python3 app.py
```

### From Windows Browser:

```
http://192.168.189.10:5000/login

Username: attacker
Password: attack123
```

✅ **Done!** You're running.

---

## 📖 Full Guide

See [KALI_DEPLOYMENT.md](KALI_DEPLOYMENT.md) for:
- Detailed step-by-step instructions
- Testing all attack functions
- Troubleshooting
- Security hardening
- Auto-start on boot
- Performance optimization

---

## 📁 What's in the Box

```
testIDS/
├── 📄 app.py                    (Flask main app - START THIS)
├── 📄 models.py                 (User management)
├── 📄 requirements-flask.txt     (Dependencies - pip install these)
├── 📁 routes/                   (API endpoints)
├── 📁 templates/                (Web interface HTML/CSS/JS)
├── 📁 modules/                  (Attack implementations)
├── 📁 utils/                    (Network utilities)
├── 📁 logs/                     (Log directory)
├── 📄 FLASK_SETUP.md            (Architecture & API docs)
├── 📄 KALI_DEPLOYMENT.md        (Full deployment guide)
└── 📄 README.md                 (Project overview)
```

---

## 🎯 Three Commands to Deploy

```bash
# Command 1: Navigate
cd /root/testIDS

# Command 2: Install
pip install -r requirements-flask.txt

# Command 3: Run
python3 app.py
```

Then visit: `http://192.168.189.10:5000/login`

---

## 🔑 Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| Attacker | attacker | attack123 |
| Defender | defender | defend123 |
| Admin | admin | admin123 |

---

## 🧪 Test the Dashboard (After Login)

1. **Attacks Tab** → Fill victim/gateway IPs → Click "Start ARP Attack" ✓
2. **Scanner Tab** → Enter network range → Click "Scan" ✓
3. **Sniffer Tab** → Click "Start Sniffer" → See packets appear ✓
4. **Info Tab** → See live CPU/RAM usage (Shield CPU) ✓

---

## ❓ Common Questions

**Q: Where should I copy the project?**  
A: `/root/testIDS` or anywhere on Kali. Adjust scp path accordingly.

**Q: What Python version?**  
A: 3.9+ (Kali usually has 3.11+)

**Q: Does it need root?**  
A: Yes, for ARP spoofing. Run as: `sudo python3 app.py`

**Q: Can I access from Windows?**  
A: Yes! Use: `http://192.168.189.10:5000` (your Kali IP)

**Q: What if port 5000 is taken?**  
A: Edit app.py line 180: `app.run(host='0.0.0.0', port=5001)` then use `:5001`

**Q: How do I stop it?**  
A: Press `Ctrl+C` in the terminal

**Q: Want it to auto-start?**  
A: See KALI_DEPLOYMENT.md → "Auto-Start on Boot" section

---

## 📞 Need Help?

See: [KALI_DEPLOYMENT.md](KALI_DEPLOYMENT.md#-troubleshooting)

Full docs, troubleshooting, and advanced setup in that file!

---

**Status**: ✅ Clean. ✅ Ready. ✅ Go Deploy!
