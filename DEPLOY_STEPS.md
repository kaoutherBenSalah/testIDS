# Deployment Steps (Attacker / Defender / Victim)

## Network (VMware)
- VMnet8 NAT (your case): `192.168.189.0/24`, gateway `192.168.189.2`, usable hosts `192.168.189.9–254`.
- Suggested static IPs within that range:
   - Attacker/Kali: `192.168.189.10`
   - Victim/RedHat: `192.168.189.20`
   - Defender/Ubuntu: `192.168.189.30`
- Ensure all VMs on the same VMnet8 virtual switch; enable "Connect at power on".

## Victim (RedHat) setup (services to attack)
1) Install services:
   - `sudo dnf install -y httpd vsftpd`
   - `sudo systemctl enable --now httpd`
2) Open ports (quick lab):
   - `sudo firewall-cmd --add-service=http --permanent`
   - `sudo firewall-cmd --reload`
   - If SELinux blocks, temporary: `sudo setenforce 0`
3) Confirm IP: `ip addr | grep 192.168.189`
   - From Kali: `ping 192.168.189.20`

## Attacker (Kali) setup (attacker UI on :8000)
1) Install Python toolchain:
   - `sudo apt update`
   - `sudo apt install -y python3-pip python3-venv`
2) Get project:
   - `git clone https://github.com/kaoutherBenSalah/testIDS`
   - `cd testIDS`
3) Env + deps:
   - `python3 -m venv venv && source venv/bin/activate`
   - `pip install -r requirements.txt`
4) DB + users:
   - `python manage.py migrate`
   - `python manage.py create_users`
5) Run server:
   - `python manage.py runserver 0.0.0.0:8000`
6) Access in browser: `http://192.168.189.10:8000/login` (attacker/attack123).

## Defender (Ubuntu/RedHat) setup (defender UI on :8001)
- Same steps as attacker, but run server on 8001:
  - `python manage.py runserver 0.0.0.0:8001`
- Defender UI will show alerts/logs (to be added if not present yet).

## Admin panel (optional)
- `http://192.168.189.10:8000/admin` (admin/admin123). Ignore if you do not need it.

## Windows host note (only if running server on Windows)
- Bind to `0.0.0.0:8000`, open firewall inbound on 8000, access via `http://<Windows-IP>:8000` from Kali. Recommended: run inside Kali instead.

## Quick verification
- From Kali: `curl http://192.168.189.10:8000/login` (should return HTML).
- Ping victim: `ping 192.168.189.20`; victim HTTP: `curl http://192.168.189.20`.
- Attacker UI login: attacker/attack123.

## Default credentials
- Attacker: attacker / attack123
- Defender: defender / defend123
- Admin: admin / admin123
