# IDS Backend Explained

This file summarizes how the backend works, where key functions live, and how requests flow.

## Top-Level Entry (app.py)
- Creates Flask app, sets `secret_key`, session storage.
- Registers blueprints:
  - `/api/attack/*` → routes/attacks.py (ARP, SYN attacks)
  - `/api/*` → routes/api.py (scanner, sniffer, info)
- Auth routes:
  - `/login` (GET/POST): checks username/password via models.py → JSON user store.
  - `/logout`: clears session.
  - `/attacker`, `/defender`: role-gated dashboards.
- Context processor exposes `user_id`, `user_role` to templates.

## Users & State (models.py)
- User class (Flask-Login compatible): `username`, `role` (ATTACKER or DEFENDER).
- JSON DB at data/users.json; default users created on startup.
- Functions:
  - `verify_password(username, password)`: check hash.
  - `get_user_by_username(username)`: return User.
- In-memory runtime maps (reset on restart):
  - `active_attacks`, `active_scanners`, `active_sniffers`, `attack_logs`.

## Attack API (routes/attacks.py)
- Middleware: `require_attacker` ensures role ATTACKER.
- ARP Spoofing:
  - `POST /api/attack/arp/start`: create ARPSpoofer, start thread, store in `active_attacks`.
  - `POST /api/attack/arp/stop`: call `stop_attack()`, remove from map.
- SYN Flood:
  - `POST /api/attack/syn/start`: create SYNFlooder, start thread.
  - `POST /api/attack/syn/stop`: call `stop()`, remove from map.
- `GET /api/attack/stats`: return running attacks snapshot.

## Utility API (routes/api.py)
- Middleware: `require_attacker` for scanner/sniffer endpoints.
- Scanner:
  - `POST /api/scan/start`: create NetworkScanner, run `identify_active_machines(cidr, full_scan)` in background, store results in `active_scanners`.
  - `GET /api/scan/results/<scan_id>`: fetch hosts + status.
  - `POST /api/scan/stop`: call scanner.stop() flag.
- Sniffer:
  - `POST /api/sniff/start`: create TrafficSniffer, run `start_sniffing(filter_str)` in background, store in `active_sniffers`.
  - `GET /api/sniff/packets/<sniffer_id>`: return last 50 packets.
  - `POST /api/sniff/stop`: stop and delete sniffer.
- Network info:
  - `GET /api/network/info`: returns local_ip, gateway_ip, counts, cpu/ram.

## Modules (core logic)

### modules/arp_spoof.py (ARPSpoofer)
- `start_attack(interval=2, capture=True)`: resolves MACs, enables IP forwarding, loops sending ARP replies to victim and gateway.
- `stop_attack()`: stops loop, restores ARP tables (sends correct mappings), disables capture.
- Helpers: `spoof()`, `restore()`, optional PCAP capture.

### modules/syn_flood.py (SYNFlooder)
- `start_attack(duration=None)`: validates target, spawns threads; each thread sends TCP SYN with random source IP/port.
- `stop_attack()`: sets is_running False, waits threads.

### modules/network_scanner.py (NetworkScanner)
- `identify_active_machines(cidr, full_scan=False)`: ARP scan → Host list; optional full scan triggers port scan + OS guess.
- `scan_subnet(cidr)`: ARP broadcast, collects IP/MAC.
- `scan_ports(ip, ports=None)`: SYN scan common ports; sends RST to close.
- `stop()`: set stop_requested flag checked in loops.
- Host model: `to_dict()` returns ip, mac, open_ports, is_active, os_guess.

### modules/traffic_sniffer.py (TrafficSniffer)
- `start_sniffing(filter_str=None, count=0)`: launches Scapy sniff in thread; stores analyzed packets in memory (max ~1000).
- `stop_sniffing()`: sets flag to stop sniff loop; closes writer if used.
- `get_packets(limit)`: returns recent captured packet infos.
- `analyze_packet(packet)`: extracts protocol, src/dst, ports, length, info (HTTP/DNS/ARP/ICMP/TCP/UDP).

## Utils
- utils/network_utils.py:
  - `get_local_ip()`: picks primary IP.
  - `get_gateway_ip()`: ARP who-has to find gateway.
  - `get_mac(ip)`: ARP resolution.
  - `enable_ip_forwarding()` / `disable_ip_forwarding()`.
- utils/logger.py:
  - `get_logger(name)`: file + console logger used across modules.

## Data Flow (Attacker ARP example)
1) Frontend POST /api/attack/arp/start → attacks.py → create ARPSpoofer → thread runs start_attack().
2) Module spoofs victim/gateway; active_attacks tracks status.
3) Frontend polls /api/attack/stats to display running attacks.
4) Stop via /api/attack/arp/stop → stop_attack() → restore ARP tables → remove from map.

## Data Flow (Scanner + Sniffer)
- Scanner: POST /api/scan/start → background scan → results saved in active_scanners[scan_id] → GET results.
- Sniffer: POST /api/sniff/start → background sniff → packets kept in memory → GET packets (last 50) → stop to release.

## Persistence
- Users: JSON file data/users.json created/updated on startup if missing.
- Runtime state (attacks/scans/sniffers) is **in-memory only**; cleared on restart.

## Security Notes
- Role check via session (`user_role` == ATTACKER) for attack/scan/sniff.
- No DB, no tokens; intended for lab use.
- Scapy requires root or CAP_NET_RAW.

## How to Run
```bash
pip install -r requirements-flask.txt
sudo python app.py
# Open http://localhost:5000 and log in:
# attacker / attack123  (ATTACKER role)
# defender / defend123  (DEFENDER role)
```
