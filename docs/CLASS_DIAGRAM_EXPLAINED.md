# UML Class Diagram for IDS Cybersecurity Platform

## 📊 Class Diagram Overview

This document describes the complete class structure of the IDS platform.

### How to View the Diagram

**Option 1: Online PlantUML Viewer**
1. Go to http://www.plantuml.com/plantuml/uml/
2. Copy the contents of `class_diagram.puml`
3. Paste and view

**Option 2: VS Code Extension**
1. Install "PlantUML" extension in VS Code
2. Open `class_diagram.puml`
3. Press `Alt+D` to preview

**Option 3: Generate PNG**
```bash
# Install PlantUML
sudo apt install plantuml

# Generate image
plantuml class_diagram.puml

# Output: class_diagram.png
```

---

## 📦 Package Structure

### 1. **Authentication Package**
Handles user authentication and session management.

**Classes:**
- `User`: User account with role-based permissions
- `UserRole` (enum): ATTACKER, DEFENDER, ADMIN
- `Session`: User session management

**Key Features:**
- Password hashing (Django's built-in)
- Role-based access control
- Session timeout management

---

### 2. **Attack Modules Package**
Contains all attacker-side functionality.

**Classes:**

#### `BaseAttack` (Abstract)
Parent class for all attacks with common functionality:
- Start/stop attack
- Statistics tracking
- Validation

#### `ARPSpoofer`
Implements ARP Spoofing (Man-in-the-Middle) attack:
- **Methods:**
  - `spoof()`: Send fake ARP packets
  - `restore()`: Restore legitimate ARP tables
  - `maintain_poisoning()`: Keep attack running
  - `sniff_traffic()`: Capture intercepted packets

#### `SYNFlooder`
Implements SYN Flood (DoS) attack:
- **Methods:**
  - `_send_syn_packet()`: Send TCP SYN with random source IP
  - `_worker_thread()`: Multi-threaded packet generation
  - `_generate_random_ip()`: Create fake source IPs

#### `NetworkScanner`
Network reconnaissance tool:
- **Methods:**
  - `scan_subnet()`: Discover active hosts
  - `scan_ports()`: Find open ports
  - `identify_active_machines()`: Network mapping

#### `TrafficSniffer`
Packet capture and analysis:
- **Methods:**
  - `start_sniffing()`: Begin capture
  - `intercept_traffic()`: Get captured packets
  - `export_to_pcap()`: Save to file

#### `Host`
Represents a discovered network host:
- IP, MAC, hostname
- Open ports
- OS detection

---

### 3. **IDS Detection Package**
Contains all defender-side functionality.

**Classes:**

#### `NetworkDetector`
Main IDS engine that monitors network:
- **Methods:**
  - `start_monitoring()`: Begin packet sniffing
  - `_packet_handler()`: Process each packet
  - `_detect_arp_spoofing()`: Check for ARP attacks
  - `_detect_syn_flood()`: Check for SYN floods

#### `ARPAnomalyDetector`
Specialized ARP attack detection:
- **Methods:**
  - `detect_ip_mac_change()`: MAC address changed for IP
  - `detect_arp_flood()`: Excessive ARP traffic
  - `detect_gratuitous_arp()`: Suspicious ARP replies

#### `SYNAnomalyDetector`
Specialized SYN flood detection:
- **Methods:**
  - `detect_syn_flood()`: High SYN packet rate
  - `calculate_syn_rate()`: Packets per second
  - `detect_half_open_connections()`: Count SYN_RECV states

#### `AlertManager`
Alert generation and management:
- **Methods:**
  - `generate_alert()`: Create new alert
  - `get_recent_alerts()`: Fetch latest alerts
  - `send_notification()`: Notify administrators

#### `Alert`
Individual security alert:
- Alert type (ARP_SPOOFING, SYN_FLOOD)
- Severity (LOW, MEDIUM, HIGH, CRITICAL)
- Timestamp and details

#### `IDSConfiguration`
IDS settings management:
- **Methods:**
  - `set_threshold()`: Configure detection sensitivity
  - `enable_detector()`: Turn on specific detector
  - `save_configuration()`: Persist settings

#### `AttackBlocker`
Active defense mechanisms:
- **Methods:**
  - `block_ip()`: Firewall blocking
  - `send_rst_packet()`: Break TCP connections
  - `restore_arp_tables()`: Fix ARP poisoning
  - `update_firewall_rules()`: Apply iptables rules

---

### 4. **Utilities Package**
Helper classes used throughout the system.

**Classes:**

#### `Logger`
Centralized logging:
- Info, warning, error, debug levels
- File-based logging
- Colored console output

#### `NetworkUtils`
Network utility functions (static methods):
- `get_local_ip()`: Get machine's IP
- `get_gateway_ip()`: Find default gateway
- `get_mac()`: Resolve MAC from IP
- `enable_ip_forwarding()`: Enable packet forwarding

#### `ReportGenerator`
Create attack/detection reports:
- **Methods:**
  - `generate_attack_report()`: Attacker summary
  - `generate_detection_report()`: Defender summary
  - `export_to_pdf()`: PDF generation
  - `send_email_report()`: Email delivery

#### `Report`
Report data structure:
- Title, summary, details
- Charts and graphs
- Export formats (PDF, JSON)

---

### 5. **Web Interface Package**
Django views and web-related classes.

**Classes:**

#### `AttackerView`
Django views for attacker interface:
- **Endpoints:**
  - `attacker_dashboard()`: Main page
  - `start_arp_attack()`: POST /api/arp/start
  - `stop_arp_attack()`: POST /api/arp/stop
  - `start_syn_attack()`: POST /api/syn/start
  - `scan_network()`: POST /api/scan
  - `get_attack_statistics()`: GET /api/stats

#### `DefenderView`
Django views for defender interface:
- **Endpoints:**
  - `defender_dashboard()`: Main page
  - `get_alerts()`: GET /api/alerts
  - `configure_ids()`: POST /api/ids/config
  - `block_attack()`: POST /api/block
  - `view_logs()`: GET /api/logs
  - `export_report()`: GET /api/report

#### `AuthenticationView`
Login/logout handling:
- **Endpoints:**
  - `login_view()`: POST /login
  - `logout_view()`: GET /logout
  - `profile_view()`: GET /profile

#### `WebSocketHandler`
Real-time updates via WebSocket:
- **Methods:**
  - `send_alert()`: Push alert to browser
  - `send_statistics()`: Real-time stats
  - `broadcast_to_defenders()`: Notify all defenders

#### `AttackStatistics`
Real-time attack metrics:
- Packets sent
- Duration
- Target information

#### `DetectionStatistics`
Real-time detection metrics:
- Packets analyzed
- Alerts generated
- Uptime

---

### 6. **Database Models Package**
Django ORM models (database tables).

**Classes:**

#### `AttackLog`
Stores attack history:
- **Fields:**
  - user (ForeignKey)
  - attack_type (ARP/SYN)
  - target_ip
  - start_time, end_time
  - packets_sent
  - status (running/stopped/completed)

#### `DetectionLog`
Stores detection events:
- **Fields:**
  - alert_type
  - severity
  - source_ip, target_ip
  - detected_at
  - details (JSON field)
  - is_blocked

#### `Configuration`
Stores system settings:
- **Fields:**
  - key/value pairs
  - category (attack/defense/general)
  - description

---

## 🔗 Key Relationships

### Inheritance
```
BaseAttack
    ├── ARPSpoofer
    └── SYNFlooder
```

### Composition
```
NetworkDetector
    ├── uses → ARPAnomalyDetector
    ├── uses → SYNAnomalyDetector
    └── uses → AlertManager
```

### Aggregation
```
User "1" ── "0..*" AttackLog
User "1" ── "0..*" Session
AlertManager "1" ── "0..*" Alert
```

### Dependencies
```
AttackerView ..> ARPSpoofer (creates/controls)
DefenderView ..> NetworkDetector (monitors)
All modules ..> Logger (logging)
```

---

## 🎓 Design Patterns Used

1. **Abstract Factory Pattern**: `BaseAttack` for creating attack types
2. **Observer Pattern**: `WebSocketHandler` for real-time updates
3. **Singleton Pattern**: `Logger` (one logger per module)
4. **Strategy Pattern**: Different detectors (ARP, SYN)
5. **Facade Pattern**: Views provide simple interface to complex modules

---

## 📝 Class Diagram Summary

**Total Classes:** 30+

**By Package:**
- Authentication: 3 classes
- Attack Modules: 6 classes
- IDS Detection: 8 classes
- Utilities: 4 classes
- Web Interface: 6 classes
- Database Models: 3 classes

**Key Interfaces:**
- `BaseAttack`: All attacks inherit from this
- `WebSocketHandler`: Real-time communication
- Views: HTTP request handlers

---

## 🚀 How to Present This to Professor

**Talking Points:**

1. **Separation of Concerns**: Clear package separation
2. **SOLID Principles**: 
   - Single Responsibility (each class has one job)
   - Open/Closed (BaseAttack can be extended)
   - Interface Segregation (specific detector classes)

3. **Scalability**: Easy to add new attack types or detectors

4. **Security**: Role-based access control, session management

5. **Real-time**: WebSocket for live updates

---

**Generated:** December 10, 2025  
**Project:** IDS Cybersecurity Platform  
**Team:** Kaouther Ben Salah, Mohamed Firas Ben Hmida, Houssem Eddine Ben Chaabane
