# IDS Platform - Use Case Analysis

## 📊 System Overview

**Educational Cybersecurity Platform** - A Flask-based network intrusion detection system demonstrating attack simulation and defense mechanisms in a controlled lab environment.

---

## 👥 Actors

### 1. **Attacker**
- Role: Adversary launching network attacks
- Authentication: Required (username/password login)
- Objective: Simulate network attacks (ARP spoofing, SYN flood, port scanning)

### 2. **Defender**
- Role: Security analyst monitoring and defending the network
- Authentication: Required (username/password login)
- Objective: Detect attacks, view alerts, block malicious IPs

### 3. **System**
- Role: Automated detection and response engine
- Objective: Monitor traffic, identify attacks, generate alerts, enforce blocks

---

## 🎯 Use Cases by Category

### **Category 1: Authentication & Session Management**
| Use Case | Actor | Description |
|----------|-------|-------------|
| Login | Attacker, Defender | Authenticate user and establish session |
| Logout | Attacker, Defender | End user session and cleanup |

---

### **Category 2: Attacker Operations**

#### **2.1 Reconnaissance**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Perform Network Scan | `/api/scan/start`, `/api/scan/results/<id>` | Scan network to discover active hosts and services |
| Get Network Interfaces | `/api/scan/interfaces` | List available network interfaces |
| Get Network Information | `/api/network/info` | Retrieve local IP, gateway, and network details |
| View Attack Statistics | `/api/attack/stats` | Monitor ongoing attack metrics |

#### **2.2 Attack Execution**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Launch ARP Spoofing | `/api/attack/arp/start` | Start ARP cache poisoning attack |
| Stop ARP Spoofing | `/api/attack/arp/stop` | Terminate ARP spoofing |
| Launch SYN Flood | `/api/attack/syn/start` | Start SYN flood denial-of-service attack |
| Stop SYN Flood | `/api/attack/syn/stop` | Terminate SYN flood |

#### **2.3 Network Analysis**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Start Packet Sniffing | `/api/sniff/start` | Begin capturing network traffic |
| Stop Packet Sniffing | `/api/sniff/stop` | End packet capture |
| Retrieve Sniffed Packets | `/api/sniff/packets/<id>` | Get captured packet details |

---

### **Category 3: Defender Operations**

#### **3.1 IDS Control**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Start IDS Monitor | `/api/ids/start` | Activate intrusion detection system |
| Stop IDS Monitor | `/api/ids/stop` | Deactivate IDS |
| Check IDS Status | `/api/ids/status` | Query current IDS state and metrics |

#### **3.2 Network Discovery & Monitoring**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Discover Network Nodes | `/api/ids/discover` | Identify hosts and services on network |
| Get IDS Overview | `/api/ids/overview` | Display network inventory and statistics |

#### **3.3 Alert Management**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| View Live Alerts | UI Dashboard | Real-time stream of security alerts |
| Acknowledge Alert | `/api/ids/alerts/<id>/ack` | Mark alert as reviewed |

#### **3.4 Response & Blocking**
| Use Case | Endpoint | Description |
|----------|----------|-------------|
| Block Malicious IP | `/api/ids/block` | Add IP to firewall blocklist |
| View Blocked IPs | UI Dashboard | List of currently blocked IPs |

---

### **Category 4: System Operations (Automated)**

| Use Case | Detection Mechanism | Description |
|----------|-------------------|-------------|
| Detect ARP Spoofing | MAC address changes | Identifies ARP cache poisoning attacks |
| Detect SYN Flood | Packet rate analysis | Detects 150+ SYN packets from 15+ sources in 10s window |
| Detect Port Scan | Service enumeration | Identifies 10+ ports scanned in 10s window |
| Identify Attacker Machine | Port scan history + ARP table | Correlates attacks with source IP on local network |
| Generate Alerts | Multi-detector correlation | Creates actionable security alerts |
| Log Events | Event recorder | Persists all detection and action events |

---

## 🔄 Use Case Flows

### **Flow 1: Attack Lifecycle**
```
Attacker
  ├─> Login
  ├─> Get Network Info (reconnaissance)
  ├─> Perform Network Scan (find targets)
  ├─> [System detects port scan]
  ├─> Launch ARP Spoofing / SYN Flood
  ├─> [System detects attack, identifies attacker]
  ├─> System generates alert
  └─> [Alert reaches Defender]
```

### **Flow 2: Defense Lifecycle**
```
Defender
  ├─> Login
  ├─> Start IDS Monitor
  ├─> Discover Network Nodes
  ├─> Get IDS Overview (baseline)
  ├─> Monitor View Live Alerts (passive)
  ├─> Receive Attack Alert
  ├─> Acknowledge Alert
  ├─> Review Attacker IP from Alert
  ├─> Block Malicious IP
  ├─> [Firewall rules applied]
  ├─> View Blocked IPs (verify)
  └─> Stop IDS Monitor (when done)
```

### **Flow 3: Detection & Response**
```
System (Continuous)
  ├─> Monitor network traffic
  ├─> Detect anomalies:
  │   ├─ ARP spoofing patterns
  │   ├─ SYN flood signatures
  │   └─ Port scan behavior
  ├─> Correlate with port scan history
  ├─> Identify local attacker machine
  ├─> Generate alert with:
  │   ├─ Attack type
  │   ├─ Target IP
  │   ├─ Attacker IP (local)
  │   ├─ Spoofed sources (if applicable)
  │   └─ Timestamp
  ├─> Log event
  └─> Make alert available to Defender UI
```

---

## 📋 Key Attack Detection Thresholds

| Attack Type | Detection Threshold | Window | Accuracy |
|------------|-------------------|--------|----------|
| **ARP Spoofing** | MAC address change from same IP | Real-time | High |
| **SYN Flood** | 150+ packets from 15+ sources | 10 seconds | High |
| **Port Scan** | 10+ unique ports probed | 10 seconds | Medium |
| **Attacker Identification** | Port scan history + ARP table | Historical | High |

---

## 🔐 Role-Based Access Control

| Operation | Attacker | Defender | Public |
|-----------|----------|----------|--------|
| Network Scan | ✅ | ❌ | ❌ |
| Launch Attacks | ✅ | ❌ | ❌ |
| Packet Sniffing | ✅ | ❌ | ❌ |
| Start/Stop IDS | ❌ | ✅ | ❌ |
| View Alerts | ❌ | ✅ | ❌ |
| Block IPs | ❌ | ✅ | ❌ |
| View Statistics | ✅ | ✅ | ❌ |

---

## 📊 Data Flow Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER INTERFACE                       │
│  Scan → Discover → Attack (ARP/SYN) → Sniff                │
└────────────────────┬────────────────────────────────────────┘
                     │ Network Traffic
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              SYSTEM DETECTION ENGINE                         │
│  Packet Capture → Analysis → Detection → Correlation        │
│  ↓                                                            │
│  Generate Alerts → Identify Attacker → Log Events           │
└────────────────────┬────────────────────────────────────────┘
                     │ Alerts
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  DEFENDER INTERFACE                          │
│  View Alerts → Acknowledge → Block IP → Monitor Results     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎓 Educational Learning Outcomes

This system demonstrates:

1. **Network Security Concepts**
   - ARP protocol vulnerabilities
   - TCP/IP stack exploitation
   - Network reconnaissance techniques

2. **Intrusion Detection Principles**
   - Anomaly detection
   - Signature-based detection
   - Real-time monitoring

3. **Incident Response**
   - Alert generation and management
   - Forensic analysis
   - Automated response (blocking)

4. **System Architecture**
   - Client-server communication
   - Role-based access control
   - Multi-threaded operations

---

## ⚠️ Important Notes

- **Educational Use Only**: This platform is designed for authorized lab environments
- **CVSS Scope**: Demonstrates actual network attacks in isolated environment
- **Requires**: Linux machines (Kali, Ubuntu) with Scapy library
- **Disclaimer**: Unauthorized use of attack tools is illegal
