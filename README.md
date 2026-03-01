<div align="center">

# 🛡️  Experimental SOC— Intelligent Security Event Detection & Correlation

**A fully virtualized Security Operations Center built from scratch**

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM%2FHIDS-00A1E0?style=for-the-badge&logo=wazuh&logoColor=white)](https://wazuh.com)
[![Snort](https://img.shields.io/badge/Snort-IDS%20Network-CC0000?style=for-the-badge&logoColor=white)](https://snort.org)
[![PfSense](https://img.shields.io/badge/PfSense-Firewall-003366?style=for-the-badge&logoColor=white)](https://pfsense.org)
[![VMware](https://img.shields.io/badge/VMware-Virtualization-607078?style=for-the-badge&logo=vmware&logoColor=white)](https://vmware.com)
[![Flask](https://img.shields.io/badge/Flask-Web%20UI-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)

<br/>

> *"Detection alone is not enough — correlation, prevention, and automation are the pillars of a modern SOC."*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Lab Environment](#-lab-environment)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [Attack Simulations](#-attack-simulations)
- [Correlation Engine](#-correlation-engine)
- [PfSense Firewall (Active Defense)](#-pfsense-firewall-active-defense)
- [Results & Validation](#-results--validation)
- [Screenshots](#-screenshots)
- [Authors](#-authors)

---

## 🔍 Overview

This project implements a **fully functional experimental SOC** (Security Operations Center) in a virtualized environment, designed to simulate realistic cybersecurity scenarios in a controlled and reproducible lab.

The system covers the complete SOC lifecycle:

| Phase | Description |
|-------|-------------|
| 🔴 **Attack Simulation** | Controlled generation of ICMP, HTTP, SSH, and TCP scan traffic via Python scripts |
| 🟡 **Detection** | Real-time network intrusion detection (Snort) + host-based analysis (Wazuh) |
| 🟠 **Correlation** | Python-powered multi-source event correlation engine with Flask dashboard |
| 🟢 **Prevention** | Active firewall countermeasures using PfSense with strict WAN filtering rules |

---

## 🏗️ Architecture

### Detection-Oriented Architecture (Phase 1)

```
┌─────────────────────────────────────────────────────────┐
│                    10.10.10.0/24 - Lab Network           │
│                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────── │
│   │   Attacker   │───▶│    Victim    │◀───│  SOC        │
│   │ 10.10.10.128 │    │ 10.10.10.129 │    │ 10.10.10.130│
│   │              │    │  Nginx + SSH │    │ Snort+Wazuh │
│   │ Python Script│    │  Wazuh Agent │    │ Flask UI    │
│   └──────────────┘    └──────────────┘    └─────────────│
└─────────────────────────────────────────────────────────┘
```

### Prevention-Oriented Architecture (Phase 2 — with PfSense)

```
┌─────────────────────────────────────────────────────────────────┐
│  WAN - 192.168.1.0/24          LAN - 10.10.10.0/24             │
│                                                                  │
│  ┌────────────┐    ┌──────────────────┐    ┌──────────────────┐ │
│  │  Attacker  │───▶│    pfSense FW    │───▶│  Victim Server   │ │
│  │192.168.1.128│   │  BLOCK ICMP/SSH  │    │  10.10.10.129    │ │
│  └────────────┘    │  BLOCK HTTP(80)  │    └──────────────────┘ │
│                    │  192.168.1.135   │    ┌──────────────────┐ │
│                    └──────────────────┘    │  SOC Monitoring  │ │
│                                            │  10.10.10.139    │ │
│                                            └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Lab Environment

### Virtual Machines

| Machine | IP Address | Role | Services |
|---------|-----------|------|----------|
| **SOC** | `10.10.10.130` | Supervision & Analysis | Wazuh Manager, Snort IDS, Flask Correlation Engine |
| **Victim** | `10.10.10.129` | Attack Target | Nginx (HTTP), SSH, Wazuh Agent |
| **Attacker** | `10.10.10.128` | Attack Simulation | Python Attack Scripts, Nmap |
| **PfSense** | `192.168.1.135` (WAN) / `10.10.10.10` (LAN) | Firewall | Packet Filtering, NAT |

### Network Configuration

```
Each VM uses dual interfaces:
  Interface 1 (NAT)       → Internet access
  Interface 2 (Host-Only) → Internal lab network (10.10.10.0/24)
```

**Why Host-Only?** Complete isolation from the real network, full traffic control, reproducible environment, and optimal for IDS testing.

---

## ✨ Features

### 🔴 Attack Simulation (Python)

A Flask-powered web interface running on the Attacker machine with 4 attack modules:

- **ICMP PING BURST** — Sends ICMP echo requests to trigger reconnaissance alerts
- **HTTP BURST** — Floods Nginx with 40 rapid GET requests to trigger rate-limit rules
- **SSH FAILED LOGINS** — Uses `paramiko` to generate authentication failure events
- **MINI TCP SCAN** — Probes ports 22, 80, 443, 21, 25 using raw sockets

### 🟡 Intrusion Detection (Snort + Wazuh)

**Snort** — 4 custom rules in `/etc/snort/rules/local.rules`:

```snort
# ICMP Detection
alert icmp any any -> $HOME_NET any (msg:"SOC ALERT - ICMP ping detected"; sid:1000003; rev:1;)

# HTTP Burst Detection (20 requests / 60 sec)
alert tcp any any -> $HOME_NET 80 (msg:"SOC ALERT - HTTP traffic burst detected"; threshold:type both, track by_src, count 20, seconds 60; sid:1000001; rev:1;)

# SSH Rate Detection (10 attempts / 60 sec)
alert tcp any any -> $HOME_NET 22 (msg:"SOC ALERT - SSH rate abnormal"; threshold:type both, track by_src, count 10, seconds 60; sid:1000002; rev:1;)

# Nmap SYN Scan Detection (10 SYN / 5 sec)
alert tcp any any -> $HOME_NET any (msg:"SOC ALERT - NMAP scan detected SYN"; flags:S; threshold:type both, track by_src, count 10, seconds 5; sid:1000004; rev:1;)
```

**Wazuh** — Host-based detection covering:
- SSH authentication failures (`/var/log/auth.log`)
- Web access analysis (`/var/log/nginx/access.log`)
- System integrity and privilege escalation

### 🟠 Correlation Engine (Python + Flask)

A custom Python script runs as a mini SOC engine on the SOC machine:

- Parses Snort fast-alert logs
- Parses Wazuh JSON alerts
- Correlates events by **source IP** and **time window**
- Calculates a **threat score** = Snort Events + Wazuh Events
- Displays results in a real-time **web dashboard**
- Exports a **timestamped HTML report**

**Threat Levels:**

| Score | Level |
|-------|-------|
| ≥ 50 | 🔴 CRITICAL |
| 30–49 | 🟠 HIGH |
| 10–29 | 🟡 MEDIUM |
| < 10 | 🟢 LOW |

### 🟢 Active Prevention (PfSense Firewall)

WAN firewall rules blocking attacks from the attacker machine:

| Protocol | Source | Destination | Action |
|----------|--------|-------------|--------|
| ICMP | ATTACKER alias | VICTIM alias | ❌ BLOCK |
| TCP port 80 (HTTP) | ATTACKER alias | VICTIM alias | ❌ BLOCK |
| TCP port 22 (SSH) | ATTACKER alias | VICTIM alias | ❌ BLOCK |

---

## 🛠️ Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Virtualization | VMware Workstation | Latest |
| OS | Ubuntu Server | 22.04 LTS |
| SIEM / HIDS | Wazuh | 4.14.x |
| Network IDS | Snort | 2.x |
| Firewall | pfSense Community Edition | 2.8.1 |
| Backend | Python 3 + Flask | 3.x |
| HTTP Simulation | `requests` | — |
| SSH Simulation | `paramiko` | — |
| ICMP Simulation | `subprocess` (ping) | — |
| TCP Scan | `socket` | — |
| Web Server (Victim) | Nginx | Latest |

---

## 🚀 Setup & Installation

### Prerequisites

- VMware Workstation (or VirtualBox)
- Ubuntu Server 22.04 ISO
- pfSense 2.8.1 ISO
- Python 3.x

### 1. SOC Machine — Install Wazuh

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Download and run Wazuh installer (all-in-one: Manager + Indexer + Dashboard)
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Verify all services are running
sudo systemctl list-unit-files | grep wazuh
```

Access the dashboard at: `https://<SOC_IP>:443`

### 2. Victim Machine — Install Wazuh Agent

```bash
# Download agent package
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.2-1_amd64.deb

# Install with manager configuration
sudo WAZUH_MANAGER='10.10.10.130' WAZUH_AGENT_NAME='ubuntu_machine_victime' \
     dpkg -i ./wazuh-agent_4.14.2-1_amd64.deb

# Enable and start agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 3. SOC Machine — Install & Configure Snort

```bash
# Install Snort
sudo apt install snort -y

# Configure HOME_NET
sudo nano /etc/snort/snort.conf
# Set: ipvar HOME_NET 10.10.10.0/24

# Add custom rules
sudo nano /etc/snort/rules/local.rules
# (paste rules from snort-config/local.rules)

# Enable Snort as a service
sudo systemctl enable snort
sudo systemctl start snort
```

### 4. Victim Machine — Setup Services

```bash
# Install and verify Nginx
sudo apt install nginx -y
systemctl status nginx

# Verify SSH
systemctl status ssh

# Monitor logs in real-time
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/auth.log
```

### 5. Attacker Machine — Run Attack Simulator

```bash
cd attack-simulator/
pip install flask requests paramiko
python3 soc_attack_sim.py
```

Access the attack UI at: `http://<ATTACKER_IP>:5000`

### 6. SOC Machine — Run Correlation Engine

```bash
cd correlation-script/
pip install flask
python3 correlation_snort_wazuh.py
```

Access the SOC correlation dashboard at: `http://<SOC_IP>:5001`

---

## ⚔️ Attack Simulations

### ICMP Ping Burst

```bash
# Manual test from attacker
ping 10.10.10.129

# Check Snort detection
sudo tail -f /var/log/snort/snort.alert.fast
```

### HTTP Flood

```bash
# Manual test (25 requests)
for i in {1..25}; do curl http://10.10.10.129; done
```

### SSH Brute Force

```bash
# Manual test (repeat multiple times to trigger threshold)
ssh fakeuser@10.10.10.129
```

### Network Scan

```bash
# Nmap SYN scan
nmap -sS 10.10.10.129
```

### Validation Results

| Simulation | Snort Detection | Wazuh Detection | Status |
|------------|:--------------:|:---------------:|:------:|
| ICMP Burst | ✅ | ❌ | ✅ OK |
| HTTP Flood | ✅ | ✅ | ✅ OK |
| SSH Failed Logins | ✅ | ✅ | ✅ OK |
| TCP Recon Scan | ✅ | ❌ | ✅ OK |

---

## 🔗 Correlation Engine

The correlation engine cross-references **Snort network alerts** with **Wazuh host events** to identify critical incidents:

```
Snort Alerts (/var/log/snort/snort.alert.fast)
         +
Wazuh Events (/var/ossec/logs/alerts/alerts.json)
         │
         ▼
    Group by Source IP
         │
         ▼
    Compute Threat Score = Snort_count + Wazuh_count
         │
         ▼
    Classify: CRITICAL / HIGH / MEDIUM / LOW
         │
         ▼
    Flask Dashboard + Export HTML Report
```

**Example output from a real test session:**

| Source IP | Snort Events | Wazuh Events | Correlation Score | Threat Level |
|-----------|:------------:|:------------:|:-----------------:|:------------:|
| 10.10.10.128 | 15 | 64 | 79 | 🔴 CRITICAL |
| 10.10.10.129 | 15 | 64 | 79 | 🔴 CRITICAL |
| 10.10.10.254 | 1 | 40 | 41 | 🟠 HIGH |

---

## 🔥 PfSense Firewall (Active Defense)

### Routing Configuration

```bash
# On Victim machine — set pfSense as default gateway
sudo ip route add default via 10.10.10.10

# Verify
ip route
```

### Firewall Aliases

| Alias | IP Address | Description |
|-------|-----------|-------------|
| `ATTACKER` | `192.168.1.128` | Attack simulation machine |
| `VICTIM` | `10.10.10.129` | Protected server |

### WAN Rules (Top-Down Order)

```
[BLOCK] ICMP    ATTACKER → VICTIM   (Stop ping reconnaissance)
[BLOCK] TCP:80  ATTACKER → VICTIM   (Block HTTP access)
[BLOCK] TCP:22  ATTACKER → VICTIM   (Block SSH access)
[ALLOW] *       *        → *        (Default allow — demo only)
```

### Validation — Before/After PfSense

| Attack | Without PfSense | With PfSense |
|--------|:--------------:|:------------:|
| ICMP ping | ✅ Reaches victim | ❌ 100% blocked |
| HTTP request | ✅ Reaches Nginx | ❌ 100% blocked |
| SSH connection | ✅ Reaches SSH | ❌ 100% blocked |
| TCP port scan | All ports visible | All ports FILTERED |

---

## 📊 Results & Validation

The complete SOC pipeline was validated end-to-end:

1. **Attack generated** on Attacker machine (Python/manual)
2. **Network alert** triggered in Snort (`snort.alert.fast`)
3. **Host event** captured by Wazuh agent → forwarded to SOC
4. **Correlation script** groups events by IP, scores them
5. **Dashboard** displays CRITICAL/HIGH threat levels in real-time
6. **HTML report** auto-exported with timestamps and statistics

**Wazuh Dashboard — Final Session Stats:**
- Total alerts: 112
- Authentication failures: 56
- Authentication successes: 19
- Top groups: `syslog`, `pam`, `authentication_failed`, `sshd`, `invalid_login`

---

## 📸 Screenshots

> *Screenshots available in the `/docs/screenshots/` folder*

| Component | Description |
|-----------|-------------|
| `wazuh_dashboard.png` | Wazuh overview with agent summary and alert severity breakdown |
| `snort_alerts.png` | Real-time Snort alert log showing ICMP, HTTP, SSH, Nmap detections |
| `attack_simulator_ui.png` | Flask-based attack control panel with 4 attack modules |
| `correlation_dashboard.png` | SOC Correlation Lab — Snort & Wazuh integration dashboard |
| `pfsense_rules.png` | PfSense WAN firewall rules blocking ICMP, SSH, HTTP |
| `pfsense_blocked.png` | Attack results after firewall — all ports CLOSED/FILTERED |

---

## 📚 What's in This Repo

```
✅ Python attack simulation scripts (ICMP, HTTP, SSH, TCP scan)
✅ Python correlation engine (Snort + Wazuh integration)
✅ Custom Snort rules (local.rules)
✅ Wazuh agent configuration
✅ PfSense firewall rules export
✅ Full project documentation (PDF report)
✅ Architecture diagrams
```

---


This project was developed as part of the **M113A — Python for AI & Cybersecurity** course at:

**École Supérieure de Technologie — Université Hassan II de Casablanca**
Bachelor CISIA — Cybersécurité, Ingénierie des Systèmes et Intelligence Artificielle

**Academic Year:** 2025 – 2026

<div align="center">
[![EST](https://img.shields.io/badge/EST-Université%20Hassan%20II-003087?style=for-the-badge)](https://est.uh2c.ma)
[![CISIA](https://img.shields.io/badge/Bachelor-CISIA-CC0000?style=for-the-badge)](https://est.uh2c.ma)

</div>
