# Network Packet Analyzer (NPA) – v1

A lightweight **Python-based network packet analyzer** that performs basic intrusion detection using live packet capture or PCAP file analysis.

This project was developed as part of a cybersecurity lab environment to demonstrate how network traffic can be captured, analyzed, and used to detect suspicious activity.

---

# Project Overview

The Network Packet Analyzer (NPA) captures network packets and analyzes them for potential malicious behaviour such as:

* Port scanning
* SYN flood attacks
* Connections to suspicious ports

The analyzer uses packet capture and rule-based detection logic to produce **structured JSON security events**.

---

# Features

* Live packet capture from a network interface
* Offline analysis using PCAP files
* Configurable detection thresholds
* JSON formatted security events
* Optional pretty-print output
* Modular detection engine

---

# Project Architecture

The tool is composed of four main components:

| Component          | Description                              |
| ------------------ | ---------------------------------------- |
| `capture.py`       | Handles packet capture using Scapy       |
| `detector.py`      | Detection engine that analyzes packets   |
| `config_loader.py` | Loads detection rules from `config.json` |
| `logger.py`        | Formats and outputs security events      |

Execution is handled by:

```
cli.py
```

Which acts as the command line interface for the analyzer.

---

# Detection Capabilities

## Port Scan Detection

Detects when a host connects to many different ports within a short time window.

Configurable parameters:

* Threshold
* Time window
* Severity level

---

## SYN Flood Detection

Detects excessive TCP SYN packets which may indicate a **denial of service attack**.

---

## Suspicious Port Detection

Alerts when traffic is detected on ports commonly associated with backdoors or insecure services.

Example suspicious ports:

* 21 (FTP)
* 23 (Telnet)
* 4444 (Common reverse shell port)

---

# Lab Environment

The project was tested in a **two-machine lab setup**:

| Machine    | Role                          |
| ---------- | ----------------------------- |
| Debian VM  | Network Packet Analyzer (IDS) |
| Kali Linux | Attack simulation             |

Both machines must be connected to the **same bridged network**.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/iammeechar/network-packet-analyzer.git
cd network-packet-analyzer
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate the environment:

Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Analyzer

⚠ Packet capture requires **root privileges**.

Start the analyzer using the virtual environment interpreter:

```bash
sudo .venv/bin/python cli.py --live --interface <interface> --config config.json --pretty
```

Example:

```bash
sudo .venv/bin/python cli.py --live --interface enp0s3 --config config.json --pretty
```

Stop the analyzer using:

```
CTRL + C
```

---

# PCAP Analysis Mode

The analyzer can also process recorded traffic:

```bash
python cli.py --pcap capture.pcap --config config.json --pretty
```

---

# Attack Simulation (Kali)

## Port Scan

```bash
nmap -p 1-1000 <IDS-IP>
```

---

## SYN Flood

```bash
sudo hping3 -S -p 80 --flood <IDS-IP>
```

---

## Suspicious Port Connection

```bash
nc <IDS-IP> 4444
```

---

# Example Detection Event

```json
{
  "timestamp": "2026-03-11T14:22:51",
  "event_type": "port_scan",
  "source_ip": "192.168.56.101",
  "severity": "medium"
}
```

---

# Configuration

Detection rules are stored in:

```
config.json
```

Example configuration parameters:

* detection thresholds
* time windows
* severity levels
* suspicious ports

---

# Requirements

* Python 3.10+
* Root privileges for packet capture
* Linux environment recommended

---

# Project Roadmap

Future improvements planned:

* Performance optimizations
* Additional detection rules
* Logging to SIEM-compatible formats
* Integration with security dashboards
* Machine learning anomaly detection

---

# Disclaimer

This project is for **educational and research purposes only**.

Do not use these tools on networks without proper authorization.

---

# Author

Aldo Micha Omondi 

# Lab Demonstration

Analyzer running:

[screenshot]

Port scan detection:

[screenshot]

SYN flood detection:

[screenshot]

Network Packet Analyzer – v1

                +------------------+
                |   config.json    |
                +------------------+
                          |
                          v
                +------------------+
                |  ConfigLoader    |
                |------------------|
                | Loads & validates|
                | Provides access  |
                +------------------+
                          |
            +-------------+--------------+
            |                            |
            v                            v
+--------------------+           +-------------------+
| PacketCapture      |           | DetectionEngine   |
|--------------------|           |------------------|
| Live capture (NIC) |           | Reads config      |
| OR PCAP file read  |--packet--> Processes packet |
| Yields packet dict |           | Detects events   |
+--------------------+           +------------------+
                                         |
                                         v
                                +------------------+
                                |   EventLogger    |
                                |------------------|
                                | Logs events to   |
                                | stdout or file  |
                                | (JSON, pretty)  |
                                +------------------+