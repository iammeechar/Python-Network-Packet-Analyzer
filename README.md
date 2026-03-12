# Python Network Packet Analyzer (v1)
# Overview

The Python Network Packet Analyzer (NPA) is a lightweight network monitoring tool designed to detect basic network attack patterns in real time.

The analyzer captures live network packets and applies rule-based detection logic to identify:

Port scanning activity

SYN flood attacks

Connections to suspicious ports

The goal of this project is to demonstrate how basic intrusion detection logic can be implemented in Python using packet inspection.

This project is the prototype (v1) of a larger security lab where more advanced detection and attack simulations will be added in future versions.

# Features

Live packet capture

Port scan detection

SYN flood detection

Suspicious port detection

JSON formatted security alerts

Real-time console output

Modular detection engine 

# Project Structure

The project is organized into modular components to separate packet capture, detection logic, and execution.

Python-Network-Packet-Analyzer/
│
├── main.py              # Entry point for the analyzer
├── capture.py           # Packet capture and parsing logic
├── detection_engine.py  # Detection algorithms
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation
└── .venv/               # Python virtual environment 

# Component Responsibilities
File	Responsibility
main.py	Starts the analyzer and processes packets
capture.py	Captures and parses network packets
detection_engine.py	Implements attack detection logic
Configuration

Detection thresholds are configurable within the detection engine.

Example parameters:

Parameter	Purpose	Example
port_threshold	Number of unique ports required to trigger a scan alert	5
port_window	Time window used for port scan detection	60 seconds
syn_threshold	Number of SYN packets required to trigger SYN flood alert	10
syn_window	Time window for SYN detection	10 seconds

These values can be adjusted to tune detection sensitivity.

# Example Analyzer Output

When malicious activity is detected, the analyzer generates structured JSON events.

Example:

{
  "event_type": "port_scan",
  "source_ip": "192.168.100.99",
  "destination_ip": "192.168.100.77",
  "ports_scanned": 21,
  "time_window_seconds": 60,
  "severity": "medium",
  "timestamp": "2026-03-12T16:48:26Z"
}

Example SYN flood detection:

{
  "event_type": "syn_flood",
  "source_ip": "192.168.100.99",
  "destination_ip": "192.168.100.77",
  "syn_count": 10,
  "ack_count": 0,
  "time_window_seconds": 10,
  "severity": "high",
  "timestamp": "2026-03-12T16:48:04Z"
}
# Contributing

Contributions are welcome.

Potential improvements include:

Additional intrusion detection rules

Log file output

Alerting integrations

Performance optimization

Visualization dashboards

# License

This project is intended for educational and research purposes.

Users are responsible for ensuring the tool is used only in authorized environments.

# Technology Stack
Component	Technology
Programming Language	Python 3
Packet Capture	Scapy
Environment	Linux
Testing Tools	Nmap, hping3, tcpdump

# Installation
Clone the repository
git clone https://github.com/iammeechar/Python-Network-Packet-Analyzer.git
cd Python-Network-Packet-Analyzer

Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

Install dependencies
pip install -r requirements.txt
# Running the Analyzer

Run the analyzer with administrative privileges so it can capture packets.

sudo python main.py

The analyzer will begin monitoring live traffic and print detection events to the console.

Example output:

{
 "event_type": "port_scan",
 "source_ip": "192.168.100.99",
 "destination_ip": "192.168.100.77",
 "ports_scanned": 21,
 "time_window_seconds": 60,
 "severity": "medium"
}

# Detection Logic
# Port Scan Detection

Tracks the number of unique destination ports accessed by a source IP within a time window.

If the number exceeds a configured threshold, a port scan event is triggered.

# SYN Flood Detection

Counts SYN packets from a source IP and compares them with completed connections.

If SYN packets exceed the configured threshold within the time window, a SYN flood alert is generated.

# Suspicious Port Detection

Traffic targeting known high-risk ports is flagged immediately.

Examples include:

Telnet (23)

FTP (21)

# Lab Environment

Testing was performed in a virtual lab environment.

Machine	Role
Kali Linux	Attack simulation
Debian	Packet analyzer host

Both machines were configured on the same subnet to allow direct packet observation.

# Testing and Validation

The following commands were used to validate detection functionality.

Test Type	Command	Purpose	Expected Result
Network connectivity	ping 192.168.100.77	Verify network connectivity	No alert
Port connectivity	nc -zv 192.168.100.77 22	Test port reachability	No alert
Basic port scan	nmap 192.168.100.77	Generate scanning traffic	Port scan alert
Expanded port scan	nmap -p 1-100 192.168.100.77	Scan multiple ports	Port scan alert
Repeated scans	Run scan multiple times	Test detection thresholds	Multiple alerts
SYN flood simulation	hping3 -S --flood -p 80 192.168.100.77	Simulate DoS attack	SYN flood alert
Controlled SYN packets	hping3 -S -p 80 -c 20 192.168.100.77	Limited SYN test	SYN flood alert
Suspicious port scan	nmap -p 23 192.168.100.77	Test Telnet detection	Suspicious port alert
HTTP request	curl http://192.168.100.77	Generate normal traffic	No alert
Packet Capture Validation

To verify that packets were visible to the analyzer, traffic was monitored using:

sudo tcpdump -i eth0

Example output during a port scan:

192.168.100.99.37222 > 192.168.100.77.33: Flags [S]
192.168.100.77.33 > 192.168.100.99.37222: Flags [R.]

This confirms that the scanner sends SYN packets to multiple ports, which the analyzer uses to detect scanning behavior.

# Bug Fixes and Improvements

During testing, a packet parsing issue prevented reliable port scan detection.

The issue was resolved by improving packet parsing logic in capture.py, ensuring that packets are converted into a consistent dictionary format before being processed by the detection engine.

Updated packet fields include:

source_ip

dest_ip

dest_port

flags

This fix improved detection accuracy and stabilized the analyzer during live capture.

# Limitations

This prototype focuses on demonstrating basic IDS concepts and has several limitations:

Limited attack detection signatures

No persistent logging

No graphical interface

No traffic classification

These improvements will be introduced in v2.

# Future Work (v2)

Planned improvements include:

Expanded attack simulations

Additional detection rules

Persistent event logging

Integration with vulnerable lab machines

Improved detection tuning

Educational Purpose

This project was developed as part of a network security learning lab to explore:

Packet capture

Intrusion detection techniques

Network attack simulation

Security tool development in Python

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