Network Packet Analyzer v2 (NPA_lab2)
Project Overview

Description:
A Python-based network packet analyzer designed to detect suspicious network activity, including port scans, SYN floods, and access to suspicious ports. v2 extends the prototype (v1) with improved modularity, live capture, PCAP replay, and structured logging for portfolio demonstration.

Target Environment:

Debian VM (analyzer)

Kali Linux / Windows VM (attack simulation)

Metasploitable VM for vulnerability testing

Core Technologies:

Python 3.x

Scapy for packet capture

JSON configuration and structured logging

Requirements

Python 3.10+

scapy

argparse (standard library)

Root privileges for live capture or SYN flood simulation

VMs on the same subnet or bridged network

Setup Instructions

Clone the repository:

git clone <repo-url> NPA_lab2
cd NPA_lab2

Create and activate virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Adjust thresholds and ports in config.json if necessary.

Usage
Live Capture
sudo -E python3 cli.py --live --interface <interface-name> --config config.json --pretty
PCAP Replay
python3 cli.py --pcap sample.pcap --config config.json --pretty
Output

JSON formatted events, optionally written to a file:

--output-file events.json
Test Plan
Scenario	Target	Tool / Command	Expected Detection	Notes / Observations
Port Scan	Debian VM	nmap -p 1-1024 <Debian-IP>	port_scan event if ports scanned exceed threshold	Multiple ports needed to exceed threshold
SYN Flood	Debian VM	sudo hping3 -S -p 80 --flood <Debian-IP>	syn_flood event if SYN packets exceed threshold	Requires root; check cooldown
Suspicious Port	Debian VM	nc <Debian-IP> 21 / 23 / 4444	suspicious_port event	Logged per connection attempt
HTTP Traffic	Debian VM	curl http://<Debian-IP>	Logs port access (port 80)	v1 only logged port scans & SYN; test HTTP events
PCAP Replay	Analyzer VM	python cli.py --pcap sample.pcap	Same events as live capture	Offline detection test
Combined Attack	Debian + Metasploitable	Sequential scans, SYN floods, suspicious ports	Multiple events with varying severity	Observe handling of concurrent events
Logging Verification	Analyzer VM	Review JSON log	Events logged with timestamp, source IP, severity	Include screenshots for portfolio
Security Notes

Root privileges are required for raw socket access.

Always perform testing in isolated lab environments.

Threshold tuning prevents excessive false positives during testing.

Artifacts for Portfolio

JSON logs of all events.

Screenshots of live capture events.

Example PCAP replay events.

Configuration snapshots (config.json).

Next Steps

Expand detection rules for HTTP/HTTPS traffic and multi-layer threats.

Integrate alerts to a dashboard for SOC-like visualization.

Automate simulated attack sequences for reproducible testing.