Network Packet Analyzer & Mini-IDS – Version 3 (V3)
Status: Demonstration / Portfolio Ready
This project is a modular network packet analyzer and mini-intrusion detection system (IDS) built in Python. Version 3 (V3) represents a major refactor, introducing modular detection, trusted host filtering, and structured JSON alert output.

🚀 Overview
V3 builds on previous versions by improving code structure, detection accuracy, and maintainability:
Replaces monolithic detector.py with modular detectors:


PortScanDetector


SynFloodDetector


SuspiciousPortsDetector


Central DetectionEngine orchestrates all detector modules.


Filters packets from trusted hosts to reduce false positives.


Ignores broadcast, multicast, and malformed packets.


Outputs alerts in structured JSON, ready for logging or integration with external tools.


Optional debug tracing for development/testing.



⚙️ Features
Feature
Status
Notes
Port scan detection
✅
Configurable threshold and time window.
SYN flood detection
✅
Tracks SYN and ACK counts per source IP.
Suspicious ports detection
✅
Detects access to sensitive ports (e.g., 21, 22, 23, 25, 53).
Trusted host filtering
✅
Skips packets from IDS host(s) to avoid false positives.
Broadcast / multicast filtering
✅
Ignores packets not meant for a single host.
JSON alert output
✅
Consistent format for all events.
Optional debug/tracing
✅
Can be enabled for packet inspection.


⚙️ Configuration
Configuration is managed via config.json:
{
 "detection": {
   "port_scan": {
     "enabled": true,
     "threshold": 2,
     "time_window_seconds": 60,
     "severity": {"numeric": 3, "label": "medium"}
   },
   "syn_flood": {
     "enabled": true,
     "threshold": 10,
     "time_window_seconds": 10,
     "severity": {"numeric": 4, "label": "high"}
   },
   "suspicious_ports": {
     "enabled": true,
     "ports": [21, 22, 23, 25, 53],
     "severity": {"numeric": 2, "label": "low"}
   }
 },
 "trusted_hosts": ["192.168.100.77"], 
 "output": {"format": "json", "pretty_print": true, "file": "alerts.log"}
}
Note: trusted_hosts should include the IP of the IDS host itself to avoid self-detection.

🖥️ Setup & Usage
Clone the repository:


git clone <repository-url>
cd NPA_lab2
Install dependencies:


python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Run live packet capture:


sudo .venv/bin/python cli.py --live --interface enp0s3
Run from PCAP file:


sudo .venv/bin/python cli.py --pcap example.pcap
Output options:


--output-file <filename> → write events to a file


--pretty → pretty-print JSON output



📝 Example Output
{
 "event_type": "port_scan",
 "source_ip": "192.168.100.99",
 "destination_ip": "192.168.100.77",
 "ports_scanned": 2,
 "time_window_seconds": 60,
 "severity": "medium",
 "timestamp": "2026-03-18T08:04:44Z"
}
{
 "event_type": "suspicious_port",
 "source_ip": "192.168.100.99",
 "destination_ip": "192.168.100.77",
 "port": 22,
 "severity": "low",
 "timestamp": "2026-03-18T08:04:04Z"
}
{
 "event_type": "syn_flood",
 "source_ip": "192.168.100.99",
 "destination_ip": "192.168.100.77",
 "syn_count": 10,
 "ack_count": 0,
 "time_window_seconds": 10,
 "severity": "high",
 "timestamp": "2026-03-18T08:05:32Z"
}

⚠️ Notes / Limitations
Currently, only IP-based trusted host filtering is implemented.


Detection thresholds are set for demonstration; production use would require tuning.


Some external traffic (e.g., public internet hosts) may appear in results depending on network configuration.


Future improvements (V4) may include:


Brute-force detection


UDP/ICMP flood detection


Detection statistics


Modular plugin support for new detectors


Improved alert logging and notification



🏗️ Project Structure (V3)
NPA_lab2/
│
├── cli.py
├── config.json
├── capture.py
├── logger.py
├── detectors/
│   ├── __init__.py
│   ├── engine.py
│   ├── base_detector.py
│   ├── port_scan.py
│   ├── syn_flood.py
│   └── suspicious_ports.py
└── logs/

📌 Conclusion
Version 3 demonstrates:
Modular IDS design


JSON-based alert logging


Trusted host and broadcast filtering


Readiness for future expansion


This version is ideal for portfolio demonstration, showing structured network detection logic and a clear progression from V1/V2.

