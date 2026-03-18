import argparse
import os
import json
import sys
from logging.handlers import RotatingFileHandler
import logging

from config_loader import ConfigLoader
from capture import PacketCapture
from detectors.engine import DetectionEngine
from logger import EventLogger

# -------------------------
# Setup logs folder and file
# -------------------------
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
os.makedirs(LOG_DIR, exist_ok=True)

# Rotating file logging
logger = logging.getLogger("packet_analyzer")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
logger.addHandler(handler)


# -------------------------
# Event logging function
# -------------------------
def log_event(event):
    """
    Logs each detection event as a JSON line to the alerts.log file
    """
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


# -------------------------
# Main CLI function
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="CLI-based Network Packet Analyzer (V3)")
    
    # Mode: live capture or PCAP analysis
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Capture packets live from a network interface")
    group.add_argument("--pcap", type=str, help="Analyze packets from a PCAP file")
    
    parser.add_argument("--interface", type=str, help="Network interface for live capture")
    parser.add_argument("--config", type=str, default="config.json", help="Path to JSON configuration file")
    parser.add_argument("--output-file", type=str, help="Write events to a separate file instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    
    args = parser.parse_args()

    # -------------------------
    # Load configuration
    # -------------------------
    try:
        config_loader = ConfigLoader(config_path=args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        sys.exit(1)

    # -------------------------
    # Initialize detection engine
    # -------------------------
    engine = DetectionEngine(config_loader)

    # -------------------------
    # Initialize packet capture
    # -------------------------
    if args.live:
        if not args.interface:
            print("Live capture requires --interface", file=sys.stderr)
            sys.exit(1)
        capture = PacketCapture(interface=args.interface)
    else:
        capture = PacketCapture(pcap_file=args.pcap)

    # -------------------------
    # Initialize event logger (optional output file)
    # -------------------------
    event_logger = EventLogger(output_file=args.output_file, pretty=args.pretty)

    # -------------------------
    # Process packets
    # -------------------------
    try:
        for packet in capture.capture():
            events = engine.process_packet(packet)
            for event in events:
                if event is None:
                    continue

                # Print JSON output
                if args.pretty:
                    print(json.dumps(event, indent=4))
                else:
                    print(json.dumps(event))

                # Log to alerts.log
                log_event(event)

    except KeyboardInterrupt:
        print("\nCapture interrupted by user", file=sys.stderr)
    finally:
        event_logger.close()


# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    main()
