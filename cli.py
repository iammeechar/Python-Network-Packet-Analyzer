import argparse
import os
import json
import sys
import logging
from logging.handlers import RotatingFileHandler
from config_loader import ConfigLoader
from capture import PacketCapture
from detector import DetectionEngine
from logger import EventLogger

# -------------------------
# Logging setup
# -------------------------
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("packet_analyzer")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1000000, backupCount=3)
logger.addHandler(handler)


# -------------------------
# Event logging function
# -------------------------
def log_event(event):
    """Append event as JSON to log file"""
    log_file = os.path.join(LOG_DIR, "alerts.log")
    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")


# -------------------------
# Main CLI function
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="CLI-based Network Packet Analyzer (v1)")
    
    # Mode selection: live capture or PCAP file
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Capture packets live from network interface")
    group.add_argument("--pcap", type=str, help="Analyze packets from a PCAP file")

    # Interface for live capture
    parser.add_argument("--interface", type=str, help="Network interface for live capture")

    # Configuration file path
    parser.add_argument("--config", type=str, default="config.json", help="Path to JSON configuration file")

    # Output options
    parser.add_argument("--output-file", type=str, help="Write events to a file instead of stdout")
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
    # Initialize Detection Engine
    # -------------------------
    engine = DetectionEngine(config_loader)

    # -------------------------
    # Initialize Packet Capture
    # -------------------------
    if args.live:
        if not args.interface:
            print("Live capture requires --interface", file=sys.stderr)
            sys.exit(1)
        capture = PacketCapture(interface=args.interface)
    else:
        capture = PacketCapture(pcap_file=args.pcap)

    # -------------------------
    # Initialize Event Logger
    # -------------------------
    event_logger = EventLogger(output_file=args.output_file, pretty=args.pretty)

    # -------------------------
    # Main packet processing loop
    # -------------------------
    try:
        for packet in capture.capture():
            events = engine.process_packet(packet)

            # Each detection returns dicts or None
            for event in events:
                if event is None:
                    continue

                # Optional: pretty-print JSON to stdout
                if args.pretty:
                    print(json.dumps(event, indent=4))
                else:
                    print(json.dumps(event))

                # Log to file
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
