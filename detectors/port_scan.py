# detectors/port_scan.py

import time
from collections import defaultdict
from .base_detector import BaseDetector


class PortScanDetector(BaseDetector):
    """
    Detects port scanning behavior based on number of unique ports accessed
    """

    def __init__(self, config):
        super().__init__(config)

        # -------------------------
        # Load configuration
        # -------------------------
        scan_config = config["detection"]["port_scan"]

        self.threshold = scan_config["threshold"]
        self.time_window = scan_config["time_window_seconds"]
        self.cooldown = scan_config.get("cooldown_seconds", 15)

        # -------------------------
        # Tracking structure
        # -------------------------
        self.tracker = defaultdict(
            lambda: {
                "window_start": 0,
                "ports": set(),
                "cooldown_until": 0
            }
        )

    def process_packet(self, packet):
        """
        Detect port scan activity
        """

        # -------------------------
        # Extract packet data
        # -------------------------
        if isinstance(packet, dict):
            src_ip = packet.get("source_ip")
            dst_ip = packet.get("dest_ip")
            dst_port = packet.get("dest_port")
        else:
            try:
                if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                    return None
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                dst_port = packet["TCP"].dport
            except Exception:
                return None

        now = time.time()
        record = self.tracker[src_ip]

        # -------------------------
        # Reset window if expired
        # -------------------------
        if now - record["window_start"] > self.time_window:
            record["window_start"] = now
            record["ports"] = set()

        # Track unique ports
        record["ports"].add(dst_port)

        # -------------------------
        # Cooldown check
        # -------------------------
        if now < record["cooldown_until"]:
            return None

        # -------------------------
        # Detection logic
        # -------------------------
        if len(record["ports"]) >= self.threshold:
            event = {
                "event_type": "port_scan",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "ports_scanned": len(record["ports"]),
                "time_window_seconds": self.time_window,
                "severity": "medium",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }

            # Reset after detection
            record["cooldown_until"] = now + self.cooldown
            record["window_start"] = now
            record["ports"] = set()

            return event

        return None
