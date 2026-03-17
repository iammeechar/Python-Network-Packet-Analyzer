# detectors/syn_flood.py

import time
from collections import defaultdict
from .base_detector import BaseDetector


class SynFloodDetector(BaseDetector):
    """
    Detects SYN flood attacks based on SYN packet rate
    """

    def __init__(self, config):
        super().__init__(config)

        # -------------------------
        # Load configuration
        # -------------------------
        syn_config = config["detection"]["syn_flood"]

        self.threshold = syn_config["threshold"]
        self.time_window = syn_config["time_window_seconds"]
        self.cooldown = syn_config.get("cooldown_seconds", 15)

        # -------------------------
        # Tracking structure
        # -------------------------
        self.tracker = defaultdict(
            lambda: {
                "window_start": 0,
                "syn_count": 0,
                "ack_count": 0,
                "cooldown_until": 0
            }
        )

    def process_packet(self, packet):
        """
        Process incoming packet and detect SYN flood
        """

        # -------------------------
        # Extract packet data
        # -------------------------
        if isinstance(packet, dict):
            src_ip = packet.get("source_ip")
            dst_ip = packet.get("dest_ip")
            flags = packet.get("flags", "")
        else:
            try:
                if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                    return None
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                flags = packet["TCP"].flags
            except Exception:
                return None

        now = time.time()
        record = self.tracker[src_ip]

        # -------------------------
        # Reset window if expired
        # -------------------------
        if now - record["window_start"] > self.time_window:
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0

        # -------------------------
        # Count SYN / ACK packets
        # -------------------------
        if flags == "S":
            record["syn_count"] += 1

        if "A" in str(flags):
            record["ack_count"] += 1

        # -------------------------
        # Cooldown check
        # -------------------------
        if now < record["cooldown_until"]:
            return None

        # -------------------------
        # Detection logic
        # -------------------------
        if record["syn_count"] >= self.threshold:
            event = {
                "event_type": "syn_flood",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "syn_count": record["syn_count"],
                "ack_count": record["ack_count"],
                "time_window_seconds": self.time_window,
                "severity": "high",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }

            # Reset after detection
            record["cooldown_until"] = now + self.cooldown
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0

            return event

        return None
