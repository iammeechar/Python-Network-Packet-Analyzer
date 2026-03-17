# detectors/suspicious_ports.py

import time
from .base_detector import BaseDetector


class SuspiciousPortsDetector(BaseDetector):
    """
    Detects traffic to suspicious/high-risk ports
    """

    def __init__(self, config):
        super().__init__(config)

        # -------------------------
        # Load configuration
        # -------------------------
        port_config = config["detection"]["suspicious_ports"]

        self.suspicious_ports = set(port_config["ports"])
        self.severity = port_config["severity"]["label"]

    def process_packet(self, packet):
        """
        Detect access to suspicious ports
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

        # -------------------------
        # Detection logic
        # -------------------------
        if dst_port in self.suspicious_ports:
            return {
                "event_type": "suspicious_port",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "port": dst_port,
                "severity": self.severity,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }

        return None
