import time
import ipaddress
from .base_detector import BaseDetector
from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector
from .suspicious_ports import SuspiciousPortsDetector


class DetectionEngine:
    """
    Central IDS engine that runs all detectors.
    - Returns events in JSON format.
    - Filters packets from/to trusted hosts.
    """

    def __init__(self, config_loader):
        self.config = config_loader.config

        # Initialize all detectors
        self.detectors = [
            PortScanDetector(self.config),
            SynFloodDetector(self.config),
            SuspiciousPortsDetector(self.config)
        ]

        # Trusted hosts (skip detection for these IPs)
        self.trusted_hosts = set(self.config.get("trusted_hosts", []))

    def process_packet(self, packet):
        events = []

        # Extract fields from dict or Scapy packet
        if isinstance(packet, dict):
            src_ip = packet.get("source_ip")
            dst_ip = packet.get("dest_ip")
            dst_port = packet.get("dest_port")
            flags = packet.get("flags", "")
        else:
            try:
                if not packet.haslayer("IP") or not packet.haslayer("TCP"):
                    return events
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                dst_port = packet["TCP"].dport
                flags = packet["TCP"].flags
            except Exception:
                return events

        # --- Filter packets from trusted IDS hosts ---
        if src_ip in self.trusted_hosts:
            return []

        # --- Filter broadcast / multicast / reserved IPs ---
        try:
            dst_ip_obj = ipaddress.ip_address(dst_ip)
            if dst_ip_obj.is_multicast or dst_ip_obj.is_reserved:
                return []
        except ValueError:
            # Malformed IP, skip packet
            return []

        now = time.time()

        # Run all detection modules
        for detector in self.detectors:
            result = detector.process_packet(packet)
            if result:
                events.append(result)

        return events
