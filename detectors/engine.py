import time
from collections import defaultdict
from .base_detector import BaseDetector


# detectors/engine.py

# Import all detector modules
from .port_scan import PortScanDetector
from .syn_flood import SynFloodDetector
from .suspicious_ports import SuspiciousPortsDetector


class DetectionEngine:
    """
    Central engine that runs all detection modules.

    This replaces the old monolithic detector.py.
    """

    def __init__(self, config_loader):
        self.config = config_loader.config

        # -------------------------
        # Initialize all detectors
        # -------------------------
        self.detectors = [
            PortScanDetector(self.config),
            SynFloodDetector(self.config),
            SuspiciousPortsDetector(self.config)
        ]

    def process_packet(self, packet):
        """
        Pass packet to all detectors and collect events
        """
        events = []

        for detector in self.detectors:
            result = detector.process_packet(packet)

            # Each detector can return:
            # - None
            # - a single event (dict)
            # - a list of events
            if result:
                if isinstance(result, list):
                    events.extend(result)
                else:
                    events.append(result)

        return events
