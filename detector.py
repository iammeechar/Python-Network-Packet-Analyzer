import time
from collections import defaultdict


class DetectionEngine:
    """
    Network intrusion detection engine for v2.
    Detects:
      - Port scans
      - SYN floods
      - Suspicious ports
    """

    def __init__(self, config_loader):
        self.config = config_loader.config

        # -------------------------
        # Port scan thresholds
        # -------------------------
        self.port_threshold = self.config["detection"]["port_scan"]["threshold"]
        self.port_window = self.config["detection"]["port_scan"]["time_window_seconds"]
        self.port_cooldown = self.config["detection"]["port_scan"].get("cooldown_seconds", 15)

        # -------------------------
        # SYN flood thresholds
        # -------------------------
        self.syn_threshold = self.config["detection"]["syn_flood"]["threshold"]
        self.syn_window = self.config["detection"]["syn_flood"]["time_window_seconds"]
        self.syn_cooldown = self.config["detection"]["syn_flood"].get("cooldown_seconds", 15)

        # -------------------------
        # Suspicious ports
        # -------------------------
        self.suspicious_ports = set(self.config["detection"]["suspicious_ports"]["ports"])

        # -------------------------
        # Tracking structures
        # -------------------------
        # FIX: use defaultdict with lambda to initialize records properly.
        #      This ensures first packet has correct keys, avoiding missing events.
        self.port_scan_tracker = defaultdict(
            lambda: {"window_start": 0, "ports": set(), "cooldown_until": 0}
        )
        self.syn_tracker = defaultdict(
            lambda: {"window_start": 0, "syn_count": 0, "ack_count": 0, "cooldown_until": 0}
        )

        # Debug counters for live monitoring
        self.debug_counters = defaultdict(lambda: {"ports_seen": set(), "syn_count": 0})

    # -------------------------
    # Main packet processing
    # -------------------------
    def process_packet(self, packet):
        """
        Accepts a Scapy packet or a dictionary:
          source_ip, dest_ip, dest_port, flags
        Returns a list of detected events (may be empty).
        """

        events = []

        # Extract fields from dict or Scapy object
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

        now = time.time()

        # -------------------------
        # Run detections
        # -------------------------
        port_event = self._detect_port_scan(src_ip, dst_ip, dst_port, now)
        syn_event = self._detect_syn_flood(src_ip, dst_ip, flags, now)
        sus_event = self._detect_suspicious_ports(src_ip, dst_ip, dst_port, now)

        # Append only non-None events
        if port_event:
            events.append(port_event)
        if syn_event:
            events.append(syn_event)
        if sus_event:
            events.append(sus_event)

        # -------------------------
        # Debug output (optional)
        # -------------------------
        self.debug_counters[src_ip]["ports_seen"].add(dst_port)
        if flags == "S":
            self.debug_counters[src_ip]["syn_count"] += 1

        print(
            f"[DEBUG] {src_ip} → Ports Seen: {len(self.debug_counters[src_ip]['ports_seen'])}, "
            f"SYN Count: {self.debug_counters[src_ip]['syn_count']}",
            flush=True
        )

        return events

    # -------------------------
    # Port Scan Detection
    # -------------------------
    def _detect_port_scan(self, src_ip, dst_ip, dst_port, now):
        """
        Detect multiple ports scanned by same IP within a time window.
        Returns a port_scan event dict or None.
        """
        record = self.port_scan_tracker[src_ip]

        # Window expired → reset
        if now - record["window_start"] > self.port_window:
            record["window_start"] = now
            record["ports"] = set()

        record["ports"].add(dst_port)

        # Cooldown active → skip
        if now < record["cooldown_until"]:
            return None

        if len(record["ports"]) >= self.port_threshold:
            # Event triggered
            event = {
                "event_type": "port_scan",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "ports_scanned": len(record["ports"]),
                "time_window_seconds": self.port_window,
                "severity": "medium",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }
            record["cooldown_until"] = now + self.port_cooldown
            # Reset ports after reporting
            record["ports"] = set()
            record["window_start"] = now
            return event
        print(f"[DEBUG] _detect_port_scan {src_ip} → ports: {record['ports']}")

        return None

    # -------------------------
    # SYN Flood Detection
    # -------------------------
    def _detect_syn_flood(self, src_ip, dst_ip, flags, now):
        """
        Detect SYN floods based on SYN packets count in a time window.
        Returns a syn_flood event dict or None.
        """
        record = self.syn_tracker[src_ip]

        # Window expired → reset counters
        if now - record["window_start"] > self.syn_window:
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0

        # Track SYN (S flag without ACK)
        if flags == "S":
            record["syn_count"] += 1

        # Track ACK packets
        if "A" in str(flags):
            record["ack_count"] += 1

        # Cooldown active → skip
        if now < record["cooldown_until"]:
            return None

        if record["syn_count"] >= self.syn_threshold:
            # Event triggered
            event = {
                "event_type": "syn_flood",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "syn_count": record["syn_count"],
                "ack_count": record["ack_count"],
                "time_window_seconds": self.syn_window,
                "severity": "high",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }
            record["cooldown_until"] = now + self.syn_cooldown
            # Reset counters
            record["syn_count"] = 0
            record["ack_count"] = 0
            record["window_start"] = now
            return event

        return None

    # -------------------------
    # Suspicious Ports Detection
    # -------------------------
    def _detect_suspicious_ports(self, src_ip, dst_ip, dst_port, now):
        """
        Detect packets sent to known suspicious ports.
        Returns a suspicious_port event dict or None.
        """
        if dst_port in self.suspicious_ports:
            return {
                "event_type": "suspicious_port",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "port": dst_port,
                "severity": self.config["detection"]["suspicious_ports"]["severity"]["label"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }
        print(f"[DEBUG] _detect_suspicious_ports {dst_port}")
        return None
