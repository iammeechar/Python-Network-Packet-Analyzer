import time
from collections import defaultdict

class DetectionEngine:
    def __init__(self, config_loader):
        self.config = config_loader.config

        self.port_threshold = self.config["detection"]["port_scan"]["threshold"]
        self.port_window = self.config["detection"]["port_scan"]["time_window_seconds"]
        self.port_cooldown = self.config["detection"]["port_scan"].get("cooldown_seconds", 15)

        self.syn_threshold = self.config["detection"]["syn_flood"]["threshold"]
        self.syn_window = self.config["detection"]["syn_flood"]["time_window_seconds"]
        self.syn_cooldown = self.config["detection"]["syn_flood"].get("cooldown_seconds", 15)

        # Suspicious ports
        self.suspicious_ports = set(self.config["detection"]["suspicious_ports"]["ports"])

        # Tracking structures
        self.port_scan_tracker = defaultdict(dict)
        self.syn_tracker = defaultdict(dict)

        # Debug counters for live monitoring
        self.debug_counters = defaultdict(lambda: {"ports_seen": set(), "syn_count": 0})

    def process_packet(self, packet):
        """
        Accepts either a Scapy packet OR a dictionary with keys:
        src_ip, dst_ip, dst_port, flags
        """
        events = []

        # Determine if packet is a dict or Scapy object
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

        # Run detections
        port_event = self._detect_port_scan(src_ip, dst_ip, dst_port, now)
        syn_event = self._detect_syn_flood(src_ip, dst_ip, flags, now)
        sus_event = self._detect_suspicious_ports(src_ip, dst_ip, dst_port, now)

        if port_event:
            events.extend(port_event)
        if syn_event:
            events.extend(syn_event)
        if sus_event:
            events.append(sus_event)

        # ---- Debugging: print live counters ----
        self.debug_counters[src_ip]["ports_seen"].add(dst_port)
        if flags == "S":
            self.debug_counters[src_ip]["syn_count"] += 1

        print(f"[DEBUG] {src_ip} → Ports Seen: {len(self.debug_counters[src_ip]['ports_seen'])}, "
              f"SYN Count: {self.debug_counters[src_ip]['syn_count']}", flush=True)

        return events

    # -------------------------
    # Port Scan Detection
    # -------------------------
    def _detect_port_scan(self, src_ip, dst_ip, dst_port, now):
        record = self.port_scan_tracker[src_ip]

        if not record:
            record["window_start"] = now
            record["ports"] = set()
            record["cooldown_until"] = 0

        # Window expired → reset
        if now - record["window_start"] > self.port_window:
            record["window_start"] = now
            record["ports"] = set()

        record["ports"].add(dst_port)

        # Cooldown active?
        if now < record["cooldown_until"]:
            return None

        if len(record["ports"]) >= self.port_threshold:
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
            record["window_start"] = now
            record["ports"] = set()
            return [event]

        return None

    # -------------------------
    # SYN Flood Detection
    # -------------------------
    def _detect_syn_flood(self, src_ip, dst_ip, flags, now):
        record = self.syn_tracker[src_ip]

        if not record:
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0
            record["cooldown_until"] = 0

        if now - record["window_start"] > self.syn_window:
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0

        # Track SYN (S flag without ACK)
        if flags == "S":
            record["syn_count"] += 1

        # Track ACK
        if "A" in str(flags):
            record["ack_count"] += 1

        if now < record["cooldown_until"]:
            return None

        if record["syn_count"] >= self.syn_threshold:
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
            record["window_start"] = now
            record["syn_count"] = 0
            record["ack_count"] = 0
            return [event]

        return None

    # -------------------------
    # Suspicious Ports
    # -------------------------
    def _detect_suspicious_ports(self, src_ip, dst_ip, dst_port, now):
        if dst_port in self.suspicious_ports:
            return {
                "event_type": "suspicious_port",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "port": dst_port,
                "severity": self.config["detection"]["suspicious_ports"]["severity"]["label"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            }
        return None
