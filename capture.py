from scapy.all import sniff, rdpcap
from typing import Dict, Any, Generator
import os

class PacketCapture:
    """
    PacketCapture handles both live network capture and PCAP file reading.

    It yields parsed packet dictionaries compatible with DetectionEngine.
    """

    def __init__(self, interface: str = None, pcap_file: str = None):
        """
        Initialize the capture layer.

        Args:
            interface: Name of network interface for live capture (e.g., "eth0").
            pcap_file: Path to PCAP file for offline analysis.
        """
        self.interface = interface
        self.pcap_file = pcap_file

        if not self.interface and not self.pcap_file:
            raise ValueError("Either 'interface' or 'pcap_file' must be provided.")

        if self.pcap_file and not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")

    def capture(self) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields packets as dictionaries.

        Yields:
            Dict with keys: source_ip, dest_ip, dest_port, flags
        """
        if self.pcap_file:
            yield from self._read_pcap()
        else:
            yield from self._live_capture()

    def _read_pcap(self) -> Generator[Dict[str, Any], None, None]:
        """
        Read packets from a PCAP file.
        """
        packets = rdpcap(self.pcap_file)
        for pkt in packets:
            parsed = self._parse_packet(pkt)
            if parsed:
                yield parsed

    def _live_capture(self):
        def packet_generator():
            while True:
                packets = sniff(iface=self.interface, count=1)
                for pkt in packets:
                    parsed = self._parse_packet(pkt)
                    if parsed:
                        yield parsed

        yield from packet_generator()

    def _parse_packet(self, pkt) -> Dict[str, Any]:
        """
        Parse a Scapy packet into a dictionary compatible with DetectionEngine.

        For v1, we only extract basic fields: source IP, destination IP, destination port, flags.

        Returns:
            Dictionary or None if packet is not TCP/UDP
        """
        try:
            if pkt.haslayer("IP") and pkt.haslayer("TCP"):
                ip_layer = pkt["IP"]
                tcp_layer = pkt["TCP"]

                # Normalize service port
                if tcp_layer.dport < 1024:
                    port = tcp_layer.dport
                else:
                    port = tcp_layer.sport

                return {
                    "source_ip": ip_layer.src,
                    "dest_ip": ip_layer.dst,
                    "dest_port": port,
                    "flags": tcp_layer.flags
    }
            elif pkt.haslayer("IP") and pkt.haslayer("UDP"):
                ip_layer = pkt["IP"]
                udp_layer = pkt["UDP"]
                return {
                    "source_ip": ip_layer.src,
                    "dest_ip": ip_layer.dst,
                    "dest_port": udp_layer.dport,
                    "flags": None
                }
            else:
                return None
        except Exception:
            # Skip malformed packets
            return None


# Example usage for testing
if __name__ == "__main__":
    # Example: PCAP mode
    pcap_path = "example.pcap"  # Replace with actual file
    if os.path.exists(pcap_path):
        cap = PacketCapture(pcap_file=pcap_path)
        for pkt in cap.capture():
            print(pkt)
    else:
        print("No example.pcap file found. Please supply a PCAP file.")