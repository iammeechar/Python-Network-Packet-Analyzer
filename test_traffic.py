from scapy.all import IP, TCP, send
import time

# === Configurable parameters ===
LOOPBACK = "127.0.0.1"
PORT_SCAN_PORTS = [22, 23, 80, 443, 8080]
SYN_FLOOD_PORT = 80
SUSPICIOUS_PORTS = [21, 23, 4444]  # matches your config.json

# === Helper functions ===
def generate_port_scan():
    print("Generating port scan...")
    for port in PORT_SCAN_PORTS:
        pkt = IP(dst=LOOPBACK)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)  # small delay to simulate scanning

def generate_syn_flood(count=20):
    print("Generating SYN flood...")
    for _ in range(count):
        pkt = IP(dst=LOOPBACK)/TCP(dport=SYN_FLOOD_PORT, flags="S")
        send(pkt, verbose=False)

def generate_suspicious_ports():
    print("Generating traffic to suspicious ports...")
    for port in SUSPICIOUS_PORTS:
        pkt = IP(dst=LOOPBACK)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)

# === Run all tests sequentially ===
if __name__ == "__main__":
    generate_port_scan()
    time.sleep(1)
    generate_syn_flood()
    time.sleep(1)
    generate_suspicious_ports()
    print("Test traffic generation complete.")