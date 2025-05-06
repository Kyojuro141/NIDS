import re
import logging
from typing import Dict, List

# Setup logging for errors and alerts
logging.basicConfig(level=logging.INFO)
error_logger = logging.getLogger('error_logger')
alert_logger = logging.getLogger('alert_logger')
alert_logger.setLevel(logging.INFO)

# Create a console handler for alert logging
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
alert_logger.addHandler(handler)

# Constants for alert types
ALERT_TYPES = {
    "DOS": "DoS Attack",
    "SQL_INJECTION": "SQL Injection"
}

# Sample in-memory store for alerts
alerts: List[Dict[str, str]] = []

def log_attack(source_ip: str, destination_ip: str, alert_type: str, details: str = "") -> None:
    """Log detected attacks to the in-memory store and console."""
    alert = {
        'alertType': alert_type,
        'sourceIP': source_ip,
        'destinationIP': destination_ip,
        'details': details
    }
    alerts.append(alert)
    alert_logger.info(f"Alert: {alert_type} from {source_ip} to {destination_ip}. Details: {details}")

def detect_attacks(packet: Dict[str, str]) -> None:
    """Detect attacks in a given packet-like dictionary."""
    try:
        if packet.get('protocol') == 'TCP':
            flags = packet.get('flags', '')
            payload = packet.get('payload', '')
            src_ip = packet.get('src_ip', 'unknown')
            dst_ip = packet.get('dst_ip', 'unknown')

            # Detect DoS attack (SYN Flood detection)
            if flags == 'S':  # SYN packet
                log_attack(src_ip, dst_ip, ALERT_TYPES["DOS"])

            # Detect SQL Injection (simple regex)
            if payload and re.search(r"(SELECT|DROP|UNION|INSERT|DELETE).*", payload, re.IGNORECASE):
                log_attack(src_ip, dst_ip, ALERT_TYPES["SQL_INJECTION"], payload)
    except Exception as e:
        error_logger.error(f"Error detecting attacks: {e}")

def simulate_packet_sniffer() -> None:
    """Simulate receiving packets and processing them."""
    test_packets = [
        {'protocol': 'TCP', 'flags': 'S', 'src_ip': '192.168.1.10', 'dst_ip': '192.168.1.1', 'payload': ''},
        {'protocol': 'TCP', 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.1', 'payload': 'SELECT * FROM users WHERE id=1;'},
        {'protocol': 'TCP', 'flags': '', 'src_ip': '172.16.0.2', 'dst_ip': '172.16.0.1', 'payload': 'Hello World'},
    ]

    print("Starting simulated packet sniffer...")
    for pkt in test_packets:
        detect_attacks(pkt)
    print("Simulation complete.")

if __name__ == "__main__":
    simulate_packet_sniffer()
