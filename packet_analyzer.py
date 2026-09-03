#!/usr/bin/env python3
"""
Network Packet Analyzer
------------------------
CodSoft Cyber Security Internship - Task 1

Captures live network packets, extracts key details (source IP,
destination IP, protocol, and payload info), and displays / logs
them in a clean, organized format.

Requires: scapy  (pip install scapy)
Requires: root/administrator privileges to sniff packets.

Usage:
    sudo python3 packet_analyzer.py                 # sniff on default interface
    sudo python3 packet_analyzer.py -i eth0          # sniff on a specific interface
    sudo python3 packet_analyzer.py -c 50            # stop after 50 packets
    sudo python3 packet_analyzer.py --demo           # run without root/network (sample data)
"""

import argparse
import csv
import datetime
import os
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG_FILE = "captured_packets.csv"

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def init_log_file():
    """Create the CSV log file with headers if it doesn't already exist."""
    file_exists = os.path.isfile(LOG_FILE)
    if not file_exists:
        with open(LOG_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Timestamp", "Source IP", "Destination IP", "Protocol",
                 "Src Port", "Dst Port", "Length", "Payload Preview"]
            )


def log_packet(row):
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def print_packet_row(row):
    """Print a single packet's details in an aligned, readable table row."""
    timestamp, src_ip, dst_ip, proto, sport, dport, length, payload = row
    print(
        f"{timestamp:<12} | {src_ip:<15} -> {dst_ip:<15} | "
        f"{proto:<5} | {str(sport):<6}->{str(dport):<6} | "
        f"{str(length):<5} | {payload}"
    )


def print_header():
    header = (
        f"{'Time':<12} | {'Source IP':<15}    {'Destination IP':<15} | "
        f"{'Proto':<5} | {'Ports':<13} | {'Len':<5} | Payload Preview"
    )
    print(header)
    print("-" * len(header))


def extract_packet_info(packet):
    """Pull the relevant fields out of a captured Scapy packet."""
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    proto_num = ip_layer.proto
    proto_name = PROTOCOL_MAP.get(proto_num, str(proto_num))

    src_port, dst_port = "-", "-"
    if TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    payload_preview = "-"
    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        # Show a short, safe preview of the payload only
        preview = raw_bytes[:24]
        payload_preview = preview.decode(errors="replace").replace("\n", " ").replace("\r", "")

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    return [
        timestamp,
        ip_layer.src,
        ip_layer.dst,
        proto_name,
        src_port,
        dst_port,
        len(packet),
        payload_preview,
    ]


def handle_packet(packet):
    row = extract_packet_info(packet)
    if row is None:
        return
    print_packet_row(row)
    log_packet(row)


def run_demo():
    """
    Demo mode: simulates captured packet data so the tool's output and
    logging format can be seen/tested without root privileges or a live
    network interface (useful for grading/review in a sandboxed environment).
    """
    print("Running in DEMO mode (no live capture, no root required)\n")
    init_log_file()
    print_header()

    sample_packets = [
        ["10:15:01", "192.168.1.5", "142.250.72.14", "TCP", 51422, 443, 74, "TLS handshake"],
        ["10:15:02", "192.168.1.5", "8.8.8.8", "UDP", 55891, 53, 64, "DNS query example.com"],
        ["10:15:03", "142.250.72.14", "192.168.1.5", "TCP", 443, 51422, 1420, "HTTP/2 200 OK"],
        ["10:15:04", "192.168.1.5", "192.168.1.1", "ICMP", "-", "-", 98, "Echo request"],
        ["10:15:05", "192.168.1.1", "192.168.1.5", "ICMP", "-", "-", 98, "Echo reply"],
    ]

    for row in sample_packets:
        row[0] = datetime.datetime.now().strftime("%H:%M:%S")
        print_packet_row(row)
        log_packet(row)

    print(f"\nDemo complete. {len(sample_packets)} sample packets logged to '{LOG_FILE}'.")


def run_live_capture(interface, count):
    if not SCAPY_AVAILABLE:
        print("Error: scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    if os.name != "nt" and os.geteuid() != 0:
        print("Error: live packet capture requires root privileges.")
        print("Try: sudo python3 packet_analyzer.py")
        print("Or run without privileges using: python3 packet_analyzer.py --demo")
        sys.exit(1)

    init_log_file()
    print_header()
    print(f"Sniffing on interface: {interface or 'default'} "
          f"(count={'unlimited' if count == 0 else count}) -- Ctrl+C to stop\n")

    try:
        sniff(iface=interface, prn=handle_packet, count=count, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    print(f"\nCaptured packets saved to '{LOG_FILE}'.")


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (e.g. eth0, wlan0). "
                              "Defaults to scapy's chosen interface.")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = unlimited).")
    parser.add_argument("--demo", action="store_true",
                         help="Run in demo mode with sample data (no root/network needed).")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        run_live_capture(args.interface, args.count)


if __name__ == "__main__":
    main()
