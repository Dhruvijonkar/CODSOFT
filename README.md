# Network Packet Analyzer

CodSoft Cyber Security Internship — Task 1

A Python-based network packet analyzer that captures live traffic, extracts key details (source IP, destination IP, protocol, ports, length, payload preview), and displays them in an organized format — both in the terminal and logged to a CSV file.

## Features
- Live packet capture using Scapy
- Extracts source/destination IP, protocol, ports, length, payload preview
- Clean table output in terminal
- Logs all captured packets to captured_packets.csv
- Demo mode (--demo) for testing without admin rights or live network

## Requirements
- Python 3.8+
- Scapy (pip install scapy)
- Administrator privileges for live capture

## Usage
Demo mode: python packet_analyzer.py --demo
Live capture: python packet_analyzer.py -c 20
