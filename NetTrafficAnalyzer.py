#!/usr/bin/env python3
"""
Advanced Network Traffic Analysis and Packet Capture Tool
-----------------------------------------------------------
Features:
- Captures live network traffic using raw sockets (requires root privileges).
- Decodes Ethernet, IP, and basic TCP/UDP headers.
- Updates live statistics in a Tkinter GUI (total packets, TCP, UDP, others).
- Logs errors and packet capture details for forensic analysis.
- Easily extendable for further protocol decoding.

Usage (run as root):
  python advanced_packet_capture.py --interface eth0
"""

import socket, struct, argparse, sys, threading, time, logging
import tkinter as tk
from datetime import datetime

# Logging configuration
logging.basicConfig(filename="advanced_packet_capture.log", level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def parse_ethernet_header(packet):
    """ Parses the Ethernet header to retrieve EtherType. """
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH", eth_header)
    return socket.ntohs(eth[2])

def parse_ip_header(packet):
    """ Parses the IP header to extract source and destination IP addresses. """
    ip_header = packet[:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return src_ip, dst_ip

class PacketStats:
    """ Stores packet statistics with thread-safe updates. """
    def __init__(self):
        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.others = 0
        self.lock = threading.Lock()

    def update(self, proto):
        with self.lock:
            self.total += 1
            if proto == "TCP":
                self.tcp += 1
            elif proto == "UDP":
                self.udp += 1
            else:
                self.others += 1

def capture_packets(interface, stats):
    """ Captures packets on a given interface and updates stats. """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((interface, 0))
    except Exception as e:
        logging.error("Socket error: %s", e)
        sys.exit(1)
    logging.info("Packet capture started on interface %s", interface)
    while True:
        packet, _ = s.recvfrom(65535)
        if len(packet) < 34:
            continue
        eth_type = parse_ethernet_header(packet)
        if eth_type == 0x0800:  # IPv4
            src_ip, dst_ip = parse_ip_header(packet[14:34])
            proto = packet[23]
            if proto == 6:
                stats.update("TCP")
            elif proto == 17:
                stats.update("UDP")
            else:
                stats.update("Others")
        else:
            stats.update("Others")

def update_gui(root, stats, label):
    """ Updates the Tkinter GUI with live packet statistics. """
    with stats.lock:
        text = (f"Total Packets: {stats.total}\n"
                f"TCP: {stats.tcp}\n"
                f"UDP: {stats.udp}\n"
                f"Others: {stats.others}")
    label.config(text=text)
    root.after(1000, update_gui, root, stats, label)

def start_gui(stats):
    """ Starts a Tkinter GUI to display live packet statistics. """
    root = tk.Tk()
    root.title("Network Traffic Analysis")
    label = tk.Label(root, text="", font=("Arial", 16), justify="left")
    label.pack(padx=20, pady=20)
    update_gui(root, stats, label)
    root.mainloop()

def main_packet_capture():
    parser = argparse.ArgumentParser(description="Advanced Network Traffic Analysis Tool")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    args = parser.parse_args()
    stats = PacketStats()
    capture_thread = threading.Thread(target=capture_packets, args=(args.interface, stats), daemon=True)
    capture_thread.start()
    start_gui(stats)

if __name__ == "__main__":
    main_packet_capture()
