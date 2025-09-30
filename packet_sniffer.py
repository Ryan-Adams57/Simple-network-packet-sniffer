#!/usr/bin/env python3
"""
packet_sniffer.py
Simple educational packet sniffer using Scapy.

Usage:
  # Install dependency: pip install scapy
  sudo python3 packet_sniffer.py          # sniff default interface, print summaries
  sudo python3 packet_sniffer.py -i eth0  # sniff specific interface
  sudo python3 packet_sniffer.py -c 100   # capture 100 packets then exit
  sudo python3 packet_sniffer.py -w out.pcap  # save to pcap

WARNING: Only sniff traffic on networks and hosts you own or have explicit permission to monitor.
"""

import argparse
from scapy.all import sniff, wrpcap, conf

def packet_callback(pkt):
    # Print a one-line summary
    try:
        print(pkt.summary())
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Simple packet sniffer (educational)")
    parser.add_argument("-i", "--iface", help="Interface to sniff (default: scapy's default)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 = unlimited)", default=0)
    parser.add_argument("-w", "--write", help="Write captured packets to pcap file", default=None)
    args = parser.parse_args()

    if args.iface:
        conf.iface = args.iface

    print("== Simple Packet Sniffer ==")
    print("Interface:", conf.iface)
    print("Press Ctrl-C to stop.\n")

    captured = []
    try:
        if args.count > 0:
            packets = sniff(count=args.count, prn=packet_callback, store=True)
            captured = packets
        else:
            packets = sniff(prn=packet_callback, store=True)
            captured = packets
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied — try running as root/administrator.")
        return

    if args.write and captured:
        try:
            wrpcap(args.write, captured)
            print(f"Saved {len(captured)} packets to {args.write}")
        except Exception as e:
            print("Failed to write pcap:", e)

    print("Done.")

if __name__ == "__main__":
    main()
