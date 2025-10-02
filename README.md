# simple-network-packet-sniffer

Simple network packet sniffer (educational).

**Warning:** Only sniff traffic on networks and hosts you own or have explicit permission to monitor.

## Quick tips
- On Linux/macOS you may need `sudo` (or run as root) to capture packets from interfaces.
- On Windows, install Npcap (https://nmap.org/npcap/) and run as Administrator.
- To analyze saved `.pcap`, open it in Wireshark.

## Requirements
- Python 3.7+
- [`scapy`](https://scapy.net/) Python package

Install Scapy:
```bash
pip install scapy
