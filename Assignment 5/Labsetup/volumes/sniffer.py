#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='br-70c34662f91e', filter='icmp', prn=print_pkt)
