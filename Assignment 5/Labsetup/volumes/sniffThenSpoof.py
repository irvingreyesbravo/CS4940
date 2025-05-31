#!/usr/bin/env python3
from scapy.all import *

def sniff_then_spoof(pkt):
    target_ip = pkt.getlayer(IP)
    a = IP(src=target_ip.dst, dst=target_ip.src)
    target_icmp = pkt.getlayer(ICMP)
    b = ICMP(type="echo-reply", id=target_icmp.id, seq=target_icmp.seq)
    d = pkt[Raw].load
    s = a/b/d
    send(s)

pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=sniff_then_spoof)
