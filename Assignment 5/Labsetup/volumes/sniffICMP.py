#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '10.9.0.5'      # Host A
a.src = '128.230.0.22'      # Arbitrary Source
b = ICMP()
ls(a)
p = a/b
send(p)
