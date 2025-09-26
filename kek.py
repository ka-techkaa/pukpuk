from scapy.all import * 
k = sniff(count=3)
k.summary()