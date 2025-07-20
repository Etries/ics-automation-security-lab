#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.modbus import *

unauth_ip_packet = IP(src="10.10.20.100", dst="10.10.10.10") / \
                   TCP(sport=RandShort(), dport=502) / \
                   ModbusADURequest(transId=101, unitId=1) / \
                   ModbusPDU06WriteSingleRegisterRequest(startAddr=1024, registerVal=100)

print("Sending packet...")
send(unauth_ip_packet, verbose=0)
print("Packet sent from unauthorized IP 10.10.20.100.")
