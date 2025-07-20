#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.modbus import *

print("C Write with Abnormal Value...")
abnormal_val_packet = IP(src="10.10.20.30", dst="10.10.10.10") / \
                      TCP(sport=RandShort(), dport=502) / \
                      ModbusADURequest(transId=104, unitId=1) / \
                      ModbusPDU06WriteSingleRegisterRequest(startAddr=1024, registerVal=999)

print("Sending packet with value 000")
send(abnormal_val_packet, verbose=0)
print("Packet sent with abnormal value 999 to control register 1024.")
print("____________________________________________________")
