#! /usr/bin/env python3

from pymodbus.client import ModbusTcpClient
import time

client = ModbusTcpClient('10.10.10.10', port=502)
client.connect()

for _ in range(3):
    client.write_register(address=1024, value=500)
    time.sleep(0.4)  # mimic close-timed replay

client.close()

