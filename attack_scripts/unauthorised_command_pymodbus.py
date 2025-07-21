#!/usr/bin/env python3

from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('10.10.10.10', port=502)
client.connect()

client.write_register(address=1024, value=999)

client.close()

