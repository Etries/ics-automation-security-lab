#!/usr/bin/env python3

import time
from pymodbus.client import ModbusTcpClient

PLC_IP = '10.10.10.10'  # Update as needed
PLC_PORT = 502

# Modbus register/coil addresses
ADDR_MW0 = 1024      # Command register (HR)
ADDR_STATUS_OUT = 102 # State (HR)
ADDR_TANK_LEVEL = 100 # Tank level (IR)
ADDR_ALARM = 0       # Alarm (DI)
ADDR_MIXING_DONE = 804 # Mixing done (Coil)

COMMANDS = {
    'start': 500,
    'pause': 100,
    'resume': 400,
    'emergency': 200,
    'reset': 300
}

STATE_MAP = {
    0: 'Idle',
    1: 'Filling',
    2: 'Mixing',
    3: 'Draining',
    4: 'Paused',
    5: 'Emergency Held'
}

def send_command(client, code):
    client.write_register(ADDR_MW0, code)
    print(f"[HMI] Sent command code {code}")
    time.sleep(1)
    client.write_register(ADDR_MW0, 0)  # Clear command


def poll_status(client):
    # Read state
    state = client.read_holding_registers(ADDR_STATUS_OUT, 1).registers[0]
    # Read tank level
    tank_level = client.read_input_registers(ADDR_TANK_LEVEL, 1).registers[0]
    # Read alarm
    alarm = client.read_discrete_inputs(ADDR_ALARM, 1).bits[0]
    # Read mixing done
    mixing_done = client.read_coils(ADDR_MIXING_DONE, 1).bits[0]
    print(f"[HMI] State: {STATE_MAP.get(state, state)} | Tank Level: {tank_level} | Alarm: {alarm} | Mixing Done: {mixing_done}")


def main():
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    if not client.connect():
        print("[HMI] Could not connect to PLC!")
        return
    print("[HMI] Connected to PLC.")
    try:
        while True:
            print("\nCommands: start, pause, resume, emergency, reset, status, exit")
            cmd = input("Enter command: ").strip().lower()
            if cmd in COMMANDS:
                send_command(client, COMMANDS[cmd])
            elif cmd == 'status':
                poll_status(client)
            elif cmd == 'exit':
                break
            else:
                print("Unknown command.")
            # Optionally, poll status after each command
            poll_status(client)
    finally:
        client.close()
        print("[HMI] Disconnected.")

if __name__ == "__main__":
    main()

