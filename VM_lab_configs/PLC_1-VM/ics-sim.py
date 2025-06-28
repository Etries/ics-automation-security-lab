#! /usr/bin/env python3
import time
import threading
import os
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

# Modbus register mapping
COIL_INLET = 0      # %QX100.0
COIL_OUTLET = 1     # %QX100.1
COIL_MIXER = 2      # %QX100.2
COIL_MIX_DONE = 4   # %QX100.4

HR_STATE = 100        # %QW100
HR_COMMAND = 1024     # %MW0

IR_LEVEL = 0        # %IW100
DI_ALARM = 0          # %IX100.0

TANK_MAX = 100
TANK_MIN = 0

TAMPER_FLAG_FILE = "tamper.flag"

def is_tampered():
    return os.path.exists(TAMPER_FLAG_FILE)

def update_simulation(context):
    tank_level = 0
    alarm = False
    fill_rate = 5      # units per cycle
    drain_rate = 2     # units per cycle

    while True:
        # Read coil states
        coils = context[0].getValues(1, COIL_INLET, count=5)
        inlet = coils[0]
        outlet = coils[1]
        # Simulate tank
        if inlet and tank_level < TANK_MAX:
            tank_level += fill_rate
        if outlet and tank_level > TANK_MIN:
            tank_level -= drain_rate
        tank_level = max(TANK_MIN, min(TANK_MAX, tank_level))

        # Alarm if level > 90
        alarm = tank_level > 90

        # Tamper mode: forge values
        if is_tampered():
            forged_level = 100
            forged_alarm = False
            context[0].setValues(4, IR_LEVEL, [forged_level])
            context[0].setValues(2, DI_ALARM, [int(forged_alarm)])
        else:
            context[0].setValues(4, IR_LEVEL, [tank_level])
            context[0].setValues(2, DI_ALARM, [int(alarm)])

        # Print live status
        print(f"[Sensor-Sim] Inlet: {inlet} | Outlet: {outlet}")
        print(f"[SensorSim] Tank Level: {tank_level} | Alarm: {alarm} | Tampered: {is_tampered()}")

        time.sleep(1)

def main():
    # Modbus data store: coils, discrete inputs, input registers, holding registers
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),   # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [0]*100), # Coils (start at 800)
        hr=ModbusSequentialDataBlock(0, [0]*1100), # Holding Registers
        ir=ModbusSequentialDataBlock(0, [0]*1100), # Input Registers
    )
    context = ModbusServerContext(slaves=store, single=True)

    # Start simulation thread
    sim_thread = threading.Thread(target=update_simulation, args=(context,))
    sim_thread.daemon = True
    sim_thread.start()

    # Start Modbus TCP server
    print("[SensorSim] Starting Modbus TCP slave on port 1502...")
    StartTcpServer(context, address=("0.0.0.0", 1502))

if __name__ == "__main__":
    main()

