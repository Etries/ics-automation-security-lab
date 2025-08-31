import time, subprocess, os, json, sys
log = "test_output/zeek_logs/modbus_detailed.log"
t0 = time.perf_counter()
subprocess.run(["python3","test-latest/detect.py","--log",log,
                "--addrmap","test-latest/addr_map.yaml",
                "--vlan-map","test_output/vlan_logs/vlan_map.log",
                "--policy","test-latest/policies.yaml",
                "--out","test_output/alerts/alerts.json"], check=True)
t1 = time.perf_counter()
size = os.path.getsize(log) / (1024*1024)
print(json.dumps({"elapsed_sec": t1-t0, "log_mb": size, "mb_per_sec": size/(t1-t0)}))
