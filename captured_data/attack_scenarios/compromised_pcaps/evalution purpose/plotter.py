import pandas as pd
import matplotlib.pyplot as plt

data = [
 # attack, pcap_mb, modbus_mb, alerts, zeek_s, detect_s, incident_s, total_s
 ("attack_01", 0.910, 0.556, 3, 1.831, 0.109, 0.072, 2.592),
 ("attack_02", 0.824, 0.503, 3, 1.569, 0.099, 0.067, 2.325),
 ("attack_03", 0.700, 0.426, 6, 1.459, 0.088, 0.072, 2.218),
 ("attack_04-1", 0.015, 0.009, 1, 1.099, 0.069, 0.115, 1.426),
 ("attack_05-1", 0.247, 0.105, 161, 1.074, 0.077, 0.063, 1.603),
 ("attack_06-1", 0.220, 0.134, 2, 1.116, 0.071, 0.063, 1.609),
 ("attack_07", 0.470, 0.287, 503, 1.531, 0.100, 0.097, 2.133),
 ("attack_08", 0.736, 0.450, 388, 2.221, 0.229, 0.128, 3.549),
 ("attack_09", 0.734, 0.447, 2, 1.732, 0.142, 0.094, 2.726),
 ("attack_10", 0.488, 0.294, 4, 1.473, 0.128, 0.096, 2.317),
 ("attack_11", 1.469, 0.409, 1, 1.559, 0.148, 0.092, 3.123),
 ("attack_12", 0.949, 0.463, 562, 1.665, 0.177, 0.118, 2.860),
 ("attack_13_main", 0.861, 0.640, 2236, 2.088, 0.184, 0.139, 3.159),
 ("attack_13", 1.277, 0.496, 867, 1.696, 0.139, 0.114, 3.088),
 ("attack_14-1", 0.711, 0.514, 2089, 1.663, 0.161, 0.138, 2.627),
 ("attack_15", 0.719, 0.522, 2719, 1.459, 0.168, 0.258, 2.547),
 ("attack_16", 0.238, 0.146, 255, 1.706, 0.111, 0.097, 2.456),
]
df = pd.DataFrame(data, columns=["attack","pcap_mb","modbus_detailed_mb","alerts","zeek_sec","detect_sec","incident_sec","total_sec"])

# 1) Detection time vs Modbus detailed size
plt.figure()
plt.scatter(df["modbus_detailed_mb"], df["detect_sec"])
plt.xlabel("modbus_detailed.log size (MB)")
plt.ylabel("Detection time (s)")
plt.title("Detection time vs Modbus detailed size")
plt.savefig("detect_time_vs_modbus_size.png", bbox_inches="tight")

# 2) Total pipeline time vs PCAP size
plt.figure()
plt.scatter(df["pcap_mb"], df["total_sec"])
plt.xlabel("PCAP size (MB)")
plt.ylabel("Total pipeline time (s)")
plt.title("Total pipeline time vs PCAP size")
plt.savefig("total_time_vs_pcap_size.png", bbox_inches="tight")

# 3) Alerts per attack
plt.figure()
plt.bar(df["attack"], df["alerts"])
plt.xlabel("Attack")
plt.ylabel("Alerts (median)")
plt.title("Alerts per attack")
plt.xticks(rotation=45, ha="right")
plt.savefig("alerts_per_attack.png", bbox_inches="tight")
