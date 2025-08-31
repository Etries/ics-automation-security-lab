#!/usr/bin/env python3
import argparse, os, subprocess, time, json, shutil, sys, csv

def abspath(p): return os.path.abspath(os.path.expanduser(p))

def must_exist(path, what):
    if not os.path.exists(path):
        print(f"FATAL: {what} not found: {path}", file=sys.stderr)
        sys.exit(1)

def fsize_mb(path):
    return os.path.getsize(path) / (1024*1024) if os.path.exists(path) else 0.0

parser = argparse.ArgumentParser()
parser.add_argument("--pcap", required=True, help="Path to the PCAP to analyze (relative or absolute)")
parser.add_argument("--zmod", default="~/.zkg/clones/package/icsnpp-modbus/scripts",
                    help="ICSNPP-Modbus Zeek scripts dir")
parser.add_argument("--zbin", default="/opt/zeek/bin/zeek", help="Path to zeek binary")
parser.add_argument("--detect", default="test-latest/detect.py", help="Path to detect.py")
parser.add_argument("--ibuilder", default="test-latest/incident_builder.py", help="Path to incident_builder.py")
parser.add_argument("--addrmap", default="test-latest/addr_map.yaml", help="addr_map.yaml")
parser.add_argument("--policy", default="test-latest/policies.yaml", help="policies.yaml")
parser.add_argument("--outdir", default="test_output", help="Root output dir")
parser.add_argument("--label", default="", help="Optional label for this run (e.g., A01, A11)")
parser.add_argument("--csv", default="", help="Optional CSV path to append results")
args = parser.parse_args()

# Resolve paths
pcap_path   = abspath(args.pcap)
zmod_path   = abspath(args.zmod)
zeek_bin    = abspath(args.zbin)
detect_py   = abspath(args.detect)
ibuild_py   = abspath(args.ibuilder)
addrmap     = abspath(args.addrmap)
policy      = abspath(args.policy)
out_root    = abspath(args.outdir)

zeek_dir    = os.path.join(out_root, "zeek_logs")
vlan_dir    = os.path.join(out_root, "vlan_logs")
alerts_dir  = os.path.join(out_root, "alerts")
inc_dir     = os.path.join(out_root, "incidents")
sys_dir     = os.path.join(out_root, "sysmetrics")
os.makedirs(zeek_dir, exist_ok=True)
os.makedirs(vlan_dir, exist_ok=True)
os.makedirs(alerts_dir, exist_ok=True)
os.makedirs(inc_dir, exist_ok=True)
os.makedirs(sys_dir, exist_ok=True)

# Sanity checks
must_exist(pcap_path, "PCAP")
must_exist(zeek_bin, "zeek binary")
must_exist(zmod_path, "ICSNPP-Modbus scripts")
must_exist(detect_py, "detect.py")
must_exist(ibuild_py, "incident_builder.py")
must_exist(addrmap, "addr_map.yaml")
must_exist(policy, "policies.yaml")

# Clean previous zeek logs
for f in os.listdir(zeek_dir):
    if f.endswith(".log"):
        try: os.remove(os.path.join(zeek_dir, f))
        except: pass

results = {
    "label": args.label,
    "pcap": pcap_path
}

# Stage 1: Zeek parse
pcap_mb = fsize_mb(pcap_path)
t0 = time.perf_counter()
subprocess.run([zeek_bin, "-Cr", pcap_path, zmod_path], check=True, cwd=zeek_dir)
t1 = time.perf_counter()
zeek_sec = t1 - t0
results["zeek_sec"] = round(zeek_sec, 6)
results["pcap_mb"] = round(pcap_mb, 6)
results["zeek_mb_per_sec"] = round((pcap_mb / zeek_sec), 6) if zeek_sec > 0 else None

# Zeek outputs
modbus_detailed = os.path.join(zeek_dir, "modbus_detailed.log")
modbus_log      = os.path.join(zeek_dir, "modbus.log")
conn_log        = os.path.join(zeek_dir, "conn.log")
for path, key in [(modbus_detailed,"modbus_detailed_mb"),
                  (modbus_log,"modbus_mb"),
                  (conn_log,"conn_mb")]:
    results[key] = round(fsize_mb(path), 6) if os.path.exists(path) else 0.0

must_exist(modbus_detailed, "modbus_detailed.log")

# Stage 1.5: VLAN map (best-effort)
vlan_map = os.path.join(vlan_dir, "vlan_map.log")
tshark = shutil.which("tshark")
if tshark:
    awk_prog = r"""{src=$1; vlan=$2; if (!(src in seen) || seen[src] != vlan){print src "\t" vlan; seen[src]=vlan}}"""
    cmd = f"""{tshark} -r "{pcap_path}" -Y "vlan && tcp.port==502" \
      -T fields -e ip.src -e vlan.id -E separator=$'\\t' | \
      awk -F'\\t' '{awk_prog}' > "{vlan_map}" """
    subprocess.run(["/bin/bash","-lc", cmd], check=False)
else:
    open(vlan_map, "w").close()

# Stage 2: detect.py
alerts_path = os.path.join(alerts_dir, "alerts.json")
t2 = time.perf_counter()
subprocess.run([
    sys.executable, detect_py,
    "--log", modbus_detailed,
    "--addrmap", addrmap,
    "--vlan-map", vlan_map,
    "--policy", policy,
    "--out", alerts_path
], check=True)
t3 = time.perf_counter()
detect_sec = t3 - t2
results["detect_sec"] = round(detect_sec, 6)
md_mb = results["modbus_detailed_mb"]
results["detect_mb_per_sec"] = round((md_mb / detect_sec), 6) if detect_sec > 0 else None

# Count alerts (if file is JSON array)
alerts_count = 0
try:
    import json as _json
    with open(alerts_path, "r") as f:
        data = _json.load(f)
        if isinstance(data, list):
            alerts_count = len(data)
        elif isinstance(data, dict) and "alerts" in data and isinstance(data["alerts"], list):
            alerts_count = len(data["alerts"])
except Exception:
    pass
results["alerts_count"] = alerts_count

# Stage 3: incident builder
incident_path = os.path.join(inc_dir, f"incident_{os.path.basename(pcap_path)}.json")
t4 = time.perf_counter()
subprocess.run([
    sys.executable, ibuild_py,
    "--alerts", alerts_path,
    "--policy", policy,
    "--addrmap", addrmap,
    "--out", incident_path,
    "--format", "both"
], check=True)
t5 = time.perf_counter()
inc_sec = t5 - t4
results["incident_sec"] = round(inc_sec, 6)
results["incident_alerts_per_sec"] = round((alerts_count / inc_sec), 6) if inc_sec > 0 else None

# Totals
results["total_sec"] = round(t5 - t0, 6)

print(json.dumps(results, indent=2))

# Optional CSV append
if args.csv:
    csv_path = abspath(args.csv)
    header = ["label","pcap","pcap_mb","modbus_detailed_mb","modbus_mb","conn_mb",
              "zeek_sec","zeek_mb_per_sec","detect_sec","detect_mb_per_sec",
              "incident_sec","incident_alerts_per_sec","alerts_count","total_sec"]
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if write_header: w.writeheader()
        row = {k: results.get(k, "") for k in header}
        w.writerow(row)
