#!/usr/bin/env python3
import argparse
import yaml
import json
from collections import defaultdict
from datetime import datetime

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Context-aware IDS for Modbus/TCP.")
parser.add_argument('--log', required=True)
parser.add_argument('--policy', required=True)
parser.add_argument('--addrmap', required=True)
parser.add_argument('--vlan-map', required=True, help="Path to the UID-to-VLAN mapping file from tshark.")
parser.add_argument('--out', required=True)
args = parser.parse_args()

# --- Load Configs & Initialize State ---
try:
    with open(args.policy) as f:
        policy = yaml.safe_load(f)
    with open(args.addrmap) as f:
        addr_map = yaml.safe_load(f)

    # Load the VLAN map into a dictionary for quick lookup
    uid_to_vlan = {}
    with open(args.vlan_map) as f:
        for line in f:
            if '\t' in line:
                uid, vlan_id = line.strip().split('\t', 1)
                if uid and vlan_id:
                    uid_to_vlan[uid] = int(vlan_id)
except Exception as e:
    print(f"[FATAL] Could not load or parse config/map files: {e}")
    exit(1)

alerts = []
process_state = 'IDLE'
last_known_values = {}
tid_tracker = defaultdict(list)
request_timestamps = []
value_specific_tracker = defaultdict(list)

# --- Utils ---
def extract_numeric_value(val_str):
    if val_str.isdigit():
        return int(val_str)
    try:
        return int(val_str.split(',')[0])  # Handle "0,1,2..." style
    except:
        return 0

def parse_log_line(line):
    parts = line.strip().split('\t')
    if len(parts) < 18 or line.startswith('#'):
        return None
    if parts[14] != 'REQUEST':  # Only handle Modbus REQUESTs
        return None
    try:
        return {
            'ts': parts[0],
            'uid': parts[1],
            'src': parts[2],
            'dst': parts[4],
            'func': int(parts[13]) if parts[13].isdigit() else -1,
            'addr': int(parts[15]) if parts[15].isdigit() else -1,
            'value': extract_numeric_value(parts[17])
        }
    except Exception as e:
        print(f"[!] Failed to parse line: {e}\n{line}")
        return None

def get_role_from_addr(addr):
    return addr_map.get(str(addr))

def emit_alert(rule, log, reason):
    alert = {
        'rule_id': rule['id'],
        'timestamp': log['ts'],
        'src': log['src'],
        'dst': log['dst'],
        'func': log.get('func'),
        'addr': log.get('addr'),
        'value': log.get('value'),
        'vlan_id': log.get('vlan_id'),
        'reason': reason,
        'severity': rule.get('severity'),
        'mitre': rule.get('mitre'),
        'real_world': rule.get('real_world'),
        'nis2_article': rule.get('nis2_article')
    }
    alerts.append(alert)

# --- MAIN ---
def main():
    global process_state

    # Preload rules
    ip_rule = policy['network']['ip_whitelist_rule']
    vlan_rule = policy['network']['network_segmentation_rule']
    ip_to_vlan_map = vlan_rule['ip_to_vlan_map']
    func_rule = policy['protocol']['function_code_rule']
    global_rules = policy.get('global_rules', [])
    register_rules_map = {r['address']: r for r in policy.get('registers', [])}
    state_machine = policy.get('state_machine', {})

    replay_rule = next((r for r in global_rules if r.get('detection_type') == 'replay'), {})
    flood_rule = next((r for r in global_rules if r.get('detection_type') == 'flood'), {})
    freq_rules = [r for r in global_rules if r.get('detection_type') == 'value_frequency']

    with open(args.log) as f:
        for line in f:
            if line.startswith('#'): continue
            log = parse_log_line(line)
            if not log:
                continue

            now = log['ts']

            # Enrich with VLAN info
            log['vlan_id'] = uid_to_vlan.get(log['uid'])

            addr = log.get('addr')
            value = log.get('value')
            if addr is not None:
                last_known_values[addr] = (now, value)

            # VLAN Segmentation Rule (R004)
            if log['vlan_id']:
                expected_vlan = ip_to_vlan_map.get(log['src'])
                if expected_vlan and log['vlan_id'] != expected_vlan:
                    emit_alert(vlan_rule, log,
                        f"IP {log['src']} expected on VLAN {expected_vlan} but seen on VLAN {log['vlan_id']}")

            # TODO: Add other detections (replay, frequency, flood, etc.)

    # --- Output ---
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"\n[+] Analysis complete. Found {len(alerts)} alerts. Report saved to {args.out}")
    elif alerts:
        print(json.dumps(alerts, indent=2))

if __name__ == "__main__":
    main()

