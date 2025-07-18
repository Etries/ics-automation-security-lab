#!/usr/bin/env python3
import argparse
import yaml
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ─────────────────────────────
# Argument Parsing
# ─────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--log', required=True)
parser.add_argument('--policy', required=True)
parser.add_argument('--addrmap', required=True)
parser.add_argument('--vlan', help='Optional VLAN tag to check against')
parser.add_argument('--out', help='Output alert file')
args = parser.parse_args()

# ─────────────────────────────
# Load YAML Configs
# ─────────────────────────────
with open(args.policy) as f:
    rules = yaml.safe_load(f)['rules']
with open(args.addrmap) as f:
    addr_map = yaml.safe_load(f)

alerts = []
role_buffer = {}
replay_tracker = defaultdict(list)
freq_tracker = defaultdict(list)

# ─────────────────────────────
# Utility
# ─────────────────────────────
def parse_log_line(line):
    parts = line.strip().split('\t')
    if len(parts) < 18: return None
    return {
        'ts': parts[0], 'uid': parts[1], 'src': parts[2], 'dst': parts[4],
        'func': int(parts[13]) if parts[13].isdigit() else -1,
        'dir': parts[14], 'addr': int(parts[11]) if parts[11].isdigit() else -1,
        'tid': parts[15], 'val': parts[17]
    }

def role(addr):
    return addr_map.get(str(addr))

def ts_float(ts):
    try: return float(ts)
    except: return 0.0

def val_int(val):
    try: return int(val)
    except: return None

def emit(rule, log, reason):
    alert = {
        "timestamp": log['ts'], "rule_id": rule['id'],
        "description": rule['description'], "source": log['src'], "destination": log['dst'],
        "address": log['addr'], "value": log['val'], "severity": rule['severity'],
        "mitre": rule.get('mitre', {}), "real_world": rule.get('real_world', ''),
        "nis2_article": rule.get('nis2_article', ''), "reason": reason
    }
    alerts.append(alert)

# ─────────────────────────────
# Process Log
# ─────────────────────────────
with open(args.log) as f:
    for line in f:
        if line.startswith('#') or not line.strip(): continue
        log = parse_log_line(line)
        if not log or log['dir'] != 'REQUEST': continue

        log['role'] = role(log['addr'])
        log['val_int'] = val_int(log['val'])
        now = ts_float(log['ts'])

        for rule in rules:
            # --- Base Matching ---
            if rule.get('role') and rule['role'] != log['role']: continue
            if rule.get('function_code') and rule['function_code'] != log['func']: continue

            # --- Source IP Checks ---
            if 'allowed_src_ips' in rule and log['src'] not in rule['allowed_src_ips']:
                emit(rule, log, f"unauthorized IP {log['src']}")
                continue

            if rule.get('require_known_src_ips') and 'allowed_src_ips' in rule:
                if log['src'] not in rule['allowed_src_ips']:
                    emit(rule, log, f"unknown source {log['src']}")

            # --- VLAN Check from --vlan arg ---
            if 'vlan_required' in rule and args.vlan:
                if str(rule['vlan_required']) != args.vlan:
                    emit(rule, log, f"VLAN mismatch (expected {rule['vlan_required']}, got {args.vlan})")

            # --- Function Abuse ---
            if 'disallowed_function_codes' in rule:
                if log['func'] in rule['disallowed_function_codes']:
                    emit(rule, log, f"Illegal function {log['func']}")

            # --- Exact Value Match + Frequency ---
            if 'value' in rule and log['val_int'] == rule['value']:
                if 'max_occurrences' in rule and 'time_window_seconds' in rule:
                    key = (rule['id'], log['src'])
                    freq_tracker[key] = [t for t in freq_tracker[key] if now - t < rule['time_window_seconds']]
                    freq_tracker[key].append(now)
                    if len(freq_tracker[key]) > rule['max_occurrences']:
                        emit(rule, log, f"Excessive frequency of {rule['value']}")
                else:
                    emit(rule, log, "Matched value")

            # --- Max Value ---
            if 'max_value' in rule and log['val_int'] and log['val_int'] > rule['max_value']:
                emit(rule, log, f"Value {log['val_int']} exceeds {rule['max_value']}")

            # --- Replay Detection ---
            if rule.get('replay_detection'):
                tid_key = (log['tid'], log['val'])
                replay_tracker[tid_key].append(now)
                if len(replay_tracker[tid_key]) >= 2:
                    if abs(replay_tracker[tid_key][-1] - replay_tracker[tid_key][-2]) < rule['time_window_seconds']:
                        emit(rule, log, "Replay Detected")

            # --- Jump Detection ---
            if 'max_jump_per_second' in rule:
                r = rule['role']
                if r in role_buffer:
                    old_ts, old_val = role_buffer[r]
                    jump = abs(log['val_int'] - old_val) / max((now - old_ts), 0.01)
                    if jump > rule['max_jump_per_second']:
                        emit(rule, log, f"Jump rate {jump:.2f} exceeds {rule['max_jump_per_second']}")
                role_buffer[r] = (now, log['val_int'])

# ─────────────────────────────
# Output Alerts
# ─────────────────────────────
if args.out:
    with open(args.out, 'w') as f:
        json.dump(alerts, f, indent=2)
    print(f"[detect.py] {len(alerts)} alerts written to {args.out}")

