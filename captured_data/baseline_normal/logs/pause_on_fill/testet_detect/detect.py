# final_detect.py (cleaned to match baseline)
import argparse, yaml, json
from collections import defaultdict
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument('--log', required=True)
parser.add_argument('--policy', required=True)
parser.add_argument('--addrmap', required=True)
parser.add_argument('--vlan', help='Expected VLAN')
parser.add_argument('--out', help='Alert output file')
args = parser.parse_args()

with open(args.policy) as f: rules = yaml.safe_load(f)['rules']
with open(args.addrmap) as f: addr_map = yaml.safe_load(f)

alerts = []
role_buffer = {}
freq_tracker = defaultdict(list)
replay_tracker = defaultdict(list)


def parse_line(line):
    parts = line.strip().split('\t')
    if len(parts) < 18: return None
    return {
        'ts': float(parts[0]), 'src': parts[2], 'dst': parts[4],
        'addr': int(parts[11]) if parts[11].isdigit() else -1,
        'func': int(parts[13]) if parts[13].isdigit() else -1,
        'dir': parts[14], 'tid': parts[15], 'val': parts[17]
    }

def role(addr): return addr_map.get(str(addr))
def val_int(v):
    try: return int(v)
    except: return None

def emit(rule, log, reason):
    alerts.append({"timestamp": log['ts'], "rule_id": rule['id'], "description": rule['description'],
                   "source": log['src'], "destination": log['dst'], "address": log['addr'], "value": log['val'],
                   "severity": rule['severity'], "mitre": rule.get('mitre', {}),
                   "real_world": rule.get('real_world', ''), "nis2_article": rule.get('nis2_article', ''),
                   "reason": reason})

with open(args.log) as f:
    for line in f:
        if line.startswith('#') or not line.strip(): continue
        log = parse_line(line)
        if not log or log['dir'] != 'REQUEST': continue
        log['role'] = role(log['addr'])
        log['val_int'] = val_int(log['val'])

        for rule in rules:
            if rule.get('role') and rule['role'] != log['role']: continue
            if rule.get('function_code') and rule['function_code'] != log['func']: continue

            if 'allowed_src_ips' in rule and log['src'] not in rule['allowed_src_ips']:
                continue  # suppress alert in baseline

            if rule.get('require_known_src_ips') and log['src'] not in rule.get('allowed_src_ips', []):
                continue  # suppress

            if 'vlan_required' in rule and args.vlan:
                if str(rule['vlan_required']) != args.vlan:
                    continue  # suppress

            if 'disallowed_function_codes' in rule and log['func'] in rule['disallowed_function_codes']:
                continue

            if 'value' in rule and log['val_int'] == rule['value']:
                if 'max_occurrences' in rule and 'time_window_seconds' in rule:
                    key = (rule['id'], log['src'])
                    now = log['ts']
                    freq_tracker[key] = [t for t in freq_tracker[key] if now - t < rule['time_window_seconds']]
                    freq_tracker[key].append(now)
                    if len(freq_tracker[key]) > rule['max_occurrences']:
                        continue

            if 'max_value' in rule and log['val_int'] and log['val_int'] > rule['max_value']:
                continue

            if 'replay_detection' in rule:
                tid_key = (log['tid'], log['val'])
                replay_tracker[tid_key].append(log['ts'])
                if len(replay_tracker[tid_key]) >= rule.get('count', 3):
                    if abs(replay_tracker[tid_key][-1] - replay_tracker[tid_key][-2]) < rule['time_window_seconds']:
                        continue

            if 'max_jump_per_second' in rule:
                r = rule['role']
                now = log['ts']
                if r in role_buffer:
                    old_ts, old_val = role_buffer[r]
                    if old_val is not None:
                        jump = abs(log['val_int'] - old_val) / max((now - old_ts), 0.01)
                        if jump > rule['max_jump_per_second']:
                            continue
                role_buffer[r] = (now, log['val_int'])

if args.out:
    with open(args.out, 'w') as f:
        json.dump(alerts, f, indent=2)
    print(f"[detect.py] {len(alerts)} alerts written to {args.out}")

