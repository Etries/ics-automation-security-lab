# detect.py (Multi-Stage ICS Analyzer with UTC timestamp fix)

import argparse
import yaml
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
import os

def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def resolve_role(register, addr_map):
    try:
        return addr_map.get(int(register), f"register_{register}")
    except Exception:
        return f"register_{register}"

def parse_zeek_log(logfile):
    with open(logfile) as f:
        first = f.readline()
        if first.strip().startswith('{'):
            f.seek(0)
            for line in f:
                if line.strip().startswith('{'):
                    yield json.loads(line)
        else:
            fields = []
            if first.startswith('#fields'):
                fields = first.strip().split()[1:]
            for line in f:
                if line.startswith('#fields'):
                    fields = line.strip().split()[1:]
                    continue
                if line.startswith('#') or not line.strip():
                    continue
                values = line.strip().split('\t')
                yield dict(zip(fields, values))

def safe_float(val):
    try:
        return float(val)
    except Exception:
        return 0.0

class MultiStageTracker:
    def __init__(self, window_sec=60):
        self.sequences = defaultdict(list)
        self.window_sec = window_sec

    def add(self, uid, rule_id, ts):
        now = convert_ts(ts)
        self.sequences[uid].append((rule_id, now))
        self.sequences[uid] = [(rid, t) for rid, t in self.sequences[uid] if (now - t).total_seconds() <= self.window_sec]

    def check_sequence(self, uid, required_rules):
        events = [rid for rid, _ in self.sequences.get(uid, [])]
        idx = 0
        for rule in required_rules:
            try:
                idx = events.index(rule, idx) + 1
            except ValueError:
                return False
        return True

def convert_ts(ts):
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace('.', '', 1).isdigit()):
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def match_rule(entry, rule, addr_map, role_values, replay_cache, freq_cache, known_ips, debug=False):
    register = str(entry.get("register") or entry.get("address"))
    role = resolve_role(register, addr_map)
    func = int(entry.get("function_code", -1))
    val = entry.get("value")
    src = entry.get("id_orig_h") or entry.get("id.orig_h")
    tid = entry.get("transaction_id") or entry.get("tid")
    vlan = entry.get("vlan")
    ts = entry.get("ts")
    uid = entry.get("uid")
    debug_msgs = []

    if rule.get("role") and rule["role"] != role:
        if debug: debug_msgs.append(f"Skip: role mismatch ({role} != {rule['role']})")
        return False, None, debug_msgs
    if rule.get("register") and str(rule["register"]) != register:
        if debug: debug_msgs.append(f"Skip: register mismatch ({register} != {rule['register']})")
        return False, None, debug_msgs
    if rule.get("function_code") and int(rule["function_code"]) != func:
        if debug: debug_msgs.append(f"Skip: function_code mismatch ({func} != {rule['function_code']})")
        return False, None, debug_msgs
    if rule.get("disallowed_function_codes") and func in rule["disallowed_function_codes"]:
        return True, "Illegal function code", debug_msgs
    if "allowed_src_ips" in rule and src not in rule["allowed_src_ips"]:
        return True, f"Unauthorized source IP: {src}", debug_msgs
    if rule.get("require_known_src_ips") and "allowed_src_ips" in rule and src not in rule["allowed_src_ips"]:
        return True, f"Unknown device source: {src}", debug_msgs
        #    if rule.get("vlan_required") is not None and vlan != rule["vlan_required"]:
        #       return True, f"VLAN mismatch: {vlan}", debug_msgs

    if rule.get("replay_detection"):
        key = (src, tid, val)
        now = convert_ts(ts)
        last_seen = replay_cache.get(key)
        if last_seen and (now - last_seen).total_seconds() < rule["time_window_seconds"]:
            return True, f"Replay detected from {src}", debug_msgs
        replay_cache[key] = now

    if rule.get("value") is not None and str(val) != str(rule["value"]):
        if debug: debug_msgs.append(f"Skip: value mismatch ({val} != {rule['value']})")
        return False, None, debug_msgs
    if rule.get("max_value") and safe_float(val) > float(rule["max_value"]):
        return True, f"Value exceeds max: {val}", debug_msgs
    if rule.get("max_jump_per_second"):
        last_val = role_values.get(role)
        if last_val is not None and abs(safe_float(val) - safe_float(last_val)) > rule["max_jump_per_second"]:
            return True, f"Unusual jump in value: {val}", debug_msgs

    if rule.get("max_occurrences") and rule.get("time_window_seconds"):
        key = (src, register)
        now = convert_ts(ts)
        freq_cache.setdefault(key, []).append(now)
        freq_cache[key] = [t for t in freq_cache[key] if (now - t).total_seconds() < rule["time_window_seconds"]]
        if len(freq_cache[key]) > rule["max_occurrences"]:
            return True, f"Command frequency exceeded: {len(freq_cache[key])}", debug_msgs

    if rule.get("correlated_role"):
        other_val = role_values.get(rule["correlated_role"])
        op = rule.get("correlated_operator", "==")
        expected = rule.get("correlated_value")
        try:
            if other_val is not None:
                if op == ">" and safe_float(other_val) > float(expected):
                    return True, f"Correlated condition met: {other_val} > {expected}", debug_msgs
                elif op == "<" and safe_float(other_val) < float(expected):
                    return True, f"Correlated condition met: {other_val} < {expected}", debug_msgs
                elif op == "==" and safe_float(other_val) == float(expected):
                    return True, f"Correlated condition met: {other_val} == {expected}", debug_msgs
        except Exception:
            pass

    if rule.get("precondition_roles") and rule.get("violation_if_precondition_missing"):
        missing = [r for r in rule["precondition_roles"] if r not in role_values]
        if missing:
            return True, f"Precondition roles not met: {missing}", debug_msgs

    return False, None, debug_msgs

def main():
    parser = argparse.ArgumentParser(description="ICS Analyzer (UTC-fixed, verbose, multi-stage)")
    parser.add_argument('--log', required=True, help='Zeek log file')
    parser.add_argument('--policy', required=True, help='Policy YAML')
    parser.add_argument('--addrmap', required=True, help='Address map YAML')
    parser.add_argument('--out', required=True, help='Output alerts JSON file')
    parser.add_argument('--verbose', action='store_true', help='Verbose rule tracing')
    args = parser.parse_args()

    rules_yaml = load_yaml(args.policy)
    rules = rules_yaml['rules'] if isinstance(rules_yaml, dict) and 'rules' in rules_yaml else rules_yaml

    addr_map = load_yaml(args.addrmap)
    known_ips = set(ip for rule in rules if isinstance(rule, dict) for ip in rule.get('allowed_src_ips', []))

    replay_cache = {}
    freq_cache = {}
    role_values = {}
    alerts = []
    multi_stage_tracker = MultiStageTracker()

    for entry in parse_zeek_log(args.log):
        ts = entry.get("ts")
        register = str(entry.get("register") or entry.get("address"))
        role = resolve_role(register, addr_map)
        val = entry.get("value")
        uid = entry.get("uid")
        if role:
            role_values[role] = val
        for rule in rules:
            match, reason, debug_msgs = match_rule(entry, rule, addr_map, role_values, replay_cache, freq_cache, known_ips, debug=args.verbose)
            if match:
                alert = {
                    "timestamp": ts,
                    "rule_id": rule.get("id"),
                    "description": rule.get("description"),
                    "src_ip": entry.get("id_orig_h") or entry.get("id.orig_h"),
                    "dst_ip": entry.get("id_resp_h") or entry.get("id.resp_h"),
                    "register": register,
                    "role": role,
                    "function_code": entry.get("function_code"),
                    "value": val,
                    "reason": reason,
                    "severity": rule.get("severity"),
                    "mitre": rule.get("mitre"),
                    "real_world": rule.get("real_world"),
                    "nis2_article": rule.get("nis2_article"),
                    "details": entry
                }
                alerts.append(alert)
                print(f"[ALERT] {ts} | Rule {rule.get('id')}: {reason}")
                if uid and rule.get("id"):
                    multi_stage_tracker.add(uid, rule["id"], ts)
            elif args.verbose and debug_msgs:
                for msg in debug_msgs:
                    print(f"[DEBUG] {ts} | Rule {rule.get('id')}: {msg}")

        for rule in rules:
            if rule.get("multi_stage_rules") and uid:
                if multi_stage_tracker.check_sequence(uid, rule["multi_stage_rules"]):
                    alert = {
                        "timestamp": ts,
                        "rule_id": rule.get("id"),
                        "description": rule.get("description"),
                        "src_ip": entry.get("id_orig_h") or entry.get("id.orig_h"),
                        "dst_ip": entry.get("id_resp_h") or entry.get("id.resp_h"),
                        "register": register,
                        "role": role,
                        "function_code": entry.get("function_code"),
                        "value": val,
                        "reason": f"Multi-stage sequence detected: {rule['multi_stage_rules']}",
                        "severity": rule.get("severity"),
                        "mitre": rule.get("mitre"),
                        "real_world": rule.get("real_world"),
                        "nis2_article": rule.get("nis2_article"),
                        "details": entry
                    }
                    alerts.append(alert)
                    print(f"[ALERT] {ts} | Rule {rule.get('id')}: Multi-stage triggered")

    with open(args.out, 'w') as f:
        json.dump(alerts, f, indent=2)
    print(f"[detect.py] {len(alerts)} alerts written to {args.out}")

if __name__ == '__main__':
    main()

