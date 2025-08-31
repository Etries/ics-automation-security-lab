#!/usr/bin/env python3
"""
Policy-Driven Context-Aware ICS Detection Engine (Modbus/TCP)

- No hard-coded thresholds: everything comes from policies.yaml
- Works with flat addr_map.yaml (numeric register keys + optional `assets:` map)
- Accepts VLAN info by UID (preferred) or src-dst pairs
- Emits rule_id + core fields; incident_builder enriches (severity, MITRE, NIS2)

CLI:
  python3 detect.py \
    --log /path/to/modbus_detailed.log \
    --policy /path/to/policies.yaml \
    --addrmap /path/to/addr_map.yaml \
    --vlan-map /path/to/vlan_map_YYYYMMDD_HHMMSS.log \
    --out /path/to/alerts.json
"""

import argparse
import yaml
import json
from collections import defaultdict, deque

# ---------- Utilities ----------

def load_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

def split_addr_map(flat_map):
    """
    Accepts flat addr_map with numeric register keys (or numeric strings)
    and optional assets: { ip: name }.
    Returns (asset_map, register_map[int->name]).
    """
    if not isinstance(flat_map, dict):
        return {}, {}

    assets = flat_map.get("assets", {})
    asset_map = dict(assets) if isinstance(assets, dict) else {}

    reg_map = {}
    for k, v in flat_map.items():
        if k == "assets":
            continue
        # honor accidental IPs at top-level as assets
        if isinstance(k, str) and k.count(".") == 3:
            asset_map.setdefault(k, v)
            continue
        try:
            reg_map[int(k)] = v
        except Exception:
            pass
    return asset_map, reg_map


def get_rule_meta(policy, rule_id):
    # 1) global_rules (list)
    for r in policy.get("global_rules", []):
        if r.get("id") == rule_id:
            return r

    # 2) top-level singleton sections (backward compat)
    for section in [
        "network_segmentation_rule","ip_whitelist_rule","function_code_rule",
        "state_logic_rule","state_transition_rule","polling_sequence_rule"
    ]:
        sec = policy.get(section)
        if isinstance(sec, dict) and sec.get("id") == rule_id:
            return sec

    # 3) NESTED sections we actually use now
    nested = [
        ("network",  "network_segmentation_rule"),
        ("network",  "ip_whitelist_rule"),
        ("protocol", "function_code_rule"),
    ]
    for parent, child in nested:
        sec = policy.get(parent, {}).get(child)
        if isinstance(sec, dict) and sec.get("id") == rule_id:
            return sec

    # 4) per-register rules
    for reg in policy.get("registers", []):
        for r in reg.get("rules", []):
            if r.get("id") == rule_id:
                return r

    return {}



# ---------- State ----------

class StateTracker:
    """Tracks process state and timing for context-aware detection"""
    def __init__(self, freq_window=5.0, freq_max=40, replay_window=2.0, tid_reset_jump=250):
        self.write_history = defaultdict(lambda: deque(maxlen=3))
        self.polling_state = {}
        self.tid_history = {}
        self.frequency_tracker = defaultdict(lambda: deque(maxlen=100))
        self.last_known_values = {}
        self.last_tid_per_source = {}
        self.freq_window = float(freq_window)
        self.freq_max = int(freq_max)
        self.replay_window = float(replay_window)
        self.tid_reset_jump = int(tid_reset_jump)

    def add_write_event(self, connection_key, value, timestamp):
        self.write_history[connection_key].append((value, timestamp))

    def get_write_history(self, connection_key):
        return list(self.write_history[connection_key])

    def reset_polling_state(self, connection_key):
        key = f"{connection_key}_polling"
        if key in self.polling_state:
            del self.polling_state[key]

    def reset_tid_state(self, source_ip):
        if source_ip in self.last_tid_per_source:
            del self.last_tid_per_source[source_ip]

# ---------- Detector ----------

class Detector:
    def __init__(self, policy_file, addr_map_file):
        self.policy = load_yaml(policy_file)
        self.addr_map = load_yaml(addr_map_file)
        self.asset_map, self.register_map = split_addr_map(self.addr_map)

        # Network policy
        net = self.policy.get("network", {})
        self.authorized_ips = set(net.get("authorized_ips", []))
        self.ip_to_vlan = net.get("ip_to_vlan_map", {})  # { "10.0.0.5": 10, ... }
        self.authorized_registers = {
            ip: set(regs) for ip, regs in net.get("authorized_registers", {}).items()
        }

        # Engine parameters
        params = self.policy.get("parameters", {})
        freq_conf      = params.get("excessive_requests", {"window_seconds": 5.0, "max_requests": 40})
        replay_seconds = params.get("replay_window_seconds", 2.0)
        tid_reset_jump = params.get("tid_pattern", {}).get("allowed_reset_jump", 250)

        self.state = StateTracker(
            freq_window=freq_conf.get("window_seconds", 5.0),
            freq_max=freq_conf.get("max_requests", 40),
            replay_window=replay_seconds,
            tid_reset_jump=tid_reset_jump
        )

        # Physical tampering checks are fully policy-driven
        self.tampering = params.get("tampering", {"enabled": False, "checks": []})

        # Allowed Modbus function codes
        self.allowed_funcs = self.policy.get("protocol", {}).get("allowed_funcs", [])

        # Stateful timing rules (already policy-driven in your design)
        self.write_value_rules = self.policy.get("write_value_rules", {})
        self.polling_rules     = self.policy.get("polling_rules", {})

        self.alerts = []

    # ---------- Parsing ----------

    def _parse_modbus_log(self, log_file):
        events = []
        func_code_map = {
            'READ_COILS': 1, 'READ_DISCRETE_INPUTS': 2, 'READ_HOLDING_REGISTERS': 3,
            'READ_INPUT_REGISTERS': 4, 'WRITE_SINGLE_COIL': 5, 'WRITE_SINGLE_REGISTER': 6,
            'WRITE_MULTIPLE_COILS': 15, 'WRITE_MULTIPLE_REGISTERS': 16
        }
        with open(log_file) as f:
            header, data = [], []
            for line in f:
                (header if line.startswith('#') else data).append(line.rstrip('\n'))

            fields = []
            for h in header:
                if h.startswith('#fields'):
                    fields = h.split('\t')[1:]
                    break
            if not fields:
                raise RuntimeError("modbus_detailed.log missing #fields header")

            for line in data:
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) < len(fields):
                    continue

                row = dict(zip(fields, parts))
                func_text = row.get('func', '')
                try:
                    events.append({
                        'ts': float(row.get('ts', 0.0)),
                        'uid': row.get('uid',''),
                        'src': row.get('id.orig_h',''),
                        'dst': row.get('id.resp_h',''),
                        'function_code': func_code_map.get(func_text, -1),
                        'func_text': func_text,
                        'address': int(row.get('address','-1')) if row.get('address','-').lstrip('-').isdigit() else -1,
                        'value': int(row.get('values','0').split(',')[0]) if row.get('values','').replace(',','').lstrip('-').isdigit() else 0,
                        'tid': int(row.get('tid','0')) if row.get('tid','0').isdigit() else 0,
                        'is_request': row.get('request_response') == 'REQUEST'
                    })
                except Exception:
                    continue
        return events

    # VLAN map: support (uid -> vlan) OR (src,dst,vlan)
    def _load_vlan_map(self, vlan_file):
        uid_to_vlan = {}
        pair_to_vlan = {}
        try:
            with open(vlan_file) as f:
                for line in f:
                    if not line.strip() or line.startswith('#'):
                        continue
                    parts = line.strip().split('\t')
                    # tshark line could be: "<uid>\t<vlanid>"
                    if len(parts) == 2 and parts[1].isdigit():
                        uid_to_vlan[parts[0]] = int(parts[1])
                    # or custom: "<src>\t<dst>\t<vlanid>"
                    elif len(parts) >= 3 and parts[2].isdigit():
                        pair_to_vlan[f"{parts[0]}-{parts[1]}"] = int(parts[2])
        except Exception:
            pass
        return uid_to_vlan, pair_to_vlan

    # ---------- Helpers ----------

    def _addr_from_name_or_int(self, val):
        """Accept either numeric address (int/str) or register name in policy."""
        # numeric
        try:
            return int(val)
        except Exception:
            pass
        # name → address via register_map
        for addr, name in self.register_map.items():
            if str(name) == str(val):
                return addr
        return None

    def _severity(self, rule_id, default="medium"):
        meta = get_rule_meta(self.policy, rule_id)
        return meta.get("severity", default) if meta else default

    # ---------- Checks (all policy-driven) ----------

    def _check_unauthorized_ip(self, e):
        if not self.authorized_ips:
            return None
        if e['src'] not in self.authorized_ips:
            return {'rule_id': 'R014', 'description': f"Communication from unauthorized IP: {e['src']}"}
        return None

    def _check_illegal_function(self, e):
        if not e['is_request']:
            return None
        if self.allowed_funcs and e['function_code'] not in self.allowed_funcs:
            return {'rule_id': 'R006', 'description': f"Illegal function code used: {e['function_code']}"}
        return None

    def _check_unauthorized_write(self, e):
        if not e['is_request'] or e['function_code'] != 6:
            return None
        allowed_regs = self.authorized_registers.get(e['src'])
        if allowed_regs is not None and e['address'] not in allowed_regs:
            return {'rule_id': 'R005', 'description': f"Role violation: Unauthorized IP {e['src']} wrote register {e['address']}"}
        # register access mode from policy.registers[]
        for reg in self.policy.get('registers', []):
            if self._addr_from_name_or_int(reg.get('address')) == e['address'] and reg.get('access') == 'read-only':
                return {'rule_id': 'R001', 'description': f"Unauthorized write attempt to read-only register {e['address']}"}
        return None

    def _check_abnormal_process_value(self, e):
        if not e['is_request']:
            return None
        for reg in self.policy.get('registers', []):
            if self._addr_from_name_or_int(reg.get('address')) == e['address']:
                vr = reg.get('value_range')
                if vr and len(vr) == 2:
                    lo, hi = vr[0], vr[1]
                    if not (lo <= e['value'] <= hi):
                        return {'rule_id': 'R002', 'description': f"Abnormal process value {e['value']} for register {e['address']}"}
        return None

    def _check_physical_tampering(self, e):
        """
        Fully policy-driven:
        parameters:
          tampering:
            enabled: true
            checks:
            - level_register: tank_level            # name or address
              threshold: { op: '>=', value: 80 }
              alarm_register: alarm_flag           # name or address
              alarm_expected: 1                    # expected when level high
              within_seconds: 5.0
        """
        if not e['is_request'] or not self.tampering.get("enabled"):
            return None

        addr, value, ts = e['address'], e['value'], e['ts']
        self.state.last_known_values[addr] = (value, ts)

        for rule in self.tampering.get("checks", []):
            level_addr = self._addr_from_name_or_int(rule.get("level_register"))
            alarm_addr = self._addr_from_name_or_int(rule.get("alarm_register"))
            if level_addr is None or alarm_addr is None:
                continue

            # evaluate level threshold only if the current event is that register
            if addr != level_addr:
                continue

            thr = rule.get("threshold", {})
            op, thr_val = thr.get("op", ">="), thr.get("value", 0)
            cond = ((op == ">=" and value >= thr_val) or
                    (op == ">"  and value >  thr_val) or
                    (op == "==" and value == thr_val) or
                    (op == "<=" and value <= thr_val) or
                    (op == "<"  and value <  thr_val))

            if not cond:
                continue

            alarm = self.state.last_known_values.get(alarm_addr)
            if not alarm:
                continue

            expected = rule.get("alarm_expected", 1)
            within = float(rule.get("within_seconds", 5.0))
            alarm_val, alarm_ts = alarm
            if alarm_val != expected and abs(ts - alarm_ts) <= within:
                return {'rule_id': 'R003',
                        'description': f"Physical tampering suspected: level {value} triggers alarm expectation {expected} but alarm is {alarm_val}."}
        return None

    def _check_replay_attack(self, e):
        if not e['is_request']:
            return None
        key = (e['src'], e['dst'], e['function_code'], e['address'], e['value'], e['tid'])
        now = e['ts']
        last = self.state.tid_history.get(key)
        if last is not None and (now - last) < self.state.replay_window:
            return {'rule_id': 'R009', 'description': f"Potential replay attack (TID {e['tid']})"}
        self.state.tid_history[key] = now
        return None

    def _check_excessive_requests(self, e):
        if not e['is_request']:
            return None
        now = e['ts']
        k = e['src']
        q = self.state.frequency_tracker[k]
        q.append(now)
        while q and now - q[0] > self.state.freq_window:
            q.popleft()
        if len(q) > self.state.freq_max:
            return {'rule_id': 'R010', 'description': f"Excessive requests from {e['src']} ({len(q)} in {self.state.freq_window:.0f}s)"}
        return None

    def _check_vlan_violation(self, e, uid_to_vlan, pair_to_vlan):
        expected_vlan = self.ip_to_vlan.get(e['src'])
        actual_vlan = None
        if e['uid'] in uid_to_vlan:
            actual_vlan = uid_to_vlan.get(e['uid'])
        else:
            actual_vlan = pair_to_vlan.get(f"{e['src']}-{e['dst']}")
        if expected_vlan and actual_vlan and actual_vlan != expected_vlan:
            return {'rule_id': 'R012', 'description': f"VLAN violation: expected {expected_vlan}, saw {actual_vlan}"}
        return None

    def _check_tid_patterns(self, e):
        if not e['is_request']:
            return None
        src, tid = e['src'], e['tid']
        last_tid = self.state.last_tid_per_source.get(src)
        if last_tid is not None:
            if tid < last_tid and (last_tid - tid) < self.state.tid_reset_jump:
                return {'rule_id': 'R013', 'description': f"Non-sequential TID pattern from {src}. Last: {last_tid}, Now: {tid}"}
        self.state.last_tid_per_source[src] = tid
        return None

    def _check_state_transition_timing(self, e):
        if not (e.get('is_request') and e['function_code'] == 6):
            return None

        current_value, current_time = e['value'], e['ts']
        connection_key = f"{e['uid']}_state_transition"
        self.state.add_write_event(connection_key, current_value, current_time)
        history = self.state.get_write_history(connection_key)
        if len(history) < 2:
            return None

        last_value, last_time = history[-2]
        time_diff = current_time - last_time
        trans_rules = self.write_value_rules.get('state_transitions', {})

        # keys may be strings; normalize
        last_key = str(last_value)
        curr_key = str(current_value)
        if last_key in trans_rules and curr_key in trans_rules.get(last_key, {}):
            for window in trans_rules[last_key][curr_key]:
                if not (window['min_time'] <= time_diff <= window['max_time']):
                    continue
                if 'preceded_by' in window:
                    if len(history) < 3:
                        continue
                    gp_val, gp_time = history[-3]
                    ctx = window['preceded_by']
                    if gp_val == ctx['state'] and (ctx['min_time'] <= (last_time - gp_time) <= ctx['max_time']):
                        return None
                else:
                    return None
            return {'rule_id': 'R015', 'description': f'State transition context/timing violation: {last_value} -> {current_value} in {time_diff:.2f}s'}
        else:
            return {'rule_id': 'R015', 'description': f'Undefined state transition: {last_value} -> {current_value}'}

    def _check_polling_sequence(self, e):
        if not (e.get('is_request') and e['function_code'] in [1,2,3,4]):
            return None

        current_time, current_func, uid = e['ts'], e['func_text'], e['uid']
        key = f"{uid}_polling"
        sequences = self.polling_rules.get('sequences', [])
        if not sequences:
            return None

        st = self.state.polling_state.get(key)
        if not st:
            for seq in sequences:
                try:
                    idx = seq['function_sequence'].index(current_func)
                    self.state.polling_state[key] = {'last_time': current_time, 'index': idx, 'active_sequence_name': seq['name']}
                    return None
                except ValueError:
                    continue
            return {'rule_id': 'R016', 'description': f'Polling violation: initial command ({current_func}) not in defined sequences.'}

        last_time = st['last_time']
        last_index = st['index']
        active = next((s for s in sequences if s['name'] == st['active_sequence_name']), None)
        if not active:
            self.state.reset_polling_state(uid)
            return {'rule_id': 'R016', 'description': 'Internal polling error: active sequence missing.'}

        func_seq = active['function_sequence']
        interval = active['inter_request_interval']  # {min_time, max_time}
        expected_index = (last_index + 1) % len(func_seq)
        expected_func = func_seq[expected_index]

        time_diff = current_time - last_time
        if current_func == expected_func:
            if not (interval['min_time'] <= time_diff <= interval['max_time']):
                self.state.reset_polling_state(uid)
                return {'rule_id': 'R016', 'description': f'Polling rhythm broken: {time_diff:.3f}s interval'}
            self.state.polling_state[key]['last_time'] = current_time
            self.state.polling_state[key]['index'] = expected_index
            return None
        else:
            # try to resynchronize to a different known sequence
            for seq in sequences:
                try:
                    idx = seq['function_sequence'].index(current_func)
                    self.state.polling_state[key] = {'last_time': current_time, 'index': idx, 'active_sequence_name': seq['name']}
                    return None
                except ValueError:
                    continue
            self.state.reset_polling_state(uid)
            return {'rule_id': 'R016', 'description': f'Polling violation: expected {expected_func}, got {current_func}'}

    # ---------- Orchestration ----------

    def analyze_log(self, log_file, vlan_map_file):
        events = self._parse_modbus_log(log_file)
        uid_to_vlan, pair_to_vlan = self._load_vlan_map(vlan_map_file)

        for e in events:
            checks = [
                self._check_unauthorized_ip,
                self._check_illegal_function,
                self._check_unauthorized_write,
                self._check_abnormal_process_value,
                self._check_physical_tampering,
                self._check_replay_attack,
                self._check_excessive_requests,
                self._check_tid_patterns,
                self._check_state_transition_timing,
                self._check_polling_sequence,
            ]

            # VLAN violation (uses UID map if available)
            vlan_violation = self._check_vlan_violation(e, uid_to_vlan, pair_to_vlan)
            if vlan_violation:
                vlan_violation.update({
                    'severity': self._severity('R012', 'high'),
                    'src': e['src'], 'dst': e['dst'],
                    'function_code': e['function_code'], 'address': e['address'], 'timestamp': e['ts']
                })
                self.alerts.append(vlan_violation)

            for fn in checks:
                v = fn(e)
                if v:
                    v.update({
                        'severity': v.get('severity', self._severity(v['rule_id'], 'medium')),
                        'src': e['src'], 'dst': e['dst'],
                        'function_code': e['function_code'], 'address': e['address'],
                        'timestamp': e['ts'], 'uid': e.get('uid',''), 'value': e.get('value', None), 'tid': e.get('tid', None)
                    })
                    self.alerts.append(v)

            # Any write resets polling & tid checks
            if e['function_code'] in [5, 6, 15, 16]:
                self.state.reset_polling_state(e['uid'])
                self.state.reset_tid_state(e['src'])

        return self.alerts

# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="Policy-Driven ICS Detection Engine")
    ap.add_argument('--log', required=True)
    ap.add_argument('--policy', required=True)
    ap.add_argument('--addrmap', required=True)
    ap.add_argument('--vlan-map', required=True, help="UID→VLAN or pair→VLAN map file")
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    det = Detector(args.policy, args.addrmap)
    alerts = det.analyze_log(args.log, args.vlan_map)

    with open(args.out, 'w') as f:
        json.dump(alerts, f, indent=2)

    print(f"[+] Detection complete: {len(alerts)} alerts → {args.out}")

if __name__ == "__main__":
    main()
