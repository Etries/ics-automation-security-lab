#!/usr/bin/env python3
"""
Universal Context-Aware ICS Detection Engine

"""

import argparse
import yaml
import json
from collections import defaultdict, deque

class StateTracker:
    """Tracks process state and timing for context-aware detection"""
    def __init__(self):
        self.write_history = defaultdict(lambda: deque(maxlen=3))
        self.polling_state = {}
        self.tid_history = {}
        self.frequency_tracker = defaultdict(lambda: deque(maxlen=100))
        self.last_known_values = {}
        self.last_tid_per_source = {}

    def add_write_event(self, connection_key, value, timestamp):
        self.write_history[connection_key].append((value, timestamp))

    def get_write_history(self, connection_key):
        return list(self.write_history[connection_key])

    def reset_polling_state(self, connection_key):
        polling_conn_key = f"{connection_key}_polling"
        if polling_conn_key in self.polling_state:
            del self.polling_state[polling_conn_key]
            
    def reset_tid_state(self, source_ip):
        """Explicitly resets the TID tracker for a given source IP."""
        if source_ip in self.last_tid_per_source:
            del self.last_tid_per_source[source_ip]

class FixedUniversalDetector:
    """Fixed universal detection engine for any ICS"""
    def __init__(self, policy_file, addr_map_file):
        self.policy = self._load_yaml(policy_file)
        self.addr_map = self._load_yaml(addr_map_file)
        self.state_tracker = StateTracker()
        self.alerts = []
        self.authorized_registers = {
        ip: set(regs) for ip, regs in self.policy.get('network', {}).get('authorized_registers', {}).items()}


    def _load_yaml(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[FATAL] Could not load {file_path}: {e}")
            exit(1)
            
    def _load_vlan_map(self, vlan_file):
        vlan_map = {}
        try:
            with open(vlan_file) as f:
                for line in f:
                    if '\t' in line and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 3:
                            src_ip, dst_ip, vlan_id = parts[0], parts[1], parts[2]
                            if vlan_id.isdigit():
                                vlan_map[f"{src_ip}-{dst_ip}"] = int(vlan_id)
        except Exception as e:
            print(f"[WARN] Could not load VLAN map file '{vlan_file}': {e}")
        return vlan_map

    def _parse_modbus_log(self, log_file):
        events = []
        func_code_map = {
            'READ_COILS': 1, 'READ_DISCRETE_INPUTS': 2, 'READ_HOLDING_REGISTERS': 3,
            'READ_INPUT_REGISTERS': 4, 'WRITE_SINGLE_COIL': 5, 'WRITE_SINGLE_REGISTER': 6,
            'WRITE_MULTIPLE_COILS': 15, 'WRITE_MULTIPLE_REGISTERS': 16
        }
        try:
            with open(log_file) as f:
                header_lines, data_lines = [], []
                for line in f:
                    (header_lines if line.startswith('#') else data_lines).append(line.strip())
                
                field_names = []
                for line in header_lines:
                    if line.startswith('#fields'):
                        field_names = line.split('\t')[1:]
                        break
                if not field_names:
                     print("[FATAL] Log file has no #fields header. Cannot parse.")
                     exit(1)

                for line_num, line in enumerate(data_lines, 1):
                    if not line.strip(): continue
                    parts = line.strip().split('\t')
                    if len(parts) < len(field_names): continue
                    try:
                        event_data = dict(zip(field_names, parts))
                        func_text = event_data.get('func', '')
                        parsed_event = {
                            'ts': float(event_data.get('ts', 0)), 'uid': event_data.get('uid', ''),
                            'src': event_data.get('id.orig_h', ''), 'dst': event_data.get('id.resp_h', ''),
                            'function_code': func_code_map.get(func_text, -1),
                            'address': int(event_data.get('address', -1)) if event_data.get('address', '-').isdigit() else -1,
                            'value': int(event_data.get('values', '0').split(',')[0]) if event_data.get('values', '-').replace(',','').isdigit() else 0,
                            'tid': int(event_data.get('tid', 0)) if event_data.get('tid', '0').isdigit() else 0,
                            'is_request': event_data.get('request_response') == 'REQUEST', 'func_text': func_text
                        }
                        if parsed_event['function_code'] > 0: events.append(parsed_event)
                    except (ValueError, IndexError): continue
        except Exception as e:
            print(f"[FATAL] Could not read log file: {e}")
            exit(1)
        return events

    # --- DETECTION RULE IMPLEMENTATIONS ---

    def _check_unauthorized_write(self, event):
        if not event['is_request'] or event['function_code'] != 6: return None
    #    if event['address'] == 1024 and event['src'] != '10.10.20.30':
    #        return {'rule_id': 'R005', 'description': f"Role violation: Unauthorized IP {event['src']} attempted to write to command register."}
             
        allowed_regs = self.authorized_registers.get(event['src'])
        if allowed_regs is not None and event['address'] not in allowed_regs:
            return {
                'rule_id': 'R005',
                'description': (
                    f"Role violation: Unauthorized IP {event['src']} wrote "
                    f"register {event['address']}"
                    )
            }
             
             
             
        for reg in self.policy.get('registers', []):
            if reg['address'] == event['address'] and reg.get('access') == 'read-only':
                return {'rule_id': 'R001', 'description': f"Unauthorized write attempt to read-only register {event['address']}"}
        return None

    def _check_abnormal_process_value(self, event):
        if not event['is_request']: return None
        for reg in self.policy.get('registers', []):
            if reg['address'] == event['address'] and 'value_range' in reg:
                min_val, max_val = reg['value_range']
                if not (min_val <= event['value'] <= max_val):
                    return {'rule_id': 'R002', 'description': f"Abnormal process value {event['value']} for register {event['address']}"}
        return None

    def _check_physical_tampering(self, event):
        if not event['is_request']: return None
        addr, value, ts = event['address'], event['value'], event['ts']
        self.state_tracker.last_known_values[addr] = (value, ts)
        if addr == 100 and value >= 80:
            alarm_state = self.state_tracker.last_known_values.get(200)
            if alarm_state and alarm_state[0] == 0 and abs(ts - alarm_state[1]) < 5.0:
                return {'rule_id': 'R003', 'description': 'Physical tampering suspected: Tank level is high but full alarm is FALSE.'}
        return None

    def _check_illegal_function(self, event):
        if not event['is_request']: return None
        allowed = self.policy.get('protocol', {}).get('allowed_funcs', [])
        if event['function_code'] not in allowed:
            return {'rule_id': 'R006', 'description': f"Illegal function code used: {event['function_code']}"}
        return None

    def _check_replay_attack(self, event):
        if not event['is_request']: return None
        key = (event['src'], event['dst'], event['function_code'], event['address'], event['value'], event['tid'])
        now = event['ts']
        if key in self.state_tracker.tid_history:
            last_seen = self.state_tracker.tid_history[key]
            if now - last_seen < 2.0:
                return {'rule_id': 'R009', 'description': f"Potential replay attack detected for TID {event['tid']}"}
        self.state_tracker.tid_history[key] = now
        return None
        
    def _check_excessive_requests(self, event):
        if not event['is_request']: return None
        now = event['ts']
        key = event['src']
        self.state_tracker.frequency_tracker[key].append(now)
        while self.state_tracker.frequency_tracker[key] and now - self.state_tracker.frequency_tracker[key][0] > 5.0:
            self.state_tracker.frequency_tracker[key].popleft()
        if len(self.state_tracker.frequency_tracker[key]) > 40:
            return {'rule_id': 'R010', 'description': f"Excessive requests from {event['src']} ({len(self.state_tracker.frequency_tracker[key])} in 5s)"}
        return None

    def _check_vlan_violation(self, event, vlan_map):
        expected_vlan = self.policy.get('network', {}).get('ip_to_vlan_map', {}).get(event['src'])
        connection_key = f"{event['src']}-{event['dst']}"
        actual_vlan = vlan_map.get(connection_key)
        if expected_vlan and actual_vlan and actual_vlan != expected_vlan:
            return {'rule_id': 'R012', 'description': f"VLAN violation: Expected {expected_vlan}, saw {actual_vlan}"}
        return None
        
    def _check_tid_patterns(self, event):
        if not event['is_request']: return None
        src, tid = event['src'], event['tid']
        last_tid = self.state_tracker.last_tid_per_source.get(src)
        
        if last_tid is not None:
            # Allow for a large downward jump in TID, which indicates a legitimate counter reset by the client.
            # A small downward jump is still considered an anomaly.
            if tid < last_tid and (last_tid - tid) < 250:
                 return {'rule_id': 'R013', 'description': f"Non-sequential TID pattern from {src}. Last: {last_tid}, Current: {tid}"}
        
        self.state_tracker.last_tid_per_source[src] = tid
        return None

    def _check_unauthorized_ip(self, event):
        authorized_ips = self.policy.get('network', {}).get('authorized_ips', [])
        if event['src'] not in authorized_ips:
            return {'rule_id': 'R014', 'description': f"Communication from unauthorized IP: {event['src']}"}
        return None

    def _check_state_transition_timing(self, event):
        if not event.get('is_request', False) or event['function_code'] != 6: return None
        current_value, current_time = event['value'], event['ts']
        connection_key = f"{event['uid']}_state_transition"
        self.state_tracker.add_write_event(connection_key, current_value, current_time)
        history = self.state_tracker.get_write_history(connection_key)
        if len(history) < 2: return None
        
        last_value, last_time = history[-2]
        time_diff = current_time - last_time
        rules = self.policy.get('write_value_rules', {})
        state_transitions = rules.get('state_transitions', {})
        
        if str(last_value) in state_transitions and str(current_value) in state_transitions.get(str(last_value), {}):
            valid_windows = state_transitions[str(last_value)][str(current_value)]
            
            matched_rule = False
            for window in valid_windows:
                direct_timing_ok = window['min_time'] <= time_diff <= window['max_time']
                if not direct_timing_ok: continue

                if 'preceded_by' in window:
                    if len(history) < 3: continue
                    grandparent_value, grandparent_time = history[-3]
                    context_rule = window['preceded_by']
                    context_state_ok = grandparent_value == context_rule['state']
                    context_time_diff = last_time - grandparent_time
                    context_timing_ok = context_rule['min_time'] <= context_time_diff <= context_rule['max_time']
                    if context_state_ok and context_timing_ok:
                        matched_rule = True
                        break
                else:
                    matched_rule = True
                    break
            
            if not matched_rule:
                return {'rule_id': 'R015', 'description': f'State transition context/timing violation: {last_value} -> {current_value} in {time_diff:.1f}s'}
        else:
            return {'rule_id': 'R015', 'description': f'Undefined state transition: {last_value} -> {current_value}'}
        return None

    def _check_polling_sequence(self, event):
        if not event.get('is_request', False) or event['function_code'] not in [1, 2, 3, 4]: return None
        current_time, current_func, uid = event['ts'], event['func_text'], event['uid']
        connection_key = f"{uid}_polling"
        polling_rules = self.policy.get('polling_rules', {})
        sequences = polling_rules.get('sequences', [])
        if not sequences: return None
        
        current_polling_state = self.state_tracker.polling_state.get(connection_key)

        if not current_polling_state:
            for seq in sequences:
                try:
                    idx = seq['function_sequence'].index(current_func)
                    self.state_tracker.polling_state[connection_key] = {'last_time': current_time, 'index': idx, 'active_sequence_name': seq['name']}
                    return None
                except ValueError: continue
            return {'rule_id': 'R016', 'description': f'Polling sequence violation: initial command ({current_func}) not in any defined sequence.'}

        last_time = current_polling_state['last_time']
        last_index = current_polling_state['index']
        active_seq_name = current_polling_state['active_sequence_name']
        time_diff = current_time - last_time
        active_sequence = next((s for s in sequences if s['name'] == active_seq_name), None)
        
        if not active_sequence:
            self.state_tracker.reset_polling_state(uid)
            return {'rule_id': 'R016', 'description': 'Internal error: active sequence not found.'}

        func_seq = active_sequence['function_sequence']
        interval = active_sequence['inter_request_interval']
        expected_index = (last_index + 1) % len(func_seq)
        expected_func = func_seq[expected_index]

        if current_func == expected_func:
            if not (interval['min_time'] <= time_diff <= interval['max_time']):
                self.state_tracker.reset_polling_state(uid)
                return {'rule_id': 'R016', 'description': f'Polling rhythm broken: {time_diff:.3f}s interval'}
            else:
                self.state_tracker.polling_state[connection_key]['last_time'] = current_time
                self.state_tracker.polling_state[connection_key]['index'] = expected_index
                return None
        else:
            for seq in sequences:
                try:
                    idx = seq['function_sequence'].index(current_func)
                    self.state_tracker.polling_state[connection_key] = {'last_time': current_time, 'index': idx, 'active_sequence_name': seq['name']}
                    return None
                except ValueError: continue
            
            alert = {'rule_id': 'R016', 'description': f'Polling sequence violation: expected {expected_func}, got {current_func}'}
            self.state_tracker.reset_polling_state(uid)
            return alert

    def analyze_log(self, log_file, vlan_map_file):
        print(f"[*] Loading and analyzing {log_file}...")
        events = self._parse_modbus_log(log_file)
        vlan_map = self._load_vlan_map(vlan_map_file)
        print(f"[*] Found {len(events)} valid Modbus events")

        for event in events:
            all_checks = [
                self._check_unauthorized_write, self._check_abnormal_process_value,
                self._check_physical_tampering, self._check_illegal_function,
                self._check_replay_attack, self._check_excessive_requests,
                self._check_tid_patterns, self._check_unauthorized_ip,
                self._check_state_transition_timing, self._check_polling_sequence,
            ]
            
            vlan_violation = self._check_vlan_violation(event, vlan_map)
            if vlan_violation:
                vlan_violation.update({
                    'severity': 'high', 'src': event['src'], 'dst': event['dst'],
                    'function_code': event['function_code'], 'address': event['address'], 'timestamp': event['ts']
                })
                self.alerts.append(vlan_violation)

            for check_function in all_checks:
                violation = check_function(event)
                if violation:
                    violation.update({
                        'severity': violation.get('severity', 'medium'), 'src': event['src'], 'dst': event['dst'],
                        'function_code': event['function_code'], 'address': event['address'], 'timestamp': event['ts']
                    })
                    self.alerts.append(violation)

            if event['function_code'] in [5, 6, 15, 16]:
                self.state_tracker.reset_polling_state(event['uid'])
                self.state_tracker.reset_tid_state(event['src'])

        return self.alerts

def main():
    parser = argparse.ArgumentParser(description="Fixed Universal ICS Detection Engine")
    parser.add_argument('--log', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--addrmap', required=True)
    parser.add_argument('--vlan-map', required=True, help="Path to VLAN mapping file")
    parser.add_argument('--out', required=True)
    args = parser.parse_args()

    print("=" * 60 + "\nFixed Universal ICS Detection Engine\n" + "=" * 60)
    detector = FixedUniversalDetector(args.policy, args.addrmap)
    alerts = detector.analyze_log(args.log, args.vlan_map)

    with open(args.out, 'w') as f: json.dump(alerts, f, indent=2)
    print(f"\n[+] Analysis complete!\n[+] Found {len(alerts)} alerts\n[+] Report saved to {args.out}")
    if alerts:
        print("\n[*] Alert Summary:")
        for alert in alerts: print(f"  - {alert['rule_id']}: {alert['description']}")
    else:
        print("\n[+] SUCCESS: Zero alerts detected (no false positives)")

if __name__ == "__main__":
    main()
