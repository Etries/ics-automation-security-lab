# incident_builder.py (Hybrid Version)

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

def parse_time(ts):
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace('.', '', 1).isdigit()):
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        return datetime.min

def generate_incident_id(alerts):
    base = '|'.join(sorted(str(a.get('uid', '')) for a in alerts))
    base += '|'.join(sorted(str(a.get('src_ip', '')) for a in alerts))
    base += '|'.join(sorted(str(a.get('register', '')) for a in alerts))
    return hashlib.sha256(base.encode()).hexdigest()[:12] or str(uuid.uuid4())

def group_alerts(alerts, window_sec=60):
    uid_groups = defaultdict(list)
    non_uid_alerts = []

    for alert in alerts:
        if alert.get('uid'):
            uid_groups[alert['uid']].append(alert)
        else:
            non_uid_alerts.append(alert)

    time_groups = defaultdict(list)
    for alert in non_uid_alerts:
        key = (alert.get('src_ip'), alert.get('register'))
        ts = parse_time(alert.get('timestamp'))
        time_groups[key].append((ts, alert))

    grouped = []
    for key, items in time_groups.items():
        # FIX: Add sorting key for timestamps to avoid TypeError
        items.sort(key=lambda x: x[0])
        group = []
        last_ts = None
        for ts, alert in items:
            if not group:
                group = [alert]
                last_ts = ts
            elif (ts - last_ts).total_seconds() <= window_sec:
                group.append(alert)
                last_ts = ts
            else:
                grouped.append(group)
                group = [alert]
                last_ts = ts
        if group:
            grouped.append(group)

    for group in uid_groups.values():
        grouped.append(group)
    return grouped

def summarize_incident(alerts):
    rules = sorted(set(a.get('rule_id') for a in alerts))
    roles = sorted(set(a.get('role') for a in alerts))
    registers = sorted(set(a.get('register') for a in alerts))
    severities = sorted(set(a.get('severity') for a in alerts if a.get('severity')))
    mitre = sorted(set(str(a.get('mitre')) for a in alerts if a.get('mitre')))
    nis2 = sorted(set(a.get('nis2_article') for a in alerts if a.get('nis2_article')))
    reasons = [a.get('reason') for a in alerts if a.get('reason')]
    return {
        'rules_triggered': rules,
        'roles_affected': roles,
        'registers_affected': registers,
        'severities': severities,
        'mitre_tags': mitre,
        'nis2_articles': nis2,
        'alert_count': len(alerts),
        'summary': reasons
    }

def build_incident_report(alerts, window_sec=60):
    groups = group_alerts(alerts, window_sec=window_sec)
    reports = []

    for group in groups:
        times = [parse_time(a.get('timestamp')) for a in group]
        start = min(times).isoformat() + 'Z' if times else None
        end = max(times).isoformat() + 'Z' if times else None
        inc_id = generate_incident_id(group)
        summary = summarize_incident(group)
        reports.append({
            'incident_id': inc_id,
            'start_time': start,
            'end_time': end,
            'src_ip': group[0].get('src_ip'),
            'dst_ip': group[0].get('dst_ip'),
            'involved_registers': summary['registers_affected'],
            'involved_roles': summary['roles_affected'],
            'severity': summary['severities'][-1] if summary['severities'] else 'low',
            'nis2_articles': summary['nis2_articles'],
            'mitre_techniques': summary['mitre_tags'],
            'rule_ids': summary['rules_triggered'],
            'incident_summary': summary['summary'],
            'alert_count': summary['alert_count'],
            'alerts': group
        })
    return reports

def save_incident_report(reports, output_file):
    with open(output_file, 'w') as f:
        json.dump(reports, f, indent=2)
    print(f"[incident_builder] Saved {len(reports)} incident(s) to {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Incident Report Generator")
    parser.add_argument('--alerts', required=True, help='Input alerts JSON file')
    parser.add_argument('--out', required=True, help='Output incident report JSON file')
    parser.add_argument('--window', type=int, default=60, help='Time window (seconds) for grouping non-UID alerts')
    args = parser.parse_args()

    with open(args.alerts, 'r') as f:
        alerts = json.load(f)

    reports = build_incident_report(alerts, window_sec=args.window)
    save_incident_report(reports, args.out)

