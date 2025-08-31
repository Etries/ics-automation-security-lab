#!/usr/bin/env python3
import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

def parse_iso_time(ts_str):
    """Safely parse ISO 8601 timestamps, handling potential errors."""
    try:
        # The 'Z' indicates UTC, which is what fromisoformat expects.
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        # Return a very old time if parsing fails, so it doesn't interfere with min/max
        return datetime.fromtimestamp(0, tz=timezone.utc)

def generate_incident_id(alerts):
    """Creates a stable, unique ID for a group of alerts."""
    # Create a consistent string based on the core components of the alerts
    components = []
    for alert in sorted(alerts, key=lambda x: x['timestamp']):
        components.append(f"{alert['rule_id']}-{alert['src_ip']}-{alert['register']}-{alert['timestamp']}")
    
    # Hash the string to create a short, unique ID
    incident_string = "|".join(components)
    return hashlib.sha256(incident_string.encode()).hexdigest()[:16]

def group_alerts_into_incidents(alerts, time_window_seconds=300):
    """
    Groups alerts into incidents based on UID, IP pairs, and a time window.
    """
    if not alerts:
        return []

    # First, group all alerts by their Zeek UID. This is the strongest correlation.
    uid_groups = defaultdict(list)
    non_uid_alerts = []
    for alert in alerts:
        if alert.get('uid') and alert['uid'] != 'SYSTEM': # 'SYSTEM' is for supervisor-level alerts
            uid_groups[alert['uid']].append(alert)
        else:
            non_uid_alerts.append(alert)
            
    # Take the UID groups as initial incidents
    incidents = list(uid_groups.values())
    
    # Now, group the remaining alerts by source/destination and time
    # Sort alerts by timestamp to process them chronologically
    non_uid_alerts.sort(key=lambda x: parse_iso_time(x['timestamp']))

    if non_uid_alerts:
        current_incident = [non_uid_alerts[0]]
        last_alert_time = parse_iso_time(non_uid_alerts[0]['timestamp'])
        
        for alert in non_uid_alerts[1:]:
            current_alert_time = parse_iso_time(alert['timestamp'])
            time_delta = (current_alert_time - last_alert_time).total_seconds()
            
            # If the new alert is within the time window and shares the same src/dst,
            # add it to the current incident.
            if (time_delta <= time_window_seconds and 
                alert.get('src_ip') == current_incident[0].get('src_ip') and 
                alert.get('dst_ip') == current_incident[0].get('dst_ip')):
                current_incident.append(alert)
            else:
                # Otherwise, the current incident is finished. Start a new one.
                incidents.append(current_incident)
                current_incident = [alert]
            
            last_alert_time = current_alert_time
        
        # Add the last incident group
        incidents.append(current_incident)
        
    return incidents

def build_incident_report(alerts, window_sec):
    """Orchestrates the creation of the final incident report."""
    incident_groups = group_alerts_into_incidents(alerts, window_sec)
    reports = []

    for group in incident_groups:
        if not group: continue

        # Summarize the collected information
        times = [parse_iso_time(a['timestamp']) for a in group]
        severities = [a.get('severity', 'low') for a in group]
        
        # Determine the highest severity for the overall incident
        sev_order = ['informational', 'low', 'medium', 'high', 'critical']
        highest_severity = 'informational'
        for s in severities:
            if sev_order.index(s) > sev_order.index(highest_severity):
                highest_severity = s

        report = {
            'incident_id': generate_incident_id(group),
            'start_time': min(times).isoformat(),
            'end_time': max(times).isoformat(),
            'severity': highest_severity,
            'source_ips': sorted(list(set(a['src_ip'] for a in group if a.get('src_ip')))),
            'destination_ips': sorted(list(set(a['dst_ip'] for a in group if a.get('dst_ip')))),
            'description': f"A potential security incident involving {len(group)} alert(s).",
            'rule_ids': sorted(list(set(a['rule_id'] for a in group))),
            'mitre_tactics': sorted(list(set(a['mitre']['tactic'] for a in group if a.get('mitre', {}).get('tactic')))),
            'mitre_techniques': sorted(list(set(a['mitre']['technique'] for a in group if a.get('mitre', {}).get('technique')))),
            'nis2_articles': sorted(list(set(a['nis2_article'] for a in group if a.get('nis2_article')))),
            'alerts': group # Include the raw alerts for drill-down
        }
        reports.append(report)
        
    return reports

def main():
    parser = argparse.ArgumentParser(description="Correlates alerts into security incidents.")
    parser.add_argument('--alerts', required=True, help='Input alert JSON file')
    parser.add_argument('--out', required=True, help='Output incident report JSON file')
    parser.add_argument('--window', type=int, default=300, help='Time window (seconds) for grouping alerts into an incident.')
    args = parser.parse_args()

    if not os.path.exists(args.alerts) or os.path.getsize(args.alerts) == 0:
        print(f"[incident_builder] Alert file is missing or empty. No incidents to report.")
        with open(args.out, 'w') as f: json.dump([], f) # Write an empty list
        return

    with open(args.alerts, 'r') as f:
        try:
            alerts = json.load(f)
        except json.JSONDecodeError:
            print(f"[incident_builder] Error decoding JSON from {args.alerts}. Creating empty report.")
            alerts = []

    if not alerts:
        print(f"[incident_builder] No alerts to process.")
        with open(args.out, 'w') as f: json.dump([], f)
        return

    reports = build_incident_report(alerts, window_sec=args.window)
    
    with open(args.out, 'w') as f:
        json.dump(reports, f, indent=2)
    
    print(f"[incident_builder] Processed {len(alerts)} alerts into {len(reports)} incident(s). Report saved to {args.out}")

if __name__ == "__main__":
    main()
