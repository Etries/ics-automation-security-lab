#!/usr/bin/env python3
"""
Incident Report Builder

DESCRIPTION:
- Correlates alerts into incidents
- Enriches alerts using policies + addr_map
- Produces JSON and optional HTML

NOTE:
- Works with a flat addr_map that mixes numeric register keys
  and an optional `assets:` sub-map, e.g.:

  1024: start_cmd
  100: tank_level
  assets:
    10.10.10.10: "PLC1 – OpenPLC Runtime"
"""

import argparse
import yaml
import json
import os
import hashlib
from datetime import datetime, timezone

class HybridIncidentBuilder:
    def __init__(self):
        self.mitre_mappings = {
            'TA0006': {'tactic': 'Impact','description': 'Adversary actions that result in disruption of availability or integrity'},
            'TA0007': {'tactic': 'Collection','description': 'Adversary techniques used to identify and gather information'},
            'TA0008': {'tactic': 'Lateral Movement','description': 'Adversary techniques that enable movement within the network'},
            'T0812': {'tactic': 'Collection','technique': 'Data from Information Repositories','description': 'Adversary access to system information and configuration data'},
            'T0815': {'tactic': 'Lateral Movement','technique': 'Replay','description': 'Adversary replay of captured communications to gain unauthorized access'},
            'T0831': {'tactic': 'Impact','technique': 'Manipulation of Control','description': 'Adversary manipulation of industrial control processes'}
        }
        self.nis2_mappings = {
            'Article 21':  {'article': 'Risk Management','description': 'Security risk management and assessment requirements','requirements': ['Risk assessment','Security measures','Incident detection']},
            'Article 21.b':{'article': 'Physical Security','description': 'Physical security and environmental protection requirements','requirements': ['Physical access controls','Environmental monitoring','Safety systems']},
            'Article 23':  {'article': 'Incident Reporting','description': 'Security incident detection and reporting requirements','requirements': ['Incident detection','Reporting procedures','Response coordination']}
        }
        self.impact_patterns = {
            'unauthorized': {'operational_impact':'high','safety_impact':'high','data_integrity':'high','system_availability':'medium','description':'Unauthorized access or control manipulation'},
            'replay':       {'operational_impact':'high','safety_impact':'high','data_integrity':'high','system_availability':'medium','description':'Replay attack - potential process manipulation'},
            'timing':       {'operational_impact':'high','safety_impact':'high','data_integrity':'high','system_availability':'medium','description':'Timing-based attack or process manipulation'},
            'network':      {'operational_impact':'medium','safety_impact':'medium','data_integrity':'high','system_availability':'medium','description':'Network segmentation or communication violation'},
            'dos':          {'operational_impact':'medium','safety_impact':'low','data_integrity':'low','system_availability':'high','description':'Denial of Service or excessive traffic'},
            'protocol':     {'operational_impact':'low','safety_impact':'low','data_integrity':'medium','system_availability':'low','description':'Protocol abuse or fuzzing attempt'}
        }

    # ---------- IO ----------

    def load_yaml(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[FATAL] Could not load YAML file {file_path}: {e}")
            exit(1)

    # ---------- ENRICHMENT / GROUPING ----------

    def _build_rule_map(self, policy):
        rule_map = {rule['id']: rule for rule in policy.get('global_rules', [])}

        for section in ['network_segmentation_rule','ip_whitelist_rule','function_code_rule',
                        'state_logic_rule','state_transition_rule','polling_sequence_rule']:
            if section in policy:
                rule = policy[section]
                if isinstance(rule, dict) and 'id' in rule:
                    rule_map[rule['id']] = rule

        for reg in policy.get('registers', []):
            for rule in reg.get('rules', []):
                if 'id' in rule:
                    rule_map[rule['id']] = rule
        return rule_map

    def enrich_alerts(self, alerts, policy, asset_map, register_map):
        """Attach description/severity/mitre/nis2 + asset/register names."""
        rule_map = self._build_rule_map(policy)
        enriched = []

        for alert in alerts:
            rule_id = alert.get('rule_id')
            rule_info = rule_map.get(rule_id, {})

            e = dict(alert)  # shallow copy
            e['description']  = rule_info.get('description', e.get('description', ''))
            e['severity']     = rule_info.get('severity',    e.get('severity', 'medium'))
            e['mitre']        = rule_info.get('mitre', {})
            e['nis2_article'] = rule_info.get('nis2_article')

            # src/dst asset names (by IP)
            src = e.get('src')
            dst = e.get('dst')
            if src: e['src_asset'] = asset_map.get(src, 'unknown_asset')
            if dst: e['dst_asset'] = asset_map.get(dst, 'unknown_asset')

            # register semantic name (by numeric address)
            if 'address' in e and e['address'] is not None:
                addr = e['address']
                # try int key first, then string fallback
                reg_name = register_map.get(addr)
                if reg_name is None:
                    try:
                        reg_name = register_map.get(int(addr))
                    except Exception:
                        pass
                if reg_name is None:
                    reg_name = register_map.get(str(addr))
                e['register_name'] = reg_name if reg_name is not None else 'unknown_register'

            enriched.append(e)
        return enriched

    def group_alerts_into_incidents(self, alerts, time_window_seconds=300):
        if not alerts: return []
        alerts.sort(key=lambda x: x['timestamp'])
        incidents = []
        current = [alerts[0]]

        for i in range(1, len(alerts)):
            a, b = current[-1], alerts[i]
            is_related = ((a.get('src') == b.get('src') and a.get('dst') == b.get('dst')) or
                          (a.get('uid') and a.get('uid') == b.get('uid')))
            if (b['timestamp'] - a['timestamp']) <= time_window_seconds and is_related:
                current.append(b)
            else:
                incidents.append(current)
                current = [b]
        incidents.append(current)
        return incidents

    # ---------- INCIDENT CONSTRUCTION ----------

    def generate_incident_id(self, alerts):
        parts = [f"{a['rule_id']}-{a.get('src','')}-{a.get('address','')}-{a['timestamp']}"
                 for a in sorted(alerts, key=lambda x: x['timestamp'])]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def build_detailed_incident(self, group):
        if not group: return None

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{self.generate_incident_id(group)}"
        sev_order = ['informational','low','medium','high','critical']
        highest = 'informational'
        for s in [a.get('severity','low') for a in group]:
            if s in sev_order and sev_order.index(s) > sev_order.index(highest):
                highest = s

        start = datetime.fromtimestamp(min(a['timestamp'] for a in group), tz=timezone.utc)
        end   = datetime.fromtimestamp(max(a['timestamp'] for a in group), tz=timezone.utc)
        primary = group[0]

        timeline = [{
            "timestamp": datetime.fromtimestamp(a['timestamp'], tz=timezone.utc).isoformat(),
            "rule_id": a['rule_id'],
            "description": a['description'],
            "source": f"{a.get('src_asset','N/A')} ({a.get('src','N/A')})",
            "target": f"{a.get('dst_asset','N/A')} ({a.get('dst','N/A')})",
            "details": f"Register: {a.get('register_name','N/A')} ({a.get('address','N/A')}), Value: {a.get('value','N/A')}"
        } for a in group]

        incident = {
            'incident_id': incident_id,
            'start_time': start.isoformat(),
            'end_time': end.isoformat(),
            'duration_seconds': (end - start).total_seconds(),
            'severity': highest,
            'alert_count': len(group),

            'summary': f"A potential security incident involving {len(group)} correlated alerts, primarily related to rule(s): {', '.join(sorted(set(a['rule_id'] for a in group)))}.",
            'affected_assets': sorted(set(a.get('dst_asset','unknown') for a in group)),
            'source_assets':   sorted(set(a.get('src_asset','unknown') for a in group)),
            'triggered_rules': sorted(set(a['rule_id'] for a in group)),

            'source_ip': primary.get('src',''),
            'destination_ip': primary.get('dst',''),
            'function_code': primary.get('function_code',''),
            'register_address': primary.get('address',''),
            'register_value': primary.get('value',''),
            'transaction_id': primary.get('tid',''),

            'mitre_attack': self._get_mitre_info(primary.get('mitre', {})),
            'nis2_compliance': self._get_nis2_info(primary.get('nis2_article','')),
            'impact_assessment': self._assess_impact(primary.get('rule_id',''), primary),
            'recommendations': self._generate_recommendations(primary.get('rule_id',''), primary),
            'false_positive_risk': self._assess_false_positive_risk(primary),
            'confidence_score': self._calculate_confidence(primary),

            'response_time': self._get_response_time(highest),
            'response_priority': self._determine_response_priority(primary),

            'timeline': timeline,
            'detection_method': 'passive_network_analysis',
            'tags': self._generate_tags(primary),
            'related_incidents': [],
            'status': 'open'
        }
        return incident

    # ---------- ANALYTICS HELPERS ----------

    def _get_mitre_info(self, mitre_data):
        tactic_id = mitre_data.get('tactic','')
        technique_id = mitre_data.get('technique','')
        return {
            'tactic_id': tactic_id,
            'tactic_name': self.mitre_mappings.get(tactic_id,{}).get('tactic','Unknown'),
            'tactic_description': self.mitre_mappings.get(tactic_id,{}).get('description',''),
            'technique_id': technique_id,
            'technique_name': self.mitre_mappings.get(technique_id,{}).get('technique','Unknown'),
            'technique_description': self.mitre_mappings.get(technique_id,{}).get('description',''),
            'real_world_example': mitre_data.get('real_world','Unknown')
        }

    def _get_nis2_info(self, article_id):
        info = self.nis2_mappings.get(article_id, {})
        return {'article_id': article_id,'article_name': info.get('article','Unknown'),
                'description': info.get('description',''), 'requirements': info.get('requirements',[])}

    def _assess_impact(self, rule_id, alert):
        desc = alert.get('description','').lower()
        reg  = (alert.get('register_name') or '').lower()
        if 'unauthorized' in desc or 'unauth' in desc: key = 'unauthorized'
        elif 'replay' in desc: key = 'replay'
        elif 'timing' in desc or 'transition' in desc: key = 'timing'
        elif 'vlan' in desc or 'network' in desc: key = 'network'
        elif 'excessive' in desc or 'dos' in desc: key = 'dos'
        elif 'illegal' in desc or 'protocol' in desc: key = 'protocol'
        else:
            if 'control' in reg: key = 'unauthorized'
            elif 'sensor' in reg: key = 'timing'
            else: key = 'network'
        impact = dict(self.impact_patterns.get(key, {}))
        if not impact:
            impact = {'operational_impact':'unknown','safety_impact':'unknown','data_integrity':'unknown','system_availability':'unknown','description':'Unknown impact assessment'}
        impact['affected_component'] = self._identify_affected_component(alert)
        impact['potential_consequences'] = self._assess_potential_consequences(rule_id, alert)
        return impact

    def _identify_affected_component(self, alert):
        reg = (alert.get('register_name') or '').lower()
        fc = alert.get('function_code','')
        if 'control' in reg: return f'Control Register ({alert.get("register_name","")})'
        if 'sensor'  in reg: return f'Sensor ({alert.get("register_name","")})'
        if 'actuator'in reg: return f'Actuator ({alert.get("register_name","")})'
        if 'valve'   in reg: return f'Valve ({alert.get("register_name","")})'
        if 'pump'    in reg: return f'Pump ({alert.get("register_name","")})'
        if fc in [1,2,3,4]:  return 'Monitoring System'
        return f'Unknown Component ({alert.get("register_name","")})'

    def _assess_potential_consequences(self, rule_id, alert):
        out, desc, reg = [], (alert.get('description','').lower()), (alert.get('register_name','').lower())
        if 'control' in reg or 'unauthorized' in desc:
            out += ['Process disruption or shutdown','Safety system bypass','Unauthorized control access','Potential equipment damage']
        elif 'sensor' in reg or 'sensor' in desc:
            out += ['Incorrect process decisions','Safety system malfunction','Sensor/actuator manipulation','Process instability']
        elif 'replay' in desc:
            out += ['Replay attack execution','Process manipulation','Unauthorized command execution','System compromise']
        elif 'excessive' in desc or 'dos' in desc:
            out += ['System performance degradation','Communication disruption','Monitoring system failure','DoS conditions']
        elif 'network' in desc or 'vlan' in desc:
            out += ['Network segmentation bypass','Unauthorized device access','Communication interception','Network infrastructure compromise']
        else:
            out += ['System security compromise','Process manipulation','Data integrity violation','Operational disruption']
        return out

    def _generate_recommendations(self, rule_id, alert):
        rec, desc, reg = [], (alert.get('description','').lower()), (alert.get('register_name','').lower())
        if 'unauthorized' in desc or 'control' in reg:
            rec += ['Immediately investigate the source IP for unauthorized access','Review network access controls and VLAN segmentation','Implement additional authentication for control registers','Monitor for similar unauthorized access attempts','Consider implementing role-based access control (RBAC)']
        elif 'sensor' in reg or 'sensor' in desc:
            rec += ['Verify sensor readings and physical system state','Check for sensor tampering or malfunction','Review physical security controls','Implement sensor redundancy and validation','Monitor for similar physical tampering attempts']
        elif 'replay' in desc:
            rec += ['Investigate potential network interception or spoofing','Verify network integrity and routing configuration','Implement network monitoring for MITM detection','Check for unauthorized network devices','Consider implementing encrypted Modbus communications']
        elif 'excessive' in desc or 'dos' in desc:
            rec += ['Investigate source of high-frequency traffic','Check for potential DoS attack or malfunctioning device','Implement rate limiting on Modbus communications','Monitor system performance for degradation','Review network bandwidth and capacity']
        elif 'network' in desc or 'vlan' in desc:
            rec += ['Verify network segmentation and VLAN configuration','Review authorized IP lists and access controls','Implement network monitoring for unauthorized devices','Check for device spoofing or network misconfiguration','Consider implementing network access control (NAC)']
        elif 'timing' in desc or 'transition' in desc:
            rec += ['Investigate timing anomalies in process control','Review process control logic and timing requirements','Monitor for process manipulation attempts','Implement additional timing validation','Consider implementing process control redundancy']
        else:
            rec += ['Investigate the source and nature of the security violation','Review security policies and access controls','Implement additional monitoring for similar activities','Consider implementing enhanced security measures']
        rec += ['Document incident details and response actions','Update security policies and procedures','Conduct post-incident review and lessons learned','Consider implementing additional monitoring and alerting']
        return rec

    def _assess_false_positive_risk(self, alert):
        risk_factors, score = [], 0
        src_asset = (alert.get('src_asset') or '')
        if 'authorized' in src_asset.lower() or 'hmi' in src_asset.lower():
            risk_factors.append('Source IP is in authorized range'); score += 1
        fc = alert.get('function_code','')
        if fc in [1,3,4]:
            risk_factors.append('Read operation - typically lower risk'); score += 1
        reg = (alert.get('register_name') or '').lower()
        if 'sensor' in reg or 'monitoring' in reg:
            risk_factors.append('Normal monitoring register'); score += 1
        level = 'high' if score >= 3 else 'medium' if score >= 1 else 'low'
        return {'risk_level': level, 'risk_score': score, 'risk_factors': risk_factors, 'recommendation': 'Verify incident details before taking action'}

    def _calculate_confidence(self, alert):
        conf = 70
        rid = alert.get('rule_id','')
        if rid in ['R001','R005','R015']: conf += 20
        elif rid in ['R009','R013']: conf += 15
        elif rid in ['R002','R003']: conf += 10
        src_asset = (alert.get('src_asset') or '')
        if 'unauthorized' in src_asset.lower() or 'unknown' in src_asset.lower(): conf += 10
        if alert.get('function_code') in [5,6,15,16]: conf += 10
        return min(conf, 100)

    def _get_response_time(self, severity):
        return {'critical':'Immediate','high':'1 hour','medium':'4 hours','low':'24 hours','informational':'24 hours'}.get(severity,'4 hours')

    def _determine_response_priority(self, alert):
        sev, rid = alert.get('severity','medium'), alert.get('rule_id','')
        if sev == 'critical' or rid in ['R001','R005','R015']: return 'immediate'
        if sev == 'high' or rid in ['R009','R013']: return 'urgent'
        if sev == 'medium': return 'normal'
        return 'low'

    def _generate_tags(self, alert):
        tags = [f"rule:{alert.get('rule_id','unknown')}", f"severity:{alert.get('severity','medium')}",
                'protocol:modbus','protocol:tcp']
        fc = alert.get('function_code','')
        if fc in [1,2,3,4]: tags.append('operation:read')
        elif fc in [5,6,15,16]: tags.append('operation:write')
        reg = (alert.get('register_name') or '').lower()
        if 'control' in reg: tags.append('component:control')
        elif 'sensor' in reg: tags.append('component:sensor')
        elif 'actuator' in reg: tags.append('component:actuator')
        elif 'valve' in reg: tags.append('component:valve')
        elif 'pump' in reg: tags.append('component:pump')
        rid = alert.get('rule_id','')
        if rid in ['R001','R005']: tags.append('attack:unauthorized_access')
        elif rid in ['R009','R013']: tags.append('attack:replay')
        elif rid in ['R010','R016']: tags.append('attack:dos')
        elif rid in ['R012','R014']: tags.append('attack:network_spoofing')
        return tags

    def generate_summary_report(self, incidents):
        if not incidents: return {'message': 'No incidents to summarize'}
        total = len(incidents)
        sev_counts, rule_counts = {}, {}
        for inc in incidents:
            sev = inc.get('severity','unknown')
            sev_counts[sev] = sev_counts.get(sev,0) + 1
            for rid in inc.get('triggered_rules',[]):
                rule_counts[rid] = rule_counts.get(rid,0) + 1
        crit = [i for i in incidents if i.get('severity') == 'critical']
        high = [i for i in incidents if i.get('severity') == 'high']
        return {'summary': {'total_incidents': total,'critical_incidents': len(crit),
                            'high_incidents': len(high),'severity_distribution': sev_counts,
                            'rule_distribution': rule_counts},
                'critical_incidents': crit, 'high_incidents': high, 'all_incidents': incidents}

# ---------- UTIL ----------

def split_addr_map(flat_map):
    """
    Accepts a flat addr_map that may contain:
      - numeric keys (or numeric strings) -> register names
      - an 'assets' sub-map -> { ip: name }
    Returns (asset_map, register_map) with robust typing.
    """
    assets_section = flat_map.get('assets', {}) if isinstance(flat_map, dict) else {}
    asset_map = dict(assets_section) if isinstance(assets_section, dict) else {}

    register_map = {}
    if isinstance(flat_map, dict):
        for k, v in flat_map.items():
            if k == 'assets':  # already handled
                continue
            # If key looks like an IP, skip (it belongs in assets)
            if isinstance(k, str) and k.count('.') == 3:
                # if the user mistakenly placed an IP at top-level, honor it as an asset
                asset_map.setdefault(k, v)
                continue
            # try to coerce to int register address
            try:
                rk = int(k)
                register_map[rk] = v
            except Exception:
                # ignore non-numeric, non-asset keys
                pass
    return asset_map, register_map

# ---------- MAIN & HTML ----------

def main():
    parser = argparse.ArgumentParser(description="Hybrid ICS Incident Report Builder")
    parser.add_argument('--alerts', required=True, help='Input alert JSON file from detect.py')
    parser.add_argument('--policy', required=True, help='Path to policies.yaml for enrichment')
    parser.add_argument('--addrmap', required=True, help='Path to addr_map.yaml for enrichment')
    parser.add_argument('--out', required=True, help='Output incident report JSON file')
    parser.add_argument('--window', type=int, default=300, help='Time window (seconds) for grouping alerts into an incident.')
    parser.add_argument('--format', choices=['json','html','both'], default='both', help="Output format for incident reports")
    args = parser.parse_args()

    print("=" * 80)
    print("Hybrid ICS Incident Report Builder")
    print("=" * 80)

    # Guard: alerts file present & non-empty
    if not os.path.exists(args.alerts) or os.path.getsize(args.alerts) == 0:
        print(f"[incident_builder] Alert file is missing or empty. No incidents to report.")
        with open(args.out, 'w') as f: json.dump([], f)
        return

    # Load alerts (lenient)
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

    builder = HybridIncidentBuilder()
    policy   = builder.load_yaml(args.policy)
    addr_map = builder.load_yaml(args.addrmap)

    # ✅ Split, don’t invert: supports flat numeric keys + optional assets block
    asset_map, register_map = split_addr_map(addr_map)

    print(f"[*] Processing {len(alerts)} alerts...")
    enriched = builder.enrich_alerts(alerts, policy, asset_map, register_map)
    groups   = builder.group_alerts_into_incidents(enriched, args.window)

    print(f"[*] Building {len(groups)} incident reports...")
    incidents = []
    for g in groups:
        inc = builder.build_detailed_incident(g)
        if inc: incidents.append(inc)

    summary = builder.generate_summary_report(incidents)

    # Save reports
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.dirname(args.out)
    if out_dir: os.makedirs(out_dir, exist_ok=True)

    with open(args.out, 'w') as f:
        json.dump(incidents, f, indent=2)

    summary_file = args.out.replace('.json', '_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    if args.format in ['html','both']:
        html_file = args.out.replace('.json', '.html')
        generate_html_report(incidents, summary, html_file)

    print(f"\n[+] Analysis Summary:")
    print(f"  - Total alerts: {len(alerts)}")
    print(f"  - Grouped into: {len(incidents)} incidents")
    if isinstance(summary, dict) and 'summary' in summary:
        print(f"  - Critical incidents: {summary['summary'].get('critical_incidents',0)}")
        print(f"  - High priority incidents: {summary['summary'].get('high_incidents',0)}")
    print(f"  - Reports saved to: {os.path.dirname(args.out) or '.'}")
    if incidents:
        print("\n[*] Incident Summary (first 5):")
        for inc in incidents[:5]:
            print(f"  - {inc['incident_id']}: {inc['summary'][:60]}... (Severity: {inc['severity']})")
    else:
        print("\n[+] SUCCESS: Zero incidents detected (no false positives)")

def generate_html_report(incidents, summary, output_file):
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICS Security Incident Report</title>
<style>
 body {{ font-family: Arial, sans-serif; margin:20px; }}
 .header {{ background:#f0f0f0; padding:20px; border-radius:5px; }}
 .summary {{ background:#e8f4f8; padding:15px; margin:20px 0; border-radius:5px; }}
 .incident {{ border:1px solid #ddd; margin:10px 0; padding:15px; border-radius:5px; }}
 .critical {{ border-left:5px solid #d32f2f; }} .high {{ border-left:5px solid #f57c00; }}
 .medium {{ border-left:5px solid #fbc02d; }} .low {{ border-left:5px solid #388e3c; }}
 .severity-critical {{ color:#d32f2f; font-weight:bold; }}
 .severity-high {{ color:#f57c00; font-weight:bold; }}
 .severity-medium {{ color:#fbc02d; font-weight:bold; }}
 .severity-low {{ color:#388e3c; font-weight:bold; }}
</style></head><body>
<div class="header">
  <h1>ICS Security Incident Report</h1>
  <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
  <p><strong>Total Incidents:</strong> {summary.get('summary',{}).get('total_incidents', len(incidents))}</p>
  <p><strong>Critical Incidents:</strong> {summary.get('summary',{}).get('critical_incidents', 0)}</p>
  <p><strong>High Priority Incidents:</strong> {summary.get('summary',{}).get('high_incidents', 0)}</p>
</div>
<div class="summary">
  <h2>Executive Summary</h2>
  <p>This report contains {len(incidents)} security incidents detected in the ICS environment.</p>
</div>
<h2>Detailed Incidents</h2>
"""
    for inc in incidents:
        sev_class = f"severity-{inc['severity']}"
        box_class = f"incident {inc['severity']}"
        html += f"""
<div class="{box_class}">
  <h3>{inc['incident_id']}</h3>
  <p><strong>Severity:</strong> <span class="{sev_class}">{inc['severity'].upper()}</span></p>
  <p><strong>Duration:</strong> {inc['duration_seconds']:.1f} seconds</p>
  <p><strong>Alert Count:</strong> {inc['alert_count']}</p>
  <p><strong>Summary:</strong> {inc['summary']}</p>
  <p><strong>Affected Assets:</strong> {', '.join(inc.get('affected_assets', []))}</p>
  <p><strong>Triggered Rules:</strong> {', '.join(inc.get('triggered_rules', []))}</p>
</div>
"""
    html += "</body></html>"
    with open(output_file, 'w') as f:
        f.write(html)
    print(f"[+] HTML report generated: {output_file}")

if __name__ == "__main__":
    main()
