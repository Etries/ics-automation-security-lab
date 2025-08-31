#!/usr/bin/env python3
"""
Hybrid ICS Incident Report Builder (Policy-Driven, Portable)

- Enrichment is policy-driven (severity/description/MITRE/NIS2 pulled from policies.yaml),
  including nested sections like network.ip_whitelist_rule and protocol.function_code_rule.
- Works with a flat addr_map.yaml (numeric register keys + optional assets: {ip: name}).
- HTML output is concise: a “What happened” line, counts per rule, and (if present) a
  risk banner for unauthorized IP (R014).
"""

import argparse
import yaml
import json
import os
import hashlib
from datetime import datetime, timezone

# ---------------- IO helpers ----------------

def load_yaml(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}

def split_addr_map(flat_map):
    """Accept flat addr_map with numeric register keys and optional assets: {ip:name}."""
    if not isinstance(flat_map, dict):
        return {}, {}
    assets = flat_map.get('assets', {})
    asset_map = dict(assets) if isinstance(assets, dict) else {}

    register_map = {}
    for k, v in flat_map.items():
        if k == 'assets':
            continue
        # If key looks like an IP mistakenly at top-level, honor it as an asset
        if isinstance(k, str) and k.count('.') == 3:
            asset_map.setdefault(k, v)
            continue
        try:
            register_map[int(k)] = v
        except Exception:
            pass
    return asset_map, register_map

# ---------------- Builder ----------------

class Builder:
    def __init__(self):
        # Simple defaults if policy lacks details (rare)
        self.mitre_defaults = {
            'TA0006': {'tactic': 'Impact','description': 'Disruption of availability/integrity'},
            'TA0007': {'tactic': 'Discovery/Collection','description': 'Information gathering or protocol abuse'},
            'TA0008': {'tactic': 'Lateral Movement','description': 'Movement within network'},
            'T0815':  {'tactic': 'Lateral Movement','technique': 'Replay','description': 'Replay of captured communications'},
            'T0831':  {'tactic': 'Impact','technique': 'Manipulation of Control','description': 'Manipulating control processes'}
        }
        self.nis2_defaults = {
            'Article 21': {'article': 'Risk Management','description': 'Risk assessment and measures','requirements': ['Risk assessment','Security measures','Incident detection']},
            'Article 23': {'article': 'Incident Reporting','description': 'Detection and reporting','requirements': ['Incident detection','Reporting','Response coordination']}
        }

    # ---------- Rule map (supports nested sections) ----------

    def _build_rule_map(self, policy):
        rule_map = {}

        # global_rules list
        for r in policy.get('global_rules', []):
            if isinstance(r, dict) and 'id' in r:
                rule_map[r['id']] = r

        # legacy top-level singleton sections (for backward compatibility)
        for section in ['network_segmentation_rule','ip_whitelist_rule','function_code_rule',
                        'state_logic_rule','state_transition_rule','polling_sequence_rule']:
            sec = policy.get(section)
            if isinstance(sec, dict) and 'id' in sec:
                rule_map[sec['id']] = sec

        # NEW: nested policy sections
        net = policy.get('network', {})
        if isinstance(net, dict):
            for k in ['network_segmentation_rule','ip_whitelist_rule']:
                sec = net.get(k)
                if isinstance(sec, dict) and 'id' in sec:
                    rule_map[sec['id']] = sec

        proto = policy.get('protocol', {})
        if isinstance(proto, dict):
            sec = proto.get('function_code_rule')
            if isinstance(sec, dict) and 'id' in sec:
                rule_map[sec['id']] = sec

        # register-scoped rules
        for reg in policy.get('registers', []):
            for r in reg.get('rules', []):
                if isinstance(r, dict) and 'id' in r:
                    rule_map[r['id']] = r

        return rule_map

    # ---------- Enrichment ----------

    def enrich(self, alerts, policy, asset_map, register_map):
        """
        Adds human-readable fields to alerts:
          - description, severity, mitre, nis2_article from policy (rule_map)
          - src_asset / dst_asset via asset_map
          - register_name via register_map
        """
        rules = self._build_rule_map(policy)
        out = []
        for a in alerts:
            rid = a.get('rule_id')
            meta = rules.get(rid, {})

            e = dict(a)
            e['description']  = meta.get('description', e.get('description', ''))
            e['severity']     = meta.get('severity',    e.get('severity', 'medium'))
            e['mitre']        = meta.get('mitre', {})
            e['nis2_article'] = meta.get('nis2_article')

            src, dst = e.get('src'), e.get('dst')
            if src: e['src_asset'] = asset_map.get(src, 'unknown_asset')
            if dst: e['dst_asset'] = asset_map.get(dst, 'unknown_asset')

            if 'address' in e and e['address'] is not None:
                addr = e['address']
                # try int key first, then string fallback
                rn = register_map.get(addr)
                if rn is None:
                    try:
                        rn = register_map.get(int(addr))
                    except Exception:
                        pass
                if rn is None:
                    rn = register_map.get(str(addr))
                e['register_name'] = rn if rn is not None else 'unknown_register'

            out.append(e)
        return out

    # ---------- Grouping ----------

    def group(self, alerts, window=300):
        if not alerts:
            return []
        alerts.sort(key=lambda x: x['timestamp'])
        groups, cur = [], [alerts[0]]
        for i in range(1, len(alerts)):
            a, b = cur[-1], alerts[i]
            related = ((a.get('src') == b.get('src') and a.get('dst') == b.get('dst')) or
                       (a.get('uid') and a.get('uid') == b.get('uid')))
            if (b['timestamp'] - a['timestamp']) <= window and related:
                cur.append(b)
            else:
                groups.append(cur); cur = [b]
        groups.append(cur)
        return groups

    # ---------- Incident build ----------

    def _sha(self, alerts):
        parts = [f"{a.get('rule_id','')}-{a.get('src','')}-{a.get('address','')}-{a.get('timestamp','')}"
                 for a in sorted(alerts, key=lambda x: x.get('timestamp', 0))]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def _mitre_info(self, mitre):
        tactic = mitre.get('tactic','')
        tech   = mitre.get('technique','')
        t_meta = self.mitre_defaults.get(tactic, {})
        c_meta = self.mitre_defaults.get(tech, {})
        return {
            'tactic_id': tactic,
            'tactic_name': t_meta.get('tactic','Unknown'),
            'tactic_description': t_meta.get('description',''),
            'technique_id': tech,
            'technique_name': c_meta.get('technique','Unknown'),
            'technique_description': c_meta.get('description','')
        }

    def _nis2_info(self, art):
        d = self.nis2_defaults.get(art, {})
        return {'article_id': art, 'article_name': d.get('article','Unknown'),
                'description': d.get('description',''), 'requirements': d.get('requirements', [])}

    def build_incident(self, group):
        if not group:
            return None

        inc_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{self._sha(group)}"
        sev_order = ['informational','low','medium','high','critical']
        highest = 'informational'
        for s in [a.get('severity','low') for a in group]:
            if s in sev_order and sev_order.index(s) > sev_order.index(highest):
                highest = s

        start = datetime.fromtimestamp(min(a['timestamp'] for a in group), tz=timezone.utc)
        end   = datetime.fromtimestamp(max(a['timestamp'] for a in group), tz=timezone.utc)
        primary = group[0]

        # One-line timeline entries for downstream HTML
        timeline = [{
            "timestamp": datetime.fromtimestamp(a['timestamp'], tz=timezone.utc).isoformat(),
            "rule_id": a.get('rule_id',''),
            "description": a.get('description',''),
            "source": f"{a.get('src_asset','N/A')} ({a.get('src','N/A')})",
            "target": f"{a.get('dst_asset','N/A')} ({a.get('dst','N/A')})",
            "details": f"Register: {a.get('register_name','N/A')} ({a.get('address','N/A')}), Value: {a.get('value','N/A')}"
        } for a in group]

        return {
            'incident_id': inc_id,
            'start_time': start.isoformat(),
            'end_time': end.isoformat(),
            'duration_seconds': (end - start).total_seconds(),
            'severity': highest,
            'alert_count': len(group),
            'summary': f"{len(group)} correlated alerts; rules: {', '.join(sorted(set(a.get('rule_id','') for a in group)))}.",
            'affected_assets': sorted(set(a.get('dst_asset','unknown') for a in group)),
            'source_assets':   sorted(set(a.get('src_asset','unknown') for a in group)),
            'triggered_rules': sorted(set(a.get('rule_id','') for a in group)),
            'source_ip': primary.get('src',''),
            'destination_ip': primary.get('dst',''),
            'function_code': primary.get('function_code',''),
            'register_address': primary.get('address',''),
            'register_value': primary.get('value',''),
            'transaction_id': primary.get('tid',''),
            'mitre_attack': self._mitre_info(primary.get('mitre', {})),
            'nis2_compliance': self._nis2_info(primary.get('nis2_article','')),
            'timeline': timeline,
            'detection_method': 'passive_network_analysis',
            'status': 'open'
        }

    def summarize(self, incidents):
        if not incidents:
            return {'message': 'No incidents to summarize'}
        sev_counts, rule_counts = {}, {}
        for inc in incidents:
            sev = inc.get('severity','unknown')
            sev_counts[sev] = sev_counts.get(sev,0)+1
            for rid in inc.get('triggered_rules',[]):
                rule_counts[rid] = rule_counts.get(rid,0)+1
        crit = [i for i in incidents if i.get('severity')=='critical']
        high = [i for i in incidents if i.get('severity')=='high']
        return {'summary': {'total_incidents': len(incidents),
                            'critical_incidents': len(crit),
                            'high_incidents': len(high),
                            'severity_distribution': sev_counts,
                            'rule_distribution': rule_counts},
                'critical_incidents': crit,
                'high_incidents': high}

# ---------------- HTML (concise) ----------------

def _summarize_rules_with_counts(inc):
    counts = {}
    for row in inc.get('timeline', []):
        rid = row.get('rule_id', '')
        if rid:
            counts[rid] = counts.get(rid, 0) + 1
    if not counts:
        return "—"
    return ", ".join(f"{rid} × {counts[rid]}" for rid in sorted(counts.keys()))

def _what_happened_line(inc):
    """Use the FIRST alert in the group as the single human-readable example."""
    tl = inc.get('timeline', [])
    if not tl:
        return "—"
    first = tl[0]
    ts   = first.get('timestamp', '')
    desc = first.get('description', '')
    src  = first.get('source', '')
    dst  = first.get('target', '')
    return f"{ts}: {desc} | {src} → {dst}"

def generate_html_report(incidents, summary, output_file):
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICS Security Incident Report</title>
<style>
 body{{font-family:Arial,sans-serif;margin:20px;line-height:1.45}}
 .header{{background:#f0f0f0;padding:18px;border-radius:10px}}
 .incident{{border:1px solid #e5e5e5;margin:16px 0;padding:16px;border-radius:12px}}
 .critical{{border-left:8px solid #d32f2f}} .high{{border-left:8px solid #f57c00}}
 .medium{{border-left:8px solid #fbc02d}} .low{{border-left:8px solid #388e3c}}
 .badge{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;margin-left:6px}}
 .b-critical{{background:#ffd4d4;color:#8b0000}} .b-high{{background:#ffe6cf;color:#9a4b00}}
 .b-medium{{background:#fff3c4;color:#7a5b00}} .b-low{{background:#dff5e1;color:#1f6b2b}}
 .kv{{margin:6px 0}} .kv span{{display:inline-block;min-width:180px;color:#555}}
 .banner{{background:#ffecec;border:1px solid #ffb3b3;padding:10px;border-radius:8px;margin:10px 0;color:#7a0000}}
</style></head><body>
<div class="header">
  <h1>ICS Security Incident Report</h1>
  <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
  <p><strong>Total Incidents:</strong> {summary.get('summary',{}).get('total_incidents', len(incidents))} &nbsp;|&nbsp;
     <strong>Critical:</strong> {summary.get('summary',{}).get('critical_incidents', 0)} &nbsp;|&nbsp;
     <strong>High:</strong> {summary.get('summary',{}).get('high_incidents', 0)}</p>
</div>
<h2>Detailed Incidents</h2>
"""
    for inc in incidents:
        sev = inc.get('severity','medium')
        box = f"incident {sev}"
        badge = f"badge b-{sev}"
        rules_summary = _summarize_rules_with_counts(inc)
        happened = _what_happened_line(inc)
        affected = ", ".join(inc.get('affected_assets', [])) or "—"

        html += f"""
<div class="{box}">
  <h3>{inc['incident_id']} <span class="{badge}">{sev.upper()}</span></h3>"""

        # Risk banner for unauthorized IP (R014)
        if 'R014' in (inc.get('triggered_rules') or []):
            html += """<div class="banner"><strong>Key risk:</strong> Unauthorized IP communicating with protected asset (R014). Treat as CRITICAL and investigate immediately.</div>"""

        html += f"""
  <div class="kv"><span>What happened:</span> {happened}</div>
  <div class="kv"><span>Affected assets:</span> {affected}</div>
  <div class="kv"><span>Triggered rules (counts):</span> {rules_summary}</div>
  <div class="kv"><span>Duration:</span> {inc.get('duration_seconds',0):.1f} seconds</div>
  <div class="kv"><span>Alerts in group:</span> {inc.get('alert_count',0)}</div>
</div>
"""
    html += "</body></html>"
    with open(output_file, 'w') as f:
        f.write(html)
    print(f"[+] HTML report generated: {output_file}")

# ---------------- CLI ----------------

def main():
    ap = argparse.ArgumentParser(description="Hybrid ICS Incident Report Builder")
    ap.add_argument('--alerts', required=True, help='Input alert JSON file from detect.py')
    ap.add_argument('--policy', required=True, help='Path to policies.yaml for enrichment')
    ap.add_argument('--addrmap', required=True, help='Path to addr_map.yaml for enrichment')
    ap.add_argument('--out', required=True, help='Output incident report JSON file')
    ap.add_argument('--window', type=int, default=300, help='Time window (seconds) for grouping alerts into an incident.')
    ap.add_argument('--format', choices=['json','html','both'], default='both', help="Output format for incident reports")
    args = ap.parse_args()

    if not os.path.exists(args.alerts) or os.path.getsize(args.alerts) == 0:
        print("[incident_builder] No alerts file or empty; writing empty report.")
        with open(args.out, 'w') as f: json.dump([], f)
        return

    try:
        alerts = json.load(open(args.alerts))
    except Exception:
        print("[incident_builder] Bad JSON; writing empty report.")
        with open(args.out, 'w') as f: json.dump([], f)
        return

    policy   = load_yaml(args.policy)
    addr_map = load_yaml(args.addrmap)
    asset_map, register_map = split_addr_map(addr_map)

    b = Builder()
    enriched = b.enrich(alerts, policy, asset_map, register_map)
    groups   = b.group(enriched, window=args.window)
    incidents = [b.build_incident(g) for g in groups if g]
    summary   = b.summarize(incidents)

    out_dir = os.path.dirname(args.out)
    if out_dir: os.makedirs(out_dir, exist_ok=True)
    json.dump(incidents, open(args.out, 'w'), indent=2)
    json.dump(summary,   open(args.out.replace('.json','_summary.json'), 'w'), indent=2)

    if args.format in ['html','both']:
        generate_html_report(incidents, summary, args.out.replace('.json','.html'))

    print(f"[+] Incidents: {len(incidents)} → {args.out}")

if __name__ == "__main__":
    main()
