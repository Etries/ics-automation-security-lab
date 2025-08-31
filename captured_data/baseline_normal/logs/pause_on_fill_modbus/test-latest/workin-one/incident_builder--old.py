#!/usr/bin/env python3
"""
Incident Report Builder


DESCRIPTION:
This script combines alert correlation (grouping related alerts into incidents)
with detailed individual incident analysis. It provides both high-level incident
grouping and deep technical analysis for each incident.

FEATURES:
- Alert correlation with temporal and relationship grouping
- Detailed impact assessment for each incident
- MITRE ATT&CK and NIS2 compliance mapping
- Professional HTML and JSON output
- False positive risk assessment
- Actionable recommendations
"""

import argparse
import yaml
import json
import os
import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List

class HybridIncidentBuilder:
    """Combines alert correlation with detailed incident analysis"""
    
    def __init__(self):
        # Enhanced MITRE ATT&CK mappings
        self.mitre_mappings = {
            'TA0006': {
                'tactic': 'Impact',
                'description': 'Adversary actions that result in disruption of availability or integrity'
            },
            'TA0007': {
                'tactic': 'Collection',
                'description': 'Adversary techniques used to identify and gather information'
            },
            'TA0008': {
                'tactic': 'Lateral Movement',
                'description': 'Adversary techniques that enable movement within the network'
            },
            'T0812': {
                'tactic': 'Collection',
                'technique': 'Data from Information Repositories',
                'description': 'Adversary access to system information and configuration data'
            },
            'T0815': {
                'tactic': 'Lateral Movement',
                'technique': 'Replay',
                'description': 'Adversary replay of captured communications to gain unauthorized access'
            },
            'T0831': {
                'tactic': 'Impact',
                'technique': 'Manipulation of Control',
                'description': 'Adversary manipulation of industrial control processes'
            }
        }
        
        # Enhanced NIS2 compliance mappings
        self.nis2_mappings = {
            'Article 21': {
                'article': 'Risk Management',
                'description': 'Security risk management and assessment requirements',
                'requirements': ['Risk assessment', 'Security measures', 'Incident detection']
            },
            'Article 21.b': {
                'article': 'Physical Security',
                'description': 'Physical security and environmental protection requirements',
                'requirements': ['Physical access controls', 'Environmental monitoring', 'Safety systems']
            },
            'Article 23': {
                'article': 'Incident Reporting',
                'description': 'Security incident detection and reporting requirements',
                'requirements': ['Incident detection', 'Reporting procedures', 'Response coordination']
            }
        }
        
        # Generic impact assessment based on rule patterns and components
        self.impact_patterns = {
            'unauthorized': {
                'operational_impact': 'high',
                'safety_impact': 'high',
                'data_integrity': 'high',
                'system_availability': 'medium',
                'description': 'Unauthorized access or control manipulation'
            },
            'replay': {
                'operational_impact': 'high',
                'safety_impact': 'high',
                'data_integrity': 'high',
                'system_availability': 'medium',
                'description': 'Replay attack - potential process manipulation'
            },
            'timing': {
                'operational_impact': 'high',
                'safety_impact': 'high',
                'data_integrity': 'high',
                'system_availability': 'medium',
                'description': 'Timing-based attack or process manipulation'
            },
            'network': {
                'operational_impact': 'medium',
                'safety_impact': 'medium',
                'data_integrity': 'high',
                'system_availability': 'medium',
                'description': 'Network segmentation or communication violation'
            },
            'dos': {
                'operational_impact': 'medium',
                'safety_impact': 'low',
                'data_integrity': 'low',
                'system_availability': 'high',
                'description': 'Denial of Service or excessive traffic'
            },
            'protocol': {
                'operational_impact': 'low',
                'safety_impact': 'low',
                'data_integrity': 'medium',
                'system_availability': 'low',
                'description': 'Protocol abuse or fuzzing attempt'
            }
        }
    
    def load_yaml(self, file_path):
        """Loads a YAML file with error handling."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[FATAL] Could not load YAML file {file_path}: {e}")
            exit(1)
    
    def enrich_alerts(self, alerts, policy, addr_map):
        """Enriches raw alerts with context from policy and address map."""
        enriched = []
        
        # Create quick lookup maps for policies
        rule_map = {rule['id']: rule for rule in policy.get('global_rules', [])}
        for section in ['network_segmentation_rule', 'ip_whitelist_rule', 'function_code_rule', 
                       'state_logic_rule', 'state_transition_rule', 'polling_sequence_rule']:
            if section in policy:
                rule = policy[section]
                rule_map[rule['id']] = rule
        for reg in policy.get('registers', []):
            for rule in reg.get('rules', []):
                rule_map[rule['id']] = rule

        for alert in alerts:
            rule_id = alert.get('rule_id')
            rule_info = rule_map.get(rule_id, {})
            
            enriched_alert = alert.copy()
            enriched_alert['description'] = rule_info.get('description', alert.get('description', ''))
            enriched_alert['severity'] = rule_info.get('severity', alert.get('severity', 'medium'))
            enriched_alert['mitre'] = rule_info.get('mitre', {})
            enriched_alert['nis2_article'] = rule_info.get('nis2_article')
            
            # Add semantic tags from addr_map
            if 'src' in alert:
                enriched_alert['src_asset'] = addr_map.get(alert['src'], 'unknown_asset')
            if 'dst' in alert:
                enriched_alert['dst_asset'] = addr_map.get(alert['dst'], 'unknown_asset')
            if 'address' in alert:
                enriched_alert['register_name'] = addr_map.get(alert['address'], 'unknown_register')
                
            enriched.append(enriched_alert)
        return enriched
    
    def group_alerts_into_incidents(self, alerts, time_window_seconds=300):
        """Groups alerts into incidents based on time and shared attributes."""
        if not alerts:
            return []

        # Sort alerts chronologically
        alerts.sort(key=lambda x: x['timestamp'])

        incidents = []
        current_incident = [alerts[0]]

        for i in range(1, len(alerts)):
            current_alert = alerts[i]
            last_alert = current_incident[-1]
            
            time_delta = current_alert['timestamp'] - last_alert['timestamp']
            
            # Check if alerts are related (same source/dest or same UID)
            is_related = (current_alert.get('src') == last_alert.get('src') and 
                          current_alert.get('dst') == last_alert.get('dst')) or \
                         (current_alert.get('uid') and current_alert.get('uid') == last_alert.get('uid'))

            if time_delta <= time_window_seconds and is_related:
                current_incident.append(current_alert)
            else:
                incidents.append(current_incident)
                current_incident = [current_alert]
        
        incidents.append(current_incident)
        return incidents
    
    def generate_incident_id(self, alerts):
        """Creates a stable, unique ID for a group of alerts."""
        components = []
        for alert in sorted(alerts, key=lambda x: x['timestamp']):
            components.append(f"{alert['rule_id']}-{alert.get('src', '')}-{alert.get('address', '')}-{alert['timestamp']}")
        incident_string = "|".join(components)
        return hashlib.sha256(incident_string.encode()).hexdigest()[:16]
    
    def build_detailed_incident(self, alert_group):
        """Builds a detailed incident report from a group of alerts."""
        if not alert_group:
            return None
        
        # Generate incident ID
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{self.generate_incident_id(alert_group)}"
        
        # Determine highest severity
        severities = [a.get('severity', 'low') for a in alert_group]
        sev_order = ['informational', 'low', 'medium', 'high', 'critical']
        highest_severity = 'informational'
        for s in severities:
            if s in sev_order and sev_order.index(s) > sev_order.index(highest_severity):
                highest_severity = s
        
        # Calculate time range
        start_time = datetime.fromtimestamp(min(a['timestamp'] for a in alert_group), tz=timezone.utc)
        end_time = datetime.fromtimestamp(max(a['timestamp'] for a in alert_group), tz=timezone.utc)
        
        # Get primary alert for detailed analysis
        primary_alert = alert_group[0]
        
        # Build timeline
        timeline = []
        for alert in alert_group:
            timeline.append({
                "timestamp": datetime.fromtimestamp(alert['timestamp'], tz=timezone.utc).isoformat(),
                "rule_id": alert['rule_id'],
                "description": alert['description'],
                "source": f"{alert.get('src_asset', 'N/A')} ({alert.get('src', 'N/A')})",
                "target": f"{alert.get('dst_asset', 'N/A')} ({alert.get('dst', 'N/A')})",
                "details": f"Register: {alert.get('register_name', 'N/A')} ({alert.get('address', 'N/A')}), Value: {alert.get('value', 'N/A')}"
            })
        
        # Detailed incident structure
        incident = {
            'incident_id': incident_id,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': (end_time - start_time).total_seconds(),
            'severity': highest_severity,
            'alert_count': len(alert_group),
            
            # Summary information
            'summary': f"A potential security incident involving {len(alert_group)} correlated alerts, primarily related to rule(s): {', '.join(sorted(list(set(a['rule_id'] for a in alert_group))))}.",
            'affected_assets': sorted(list(set(a.get('dst_asset', 'unknown') for a in alert_group))),
            'source_assets': sorted(list(set(a.get('src_asset', 'unknown') for a in alert_group))),
            'triggered_rules': sorted(list(set(a['rule_id'] for a in alert_group))),
            
            # Technical details from primary alert
            'source_ip': primary_alert.get('src', ''),
            'destination_ip': primary_alert.get('dst', ''),
            'function_code': primary_alert.get('function_code', ''),
            'register_address': primary_alert.get('address', ''),
            'register_value': primary_alert.get('value', ''),
            'transaction_id': primary_alert.get('tid', ''),
            
            # Enhanced analysis
            'mitre_attack': self._get_mitre_info(primary_alert.get('mitre', {})),
            'nis2_compliance': self._get_nis2_info(primary_alert.get('nis2_article', '')),
            'impact_assessment': self._assess_impact(primary_alert.get('rule_id', ''), primary_alert),
            'recommendations': self._generate_recommendations(primary_alert.get('rule_id', ''), primary_alert),
            'false_positive_risk': self._assess_false_positive_risk(primary_alert),
            'confidence_score': self._calculate_confidence(primary_alert),
            
            # Response information
            'response_time': self._get_response_time(highest_severity),
            'response_priority': self._determine_response_priority(primary_alert),
            
            # Timeline and metadata
            'timeline': timeline,
            'detection_method': 'passive_network_analysis',
            'tags': self._generate_tags(primary_alert),
            'related_incidents': [],
            'status': 'open'
        }
        
        return incident
    
    def _get_mitre_info(self, mitre_data):
        """Get enhanced MITRE ATT&CK information"""
        tactic_id = mitre_data.get('tactic', '')
        technique_id = mitre_data.get('technique', '')
        
        tactic_info = self.mitre_mappings.get(tactic_id, {})
        technique_info = self.mitre_mappings.get(technique_id, {})
        
        return {
            'tactic_id': tactic_id,
            'tactic_name': tactic_info.get('tactic', 'Unknown'),
            'tactic_description': tactic_info.get('description', ''),
            'technique_id': technique_id,
            'technique_name': technique_info.get('technique', 'Unknown'),
            'technique_description': technique_info.get('description', ''),
            'real_world_example': mitre_data.get('real_world', 'Unknown')
        }
    
    def _get_nis2_info(self, article_id):
        """Get enhanced NIS2 compliance information"""
        article_info = self.nis2_mappings.get(article_id, {})
        
        return {
            'article_id': article_id,
            'article_name': article_info.get('article', 'Unknown'),
            'description': article_info.get('description', ''),
            'requirements': article_info.get('requirements', [])
        }
    
    def _assess_impact(self, rule_id, alert):
        """Assess the potential impact of the security violation based on rule patterns"""
        # Determine impact based on rule description and component type
        rule_description = alert.get('description', '').lower()
        register_name = alert.get('register_name', '').lower()
        
        # Pattern matching for impact assessment
        if 'unauthorized' in rule_description or 'unauth' in rule_description:
            impact_pattern = 'unauthorized'
        elif 'replay' in rule_description:
            impact_pattern = 'replay'
        elif 'timing' in rule_description or 'transition' in rule_description:
            impact_pattern = 'timing'
        elif 'vlan' in rule_description or 'network' in rule_description:
            impact_pattern = 'network'
        elif 'excessive' in rule_description or 'dos' in rule_description:
            impact_pattern = 'dos'
        elif 'illegal' in rule_description or 'protocol' in rule_description:
            impact_pattern = 'protocol'
        else:
            # Default based on component type
            if 'control' in register_name:
                impact_pattern = 'unauthorized'
            elif 'sensor' in register_name:
                impact_pattern = 'timing'
            else:
                impact_pattern = 'network'
        
        impact = self.impact_patterns.get(impact_pattern, {
            'operational_impact': 'unknown',
            'safety_impact': 'unknown',
            'data_integrity': 'unknown',
            'system_availability': 'unknown',
            'description': 'Unknown impact assessment'
        })
        
        # Add contextual information
        impact['affected_component'] = self._identify_affected_component(alert)
        impact['potential_consequences'] = self._assess_potential_consequences(rule_id, alert)
        
        return impact
    
    def _identify_affected_component(self, alert):
        """Identify the affected industrial component using semantic names"""
        register_name = alert.get('register_name', '')
        function_code = alert.get('function_code', '')
        
        if 'control' in register_name.lower():
            return f'Control Register ({register_name})'
        elif 'sensor' in register_name.lower():
            return f'Sensor ({register_name})'
        elif 'actuator' in register_name.lower():
            return f'Actuator ({register_name})'
        elif 'valve' in register_name.lower():
            return f'Valve ({register_name})'
        elif 'pump' in register_name.lower():
            return f'Pump ({register_name})'
        elif function_code in [1, 2, 3, 4]:
            return 'Monitoring System'
        else:
            return f'Unknown Component ({register_name})'
    
    def _assess_potential_consequences(self, rule_id, alert):
        """Assess potential consequences of the violation based on component and rule type"""
        consequences = []
        rule_description = alert.get('description', '').lower()
        register_name = alert.get('register_name', '').lower()
        
        # Determine consequences based on component type and rule pattern
        if 'control' in register_name or 'unauthorized' in rule_description:
            consequences.extend([
                'Process disruption or shutdown',
                'Safety system bypass',
                'Unauthorized control access',
                'Potential equipment damage'
            ])
        elif 'sensor' in register_name or 'sensor' in rule_description:
            consequences.extend([
                'Incorrect process decisions',
                'Safety system malfunction',
                'Sensor/actuator manipulation',
                'Process instability'
            ])
        elif 'replay' in rule_description:
            consequences.extend([
                'Replay attack execution',
                'Process manipulation',
                'Unauthorized command execution',
                'System compromise'
            ])
        elif 'excessive' in rule_description or 'dos' in rule_description:
            consequences.extend([
                'System performance degradation',
                'Communication disruption',
                'Monitoring system failure',
                'DoS conditions'
            ])
        elif 'network' in rule_description or 'vlan' in rule_description:
            consequences.extend([
                'Network segmentation bypass',
                'Unauthorized device access',
                'Communication interception',
                'Network infrastructure compromise'
            ])
        else:
            consequences.extend([
                'System security compromise',
                'Process manipulation',
                'Data integrity violation',
                'Operational disruption'
            ])
        
        return consequences
    
    def _generate_recommendations(self, rule_id, alert):
        """Generate actionable recommendations based on rule patterns and component types"""
        recommendations = []
        rule_description = alert.get('description', '').lower()
        register_name = alert.get('register_name', '').lower()
        
        # Pattern-based recommendations
        if 'unauthorized' in rule_description or 'control' in register_name:
            recommendations.extend([
                'Immediately investigate the source IP for unauthorized access',
                'Review network access controls and VLAN segmentation',
                'Implement additional authentication for control registers',
                'Monitor for similar unauthorized access attempts',
                'Consider implementing role-based access control (RBAC)'
            ])
        elif 'sensor' in register_name or 'sensor' in rule_description:
            recommendations.extend([
                'Verify sensor readings and physical system state',
                'Check for sensor tampering or malfunction',
                'Review physical security controls',
                'Implement sensor redundancy and validation',
                'Monitor for similar physical tampering attempts'
            ])
        elif 'replay' in rule_description:
            recommendations.extend([
                'Investigate potential network interception or spoofing',
                'Verify network integrity and routing configuration',
                'Implement network monitoring for MITM detection',
                'Check for unauthorized network devices',
                'Consider implementing encrypted Modbus communications'
            ])
        elif 'excessive' in rule_description or 'dos' in rule_description:
            recommendations.extend([
                'Investigate source of high-frequency traffic',
                'Check for potential DoS attack or malfunctioning device',
                'Implement rate limiting on Modbus communications',
                'Monitor system performance for degradation',
                'Review network bandwidth and capacity'
            ])
        elif 'network' in rule_description or 'vlan' in rule_description:
            recommendations.extend([
                'Verify network segmentation and VLAN configuration',
                'Review authorized IP lists and access controls',
                'Implement network monitoring for unauthorized devices',
                'Check for device spoofing or network misconfiguration',
                'Consider implementing network access control (NAC)'
            ])
        elif 'timing' in rule_description or 'transition' in rule_description:
            recommendations.extend([
                'Investigate timing anomalies in process control',
                'Review process control logic and timing requirements',
                'Monitor for process manipulation attempts',
                'Implement additional timing validation',
                'Consider implementing process control redundancy'
            ])
        else:
            recommendations.extend([
                'Investigate the source and nature of the security violation',
                'Review security policies and access controls',
                'Implement additional monitoring for similar activities',
                'Consider implementing enhanced security measures'
            ])
        
        # General recommendations
        recommendations.extend([
            'Document incident details and response actions',
            'Update security policies and procedures',
            'Conduct post-incident review and lessons learned',
            'Consider implementing additional monitoring and alerting'
        ])
        
        return recommendations
    
    def _assess_false_positive_risk(self, alert):
        """Assess the risk of this being a false positive"""
        risk_factors = []
        risk_score = 0
        
        # Check source IP - use addr_map to determine if authorized
        source_ip = alert.get('src', '')
        src_asset = alert.get('src_asset', '')
        if 'authorized' in src_asset.lower() or 'hmi' in src_asset.lower():
            risk_factors.append('Source IP is in authorized range')
            risk_score += 1
        
        # Check function code - read operations are typically lower risk
        function_code = alert.get('function_code', '')
        if function_code in [1, 3, 4]:  # Read operations
            risk_factors.append('Read operation - typically lower risk')
            risk_score += 1
        
        # Check register address - use semantic names from addr_map
        register_name = alert.get('register_name', '')
        if 'sensor' in register_name.lower() or 'monitoring' in register_name.lower():
            risk_factors.append('Normal monitoring register')
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 3:
            risk_level = 'high'
        elif risk_score >= 1:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendation': 'Verify incident details before taking action'
        }
    
    def _calculate_confidence(self, alert):
        """Calculate confidence score (0-100) for the detection"""
        confidence = 70  # Base confidence
        
        # Adjust based on rule type
        rule_id = alert.get('rule_id', '')
        if rule_id in ['R001', 'R005', 'R015']:  # Control violations
            confidence += 20
        elif rule_id in ['R009', 'R013']:  # Replay/TID violations
            confidence += 15
        elif rule_id in ['R002', 'R003']:  # Physical violations
            confidence += 10
        
        # Adjust based on source characteristics - use semantic names
        src_asset = alert.get('src_asset', '')
        if 'unauthorized' in src_asset.lower() or 'unknown' in src_asset.lower():
            confidence += 10
        
        # Adjust based on function code - write operations are higher risk
        function_code = alert.get('function_code', '')
        if function_code in [5, 6, 15, 16]:  # Write operations
            confidence += 10
        
        # Cap at 100
        return min(confidence, 100)
    
    def _get_response_time(self, severity):
        """Get response time based on severity"""
        response_times = {
            'critical': 'Immediate',
            'high': '1 hour',
            'medium': '4 hours',
            'low': '24 hours',
            'informational': '24 hours'
        }
        return response_times.get(severity, '4 hours')
    
    def _determine_response_priority(self, alert):
        """Determine response priority based on alert characteristics"""
        severity = alert.get('severity', 'medium')
        rule_id = alert.get('rule_id', '')
        
        if severity == 'critical' or rule_id in ['R001', 'R005', 'R015']:
            return 'immediate'
        elif severity == 'high' or rule_id in ['R009', 'R013']:
            return 'urgent'
        elif severity == 'medium':
            return 'normal'
        else:
            return 'low'
    
    def _generate_tags(self, alert):
        """Generate comprehensive tags for categorization"""
        tags = []
        
        # Rule-based tags
        tags.append(f"rule:{alert.get('rule_id', 'unknown')}")
        tags.append(f"severity:{alert.get('severity', 'medium')}")
        
        # Protocol tags
        tags.append('protocol:modbus')
        tags.append('protocol:tcp')
        
        # Function-based tags
        function_code = alert.get('function_code', '')
        if function_code in [1, 2, 3, 4]:
            tags.append('operation:read')
        elif function_code in [5, 6, 15, 16]:
            tags.append('operation:write')
        
        # Component-based tags - use semantic names from addr_map
        register_name = alert.get('register_name', '')
        if 'control' in register_name.lower():
            tags.append('component:control')
        elif 'sensor' in register_name.lower():
            tags.append('component:sensor')
        elif 'actuator' in register_name.lower():
            tags.append('component:actuator')
        elif 'valve' in register_name.lower():
            tags.append('component:valve')
        elif 'pump' in register_name.lower():
            tags.append('component:pump')
        
        # Attack type tags
        rule_id = alert.get('rule_id', '')
        if rule_id in ['R001', 'R005']:
            tags.append('attack:unauthorized_access')
        elif rule_id in ['R009', 'R013']:
            tags.append('attack:replay')
        elif rule_id in ['R010', 'R016']:
            tags.append('attack:dos')
        elif rule_id in ['R012', 'R014']:
            tags.append('attack:network_spoofing')
        
        return tags
    
    def generate_summary_report(self, incidents):
        """Generate a summary report from multiple incidents"""
        if not incidents:
            return {'message': 'No incidents to summarize'}
        
        # Calculate statistics
        total_incidents = len(incidents)
        severity_counts = {}
        rule_counts = {}
        
        for incident in incidents:
            severity = incident.get('severity', 'unknown')
            for rule_id in incident.get('triggered_rules', []):
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Identify critical incidents
        critical_incidents = [inc for inc in incidents if inc.get('severity') == 'critical']
        high_incidents = [inc for inc in incidents if inc.get('severity') == 'high']
        
        return {
            'summary': {
                'total_incidents': total_incidents,
                'critical_incidents': len(critical_incidents),
                'high_incidents': len(high_incidents),
                'severity_distribution': severity_counts,
                'rule_distribution': rule_counts
            },
            'critical_incidents': critical_incidents,
            'high_incidents': high_incidents,
            'all_incidents': incidents
        }

def main():
    parser = argparse.ArgumentParser(description="Hybrid ICS Incident Report Builder")
    parser.add_argument('--alerts', required=True, help='Input alert JSON file from detect.py')
    parser.add_argument('--policy', required=True, help='Path to policies.yaml for enrichment')
    parser.add_argument('--addrmap', required=True, help='Path to addr_map.yaml for enrichment')
    parser.add_argument('--out', required=True, help='Output incident report JSON file')
    parser.add_argument('--window', type=int, default=300, help='Time window (seconds) for grouping alerts into an incident.')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                       help="Output format for incident reports")
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("Hybrid ICS Incident Report Builder")
    print("=" * 80)
    
    # Check input file
    if not os.path.exists(args.alerts) or os.path.getsize(args.alerts) == 0:
        print(f"[incident_builder] Alert file is missing or empty. No incidents to report.")
        with open(args.out, 'w') as f: json.dump([], f)
        return
    
    # Load data
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
    
    # Initialize builder
    builder = HybridIncidentBuilder()
    policy = builder.load_yaml(args.policy)
    addr_map = builder.load_yaml(args.addrmap)
    
    # Invert addr_map for easier lookup
    addr_map_inverted = {v: k for k, v in addr_map.items()}
    
    # Process alerts
    print(f"[*] Processing {len(alerts)} alerts...")
    enriched_alerts = builder.enrich_alerts(alerts, policy, addr_map_inverted)
    alert_groups = builder.group_alerts_into_incidents(enriched_alerts, args.window)
    
    # Build detailed incidents
    print(f"[*] Building {len(alert_groups)} incident reports...")
    incidents = []
    for group in alert_groups:
        incident = builder.build_detailed_incident(group)
        if incident:
            incidents.append(incident)
    
    # Generate summary
    summary = builder.generate_summary_report(incidents)
    
    # Save reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.dirname(args.out)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Save detailed incidents
    incidents_file = args.out
    with open(incidents_file, 'w') as f:
        json.dump(incidents, f, indent=2)
    
    # Save summary report
    summary_file = args.out.replace('.json', '_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Generate HTML report if requested
    if args.format in ['html', 'both']:
        html_file = args.out.replace('.json', '.html')
        generate_html_report(incidents, summary, html_file)
    
    # Print summary
    print(f"\n[+] Analysis Summary:")
    print(f"  - Total alerts: {len(alerts)}")
    print(f"  - Grouped into: {len(incidents)} incidents")
    print(f"  - Critical incidents: {summary['summary']['critical_incidents']}")
    print(f"  - High priority incidents: {summary['summary']['high_incidents']}")
    print(f"  - Reports saved to: {os.path.dirname(args.out) or '.'}")
    
    if incidents:
        print(f"\n[*] Incident Summary:")
        for incident in incidents[:5]:  # Show first 5 incidents
            print(f"  - {incident['incident_id']}: {incident['summary'][:60]}... (Severity: {incident['severity']})")
        if len(incidents) > 5:
            print(f"  ... and {len(incidents) - 5} more incidents")
    else:
        print("\n[+] SUCCESS: Zero incidents detected (no false positives)")

def generate_html_report(incidents, summary, output_file):
    """Generate an HTML incident report"""
    # This would be similar to the HTML generation in the original enhanced builder
    # For brevity, I'll create a simpler version
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICS Security Incident Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e8f4f8; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .incident {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .low {{ border-left: 5px solid #388e3c; }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; font-weight: bold; }}
        .severity-low {{ color: #388e3c; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ICS Security Incident Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Total Incidents:</strong> {summary['summary']['total_incidents']}</p>
        <p><strong>Critical Incidents:</strong> {summary['summary']['critical_incidents']}</p>
        <p><strong>High Priority Incidents:</strong> {summary['summary']['high_incidents']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report contains {len(incidents)} security incidents detected in the ICS environment.</p>
    </div>
    
    <h2>Detailed Incidents</h2>
"""
    
    for incident in incidents:
        severity_class = f"severity-{incident['severity']}"
        incident_class = f"incident {incident['severity']}"
        
        html_content += f"""
    <div class="{incident_class}">
        <h3>{incident['incident_id']}</h3>
        <p><strong>Severity:</strong> <span class="{severity_class}">{incident['severity'].upper()}</span></p>
        <p><strong>Duration:</strong> {incident['duration_seconds']:.1f} seconds</p>
        <p><strong>Alert Count:</strong> {incident['alert_count']}</p>
        <p><strong>Summary:</strong> {incident['summary']}</p>
        <p><strong>Affected Assets:</strong> {', '.join(incident['affected_assets'])}</p>
        <p><strong>Triggered Rules:</strong> {', '.join(incident['triggered_rules'])}</p>
    </div>
"""
    
    html_content += """
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"[+] HTML report generated: {output_file}")

if __name__ == "__main__":
    main() 
