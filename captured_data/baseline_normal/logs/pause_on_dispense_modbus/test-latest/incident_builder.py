#!/usr/bin/env python3
"""
Incident Builder Module
Generates human-readable incident reports from security violations
"""

import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

class IncidentBuilder:
    """Builds structured incident reports from security violations"""
    
    def __init__(self):
        self.mitre_mappings = {
            'T0833': {
                'tactic': 'Manipulation',
                'technique': 'Manipulation of Control',
                'description': 'Adversary manipulation of industrial control processes'
            },
            'T0832': {
                'tactic': 'Collection',
                'technique': 'Man in the Middle',
                'description': 'Interception of ICS communications'
            },
            'T0889': {
                'tactic': 'Impact',
                'technique': 'Network Denial of Service',
                'description': 'Disruption of ICS network communications'
            },
            'T0810': {
                'tactic': 'Lateral Movement',
                'technique': 'Network Segmentation',
                'description': 'Bypass of network segmentation controls'
            },
            'T0812': {
                'tactic': 'Collection',
                'technique': 'Data from Information Repositories',
                'description': 'Unauthorized access to system information'
            }
        }
        
        self.nis2_mappings = {
            '21': {
                'article': 'Risk Management',
                'description': 'Security risk management and assessment'
            },
            '23': {
                'article': 'Incident Reporting',
                'description': 'Security incident detection and reporting'
            }
        }
        
        self.severity_levels = {
            'low': {'score': 1, 'color': 'green'},
            'medium': {'score': 2, 'color': 'yellow'},
            'high': {'score': 3, 'color': 'orange'},
            'critical': {'score': 4, 'color': 'red'}
        }
    
    def build_incident(self, violation: Dict[str, Any], features: Dict[str, Any], 
                      timestamp: str) -> Dict[str, Any]:
        """Build a complete incident report"""
        
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        
        # Base incident structure
        incident = {
            'incident_id': incident_id,
            'timestamp': timestamp,
            'rule_id': violation.get('id', 'unknown'),
            'description': violation.get('description', ''),
            'severity': violation.get('severity', 'medium'),
            'mitre_attack': self._get_mitre_info(violation.get('mitre', '')),
            'nis2_compliance': self._get_nis2_info(violation.get('nis2_article', '')),
            
            # Technical details
            'source': features.get('source_ip', ''),
            'destination': features.get('dest_ip', ''),
            'function_code': features.get('function_code', ''),
            'register': features.get('address', ''),
            'value': features.get('value', ''),
            'vlan': features.get('vlan', ''),
            'semantic_role': features.get('semantic_role', 'unknown'),
            
            # Analysis
            'impact_assessment': self._assess_impact(violation, features),
            'recommendations': self._generate_recommendations(violation, features),
            'false_positive_risk': self._assess_false_positive_risk(violation, features),
            
            # Metadata
            'detection_method': 'passive_network_analysis',
            'confidence_score': self._calculate_confidence(violation, features),
            'tags': self._generate_tags(violation, features)
        }
        
        return incident
    
    def _get_mitre_info(self, mitre_id: str) -> Dict[str, Any]:
        """Get MITRE ATT&CK information for the violation"""
        if mitre_id in self.mitre_mappings:
            return {
                'technique_id': mitre_id,
                'tactic': self.mitre_mappings[mitre_id]['tactic'],
                'technique': self.mitre_mappings[mitre_id]['technique'],
                'description': self.mitre_mappings[mitre_id]['description']
            }
        return {
            'technique_id': mitre_id,
            'tactic': 'Unknown',
            'technique': 'Unknown',
            'description': 'Unknown technique'
        }
    
    def _get_nis2_info(self, article_id: str) -> Dict[str, Any]:
        """Get NIS2 compliance information"""
        if article_id in self.nis2_mappings:
            return {
                'article_id': article_id,
                'article': self.nis2_mappings[article_id]['article'],
                'description': self.nis2_mappings[article_id]['description']
            }
        return {
            'article_id': article_id,
            'article': 'Unknown',
            'description': 'Unknown compliance requirement'
        }
    
    def _assess_impact(self, violation: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the potential impact of the security violation"""
        impact = {
            'operational_impact': 'unknown',
            'safety_impact': 'unknown',
            'data_integrity': 'unknown',
            'system_availability': 'unknown'
        }
        
        rule_id = violation.get('id', '')
        semantic_role = features.get('semantic_role', '')
        
        # Assess based on rule type and affected component
        if 'valve' in semantic_role.lower():
            impact['operational_impact'] = 'high'
            impact['safety_impact'] = 'high'
        elif 'pump' in semantic_role.lower():
            impact['operational_impact'] = 'high'
            impact['safety_impact'] = 'medium'
        elif 'emergency' in semantic_role.lower():
            impact['operational_impact'] = 'critical'
            impact['safety_impact'] = 'critical'
        elif 'config' in semantic_role.lower():
            impact['data_integrity'] = 'high'
            impact['system_availability'] = 'medium'
        
        # Adjust based on violation type
        if 'tid_mismatch' in rule_id:
            impact['data_integrity'] = 'high'
        elif 'high_frequency' in rule_id:
            impact['system_availability'] = 'high'
        
        return impact
    
    def _generate_recommendations(self, violation: Dict[str, Any], features: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations for the incident"""
        recommendations = []
        rule_id = violation.get('id', '')
        
        if 'unauth_write' in rule_id:
            recommendations.extend([
                'Review network access controls for the source IP',
                'Implement VLAN segmentation if not already in place',
                'Add source IP to authorized hosts list if legitimate',
                'Monitor for similar unauthorized access attempts'
            ])
        elif 'emergency_bypass' in rule_id:
            recommendations.extend([
                'Immediately investigate the source of emergency control attempts',
                'Verify emergency stop systems are functioning correctly',
                'Review emergency access procedures and permissions',
                'Consider implementing additional safety interlocks'
            ])
        elif 'tid_mismatch' in rule_id:
            recommendations.extend([
                'Investigate potential network interception or spoofing',
                'Verify network integrity and routing configuration',
                'Check for unauthorized network devices or connections',
                'Implement network monitoring for MITM detection'
            ])
        elif 'high_frequency' in rule_id:
            recommendations.extend([
                'Investigate source of high-frequency traffic',
                'Check for potential DoS attack or malfunctioning device',
                'Implement rate limiting on Modbus communications',
                'Monitor system performance for degradation'
            ])
        else:
            recommendations.append('Review incident details and implement appropriate controls')
        
        return recommendations
    
    def _assess_false_positive_risk(self, violation: Dict[str, Any], features: Dict[str, Any]) -> str:
        """Assess the risk of this being a false positive"""
        risk_factors = []
        
        # Check for common false positive indicators
        if features.get('exception_code'):
            risk_factors.append('Modbus exception present - may indicate legitimate error')
        
        if features.get('source_ip') in ['10.10.20.30', '10.10.20.31']:
            risk_factors.append('Source IP is in authorized range')
        
        if features.get('vlan') == '20':
            risk_factors.append('Traffic from authorized VLAN')
        
        if len(risk_factors) > 1:
            return 'medium'
        elif len(risk_factors) == 1:
            return 'low'
        else:
            return 'high'
    
    def _calculate_confidence(self, violation: Dict[str, Any], features: Dict[str, Any]) -> int:
        """Calculate confidence score (0-100) for the detection"""
        confidence = 70  # Base confidence
        
        # Adjust based on violation type
        if 'emergency_bypass' in violation.get('id', ''):
            confidence += 20
        elif 'tid_mismatch' in violation.get('id', ''):
            confidence += 15
        elif 'unauth_write' in violation.get('id', ''):
            confidence += 10
        
        # Adjust based on source characteristics
        if features.get('source_ip') not in ['10.10.20.30', '10.10.20.31']:
            confidence += 10
        
        if features.get('vlan') != '20':
            confidence += 10
        
        # Cap at 100
        return min(confidence, 100)
    
    def _generate_tags(self, violation: Dict[str, Any], features: Dict[str, Any]) -> List[str]:
        """Generate tags for categorization"""
        tags = []
        
        # Rule-based tags
        tags.append(f"rule:{violation.get('id', 'unknown')}")
        tags.append(f"severity:{violation.get('severity', 'medium')}")
        
        # Component-based tags
        semantic_role = features.get('semantic_role', '')
        if 'valve' in semantic_role.lower():
            tags.append('component:valve')
        elif 'pump' in semantic_role.lower():
            tags.append('component:pump')
        elif 'emergency' in semantic_role.lower():
            tags.append('component:emergency')
        
        # Protocol tags
        tags.append('protocol:modbus')
        tags.append('protocol:tcp')
        
        # Network tags
        if features.get('vlan'):
            tags.append(f"vlan:{features.get('vlan')}")
        
        return tags 