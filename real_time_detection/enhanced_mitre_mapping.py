"""
Enhanced MITRE ATT&CK Mapping Module

This module provides advanced MITRE ATT&CK technique identification with:
- Confidence scoring based on multiple factors
- APT-specific pattern recognition
- Mitigation recommendations
- Severity adjustment based on technique criticality
- Kill chain analysis
"""

import os
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

class EnhancedMitreMapper:
    """
    Enhanced MITRE ATT&CK mapper with sophisticated confidence scoring
    and APT-specific pattern recognition.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the enhanced MITRE mapper.
        
        Args:
            config_path: Path to the enhanced mapping configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = {}
        
        # Load enhanced configuration
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 
                'config', 
                'enhanced_mitre_ttp_map.yaml'
            )
        
        self.load_config(config_path)
        
        # Initialize mapping data
        self.feature_mappings = self.config.get('feature_mappings', {})
        self.apt_patterns = self.config.get('apt_patterns', {})
        self.event_type_mappings = self.config.get('event_type_mappings', {})
        self.entity_tactics = self.config.get('entity_tactics', {})
        self.mitigations = self.config.get('mitigations', {})
        self.confidence_params = self.config.get('confidence_scoring', {})
        self.criticality_levels = self.config.get('criticality_levels', {})
        self.kill_chain = self.config.get('kill_chain', {})
        self.apt_groups = self.config.get('apt_groups', {})
    
    def load_config(self, config_path: str) -> None:
        """
        Load enhanced mapping configuration from YAML file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, 'r') as file:
                self.config = yaml.safe_load(file)
                self.logger.info(f"Loaded enhanced MITRE mapping config from {config_path}")
        except Exception as e:
            self.logger.error(f"Error loading enhanced mapping config: {str(e)}")
            self.config = {}
    
    def map_features_to_techniques_enhanced(
        self, 
        features: Dict[str, float],
        prediction_score: float,
        event_type: str = None,
        entity_type: str = None,
        timestamp: datetime = None
    ) -> List[Dict[str, Any]]:
        """
        Map features to MITRE ATT&CK techniques with enhanced confidence scoring.
        
        Args:
            features: Dictionary of feature names and their values
            prediction_score: The overall prediction score from the model
            event_type: Optional event type for more specific mapping
            entity_type: Optional entity type for more specific mapping
            timestamp: Optional timestamp for temporal analysis
            
        Returns:
            List of technique dictionaries with confidence scores and metadata
        """
        if prediction_score < 0.5:
            return []
        
        technique_candidates = {}
        
        # Map based on feature values
        for feature_name, value in features.items():
            if feature_name in self.feature_mappings:
                mapping = self.feature_mappings[feature_name]
                threshold = mapping.get('threshold', 0.6)
                
                if value >= threshold:
                    for technique_info in mapping['techniques']:
                        technique_id = technique_info['id']
                        
                        # Calculate base confidence
                        base_confidence = technique_info.get('confidence_weight', 0.5)
                        
                        # Adjust confidence based on how far above threshold
                        threshold_excess = (value - threshold) / (1.0 - threshold)
                        confidence_adjustment = threshold_excess * 0.2
                        
                        confidence = min(0.95, base_confidence + confidence_adjustment)
                        
                        if technique_id not in technique_candidates:
                            technique_candidates[technique_id] = {
                                'id': technique_id,
                                'name': technique_info['name'],
                                'confidence': confidence,
                                'criticality': technique_info.get('criticality', 'medium'),
                                'description': technique_info.get('description', ''),
                                'supporting_features': [feature_name],
                                'feature_values': {feature_name: value}
                            }
                        else:
                            # Technique already identified, boost confidence
                            existing = technique_candidates[technique_id]
                            existing['confidence'] = min(0.95, existing['confidence'] + 0.1)
                            existing['supporting_features'].append(feature_name)
                            existing['feature_values'][feature_name] = value
        
        # Apply event type specific boosts
        if event_type and event_type in self.event_type_mappings:
            event_mapping = self.event_type_mappings[event_type]
            primary_techniques = event_mapping.get('primary_techniques', [])
            confidence_multiplier = event_mapping.get('confidence_multiplier', 1.0)
            
            for technique_id in technique_candidates:
                if technique_id in primary_techniques:
                    technique_candidates[technique_id]['confidence'] *= confidence_multiplier
                    technique_candidates[technique_id]['confidence'] = min(0.95, technique_candidates[technique_id]['confidence'])
        
        # Apply entity type specific boosts
        if entity_type and entity_type in self.entity_tactics:
            entity_config = self.entity_tactics[entity_type]
            priority_tactics = entity_config.get('priority_tactics', [])
            confidence_boost = entity_config.get('confidence_boost', 0.0)
            
            for technique_id in technique_candidates:
                # Check if technique belongs to priority tactics
                technique_tactics = self._get_technique_tactics(technique_id)
                if any(tactic in priority_tactics for tactic in technique_tactics):
                    technique_candidates[technique_id]['confidence'] += confidence_boost
                    technique_candidates[technique_id]['confidence'] = min(0.95, technique_candidates[technique_id]['confidence'])
        
        # Apply APT pattern recognition
        self._apply_apt_pattern_boosts(technique_candidates)
        
        # Apply confidence scoring rules
        self._apply_confidence_scoring_rules(technique_candidates, features, prediction_score)
        
        # Convert to list and sort by confidence
        techniques = list(technique_candidates.values())
        techniques.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Add additional metadata
        for technique in techniques:
            technique['mitigations'] = self._get_mitigations(technique['id'])
            technique['kill_chain_phase'] = self._get_kill_chain_phase(technique['id'])
            technique['severity_impact'] = self._calculate_severity_impact(technique)
        
        return techniques
    
    def _get_technique_tactics(self, technique_id: str) -> List[str]:
        """Get the tactics associated with a technique."""
        # This would normally query the MITRE ATT&CK database
        # For now, we'll use our kill chain mapping
        for phase, phase_info in self.kill_chain.items():
            if technique_id in phase_info.get('techniques', []):
                return phase_info.get('tactics', [])
        return []
    
    def _apply_apt_pattern_boosts(self, technique_candidates: Dict[str, Dict]) -> None:
        """Apply confidence boosts for APT-specific patterns."""
        identified_techniques = set(technique_candidates.keys())
        
        for pattern_name, pattern_info in self.apt_patterns.items():
            pattern_techniques = set(pattern_info['techniques'])
            confidence_boost = pattern_info.get('confidence_boost', 0.0)
            
            # Check if we have multiple techniques from this pattern
            matching_techniques = identified_techniques.intersection(pattern_techniques)
            if len(matching_techniques) >= 2:
                for technique_id in matching_techniques:
                    technique_candidates[technique_id]['confidence'] += confidence_boost
                    technique_candidates[technique_id]['confidence'] = min(0.95, technique_candidates[technique_id]['confidence'])
                    
                    # Add pattern information
                    if 'apt_patterns' not in technique_candidates[technique_id]:
                        technique_candidates[technique_id]['apt_patterns'] = []
                    technique_candidates[technique_id]['apt_patterns'].append(pattern_name)
    
    def _apply_confidence_scoring_rules(
        self, 
        technique_candidates: Dict[str, Dict], 
        features: Dict[str, float], 
        prediction_score: float
    ) -> None:
        """Apply confidence scoring rules based on various factors."""
        params = self.confidence_params
        
        for technique_id, technique in technique_candidates.items():
            # Apply boosters
            boosters = params.get('boosters', {})
            
            # Multiple techniques boost
            if len(technique_candidates) > 1:
                technique['confidence'] += boosters.get('multiple_techniques', 0.0)
            
            # High severity feature boost
            max_feature_value = max(technique['feature_values'].values())
            if max_feature_value > 0.9:
                technique['confidence'] += boosters.get('high_severity_feature', 0.0)
            
            # APT pattern match boost (already applied in _apply_apt_pattern_boosts)
            if 'apt_patterns' in technique:
                technique['confidence'] += boosters.get('apt_pattern_match', 0.0)
            
            # Apply penalties
            penalties = params.get('penalties', {})
            
            # Single technique penalty
            if len(technique_candidates) == 1:
                technique['confidence'] += penalties.get('single_technique', 0.0)  # This is negative
            
            # Low feature value penalty
            min_feature_value = min(technique['feature_values'].values())
            feature_thresholds = {name: self.feature_mappings[name]['threshold'] 
                                for name in technique['supporting_features'] 
                                if name in self.feature_mappings}
            
            if feature_thresholds:
                avg_threshold = sum(feature_thresholds.values()) / len(feature_thresholds)
                if min_feature_value < avg_threshold + 0.1:
                    technique['confidence'] += penalties.get('low_feature_value', 0.0)  # This is negative
            
            # Ensure confidence stays within bounds
            min_conf = params.get('min_confidence', 0.1)
            max_conf = params.get('max_confidence', 0.95)
            technique['confidence'] = max(min_conf, min(max_conf, technique['confidence']))
    
    def _get_mitigations(self, technique_id: str) -> Dict[str, Any]:
        """Get mitigation recommendations for a technique."""
        if technique_id in self.mitigations:
            return self.mitigations[technique_id]
        return {
            'recommendations': ['Monitor for this technique'],
            'priority': 'medium'
        }
    
    def _get_kill_chain_phase(self, technique_id: str) -> Optional[str]:
        """Get the kill chain phase for a technique."""
        for phase, phase_info in self.kill_chain.items():
            if technique_id in phase_info.get('techniques', []):
                return phase
        return None
    
    def _calculate_severity_impact(self, technique: Dict[str, Any]) -> float:
        """Calculate severity impact based on technique criticality."""
        criticality = technique.get('criticality', 'medium')
        
        for level, level_info in self.criticality_levels.items():
            if technique['id'] in level_info.get('techniques', []):
                return level_info.get('severity_boost', 1.0)
            elif criticality == level:
                return level_info.get('severity_boost', 1.0)
        
        return 1.0  # Default multiplier
    
    def enrich_alert_enhanced(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with enhanced MITRE ATT&CK information.
        
        Args:
            alert: The alert dictionary to enrich
            
        Returns:
            Enriched alert with enhanced MITRE ATT&CK information
        """
        features = alert.get('features', {})
        prediction_score = alert.get('prediction_score', 0)
        detection_type = alert.get('detection_type', '')
        entity = alert.get('entity', 'unknown')
        entity_type = alert.get('entity_type', 'host')
        event_type = alert.get('event_type', '')
        timestamp = alert.get('timestamp')
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        elif timestamp is None:
            timestamp = datetime.now()
        
        self.logger.info(f"Enhanced MITRE enrichment for {entity} (type: {detection_type}, event: {event_type})")
        
        # Get enhanced technique mappings
        techniques = self.map_features_to_techniques_enhanced(
            features, 
            prediction_score,
            event_type=event_type,
            entity_type=entity_type,
            timestamp=timestamp
        )
        
        # Group techniques by tactics
        tactics = {}
        for technique in techniques:
            technique_tactics = self._get_technique_tactics(technique['id'])
            for tactic_id in technique_tactics:
                if tactic_id not in tactics:
                    tactics[tactic_id] = {
                        'id': tactic_id,
                        'name': self._get_tactic_name(tactic_id),
                        'techniques': []
                    }
                tactics[tactic_id]['techniques'].append({
                    'id': technique['id'],
                    'name': technique['name'],
                    'confidence': technique['confidence']
                })
        
        # Calculate overall confidence
        overall_confidence = 0.0
        if techniques:
            # Weight by technique confidence and criticality
            total_weight = 0.0
            weighted_sum = 0.0
            
            for technique in techniques:
                weight = technique['confidence'] * technique['severity_impact']
                weighted_sum += technique['confidence'] * weight
                total_weight += weight
            
            if total_weight > 0:
                overall_confidence = weighted_sum / total_weight
        
        # Adjust alert severity based on technique criticality
        original_severity = alert.get('severity', 'Medium')
        adjusted_severity = self._adjust_severity(original_severity, techniques)
        
        # Create enhanced MITRE ATT&CK information
        enriched_alert = alert.copy()
        enriched_alert['mitre_attack'] = {
            'techniques': techniques,
            'tactics': list(tactics.values()),
            'confidence': round(overall_confidence, 3),
            'kill_chain_phases': list(set(t.get('kill_chain_phase') for t in techniques if t.get('kill_chain_phase'))),
            'apt_patterns': list(set(pattern for t in techniques for pattern in t.get('apt_patterns', []))),
            'enhancement_version': self.config.get('version', '2.0'),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Update severity if significantly different
        if adjusted_severity != original_severity:
            enriched_alert['severity'] = adjusted_severity
            enriched_alert['severity_adjusted'] = True
            enriched_alert['original_severity'] = original_severity
        
        # Add investigation recommendations
        enriched_alert['investigation'] = self._generate_investigation_recommendations(techniques, entity_type)
        
        # Log results
        if techniques:
            self.logger.info(f"Enhanced analysis identified {len(techniques)} techniques for {entity}")
            self.logger.info(f"Overall confidence: {overall_confidence:.3f}")
            for technique in techniques[:3]:  # Log top 3
                self.logger.info(f"- {technique['id']}: {technique['name']} (confidence: {technique['confidence']:.3f})")
        else:
            self.logger.info(f"No MITRE ATT&CK techniques identified for {entity}")
        
        return enriched_alert
    
    def _get_tactic_name(self, tactic_id: str) -> str:
        """Get the name of a tactic from its ID."""
        tactic_names = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact',
            'TA0042': 'Resource Development',
            'TA0043': 'Reconnaissance'
        }
        return tactic_names.get(tactic_id, 'Unknown Tactic')
    
    def _adjust_severity(self, original_severity: str, techniques: List[Dict[str, Any]]) -> str:
        """Adjust alert severity based on technique criticality."""
        if not techniques:
            return original_severity
        
        # Find the highest severity impact
        max_impact = max(t.get('severity_impact', 1.0) for t in techniques)
        
        severity_levels = ['Low', 'Medium', 'High', 'Critical']
        current_index = severity_levels.index(original_severity) if original_severity in severity_levels else 1
        
        # Adjust based on severity impact
        if max_impact >= 2.0:  # Critical techniques
            new_index = min(3, current_index + 2)
        elif max_impact >= 1.5:  # High impact techniques
            new_index = min(3, current_index + 1)
        elif max_impact <= 0.5:  # Low impact techniques
            new_index = max(0, current_index - 1)
        else:
            new_index = current_index
        
        return severity_levels[new_index]
    
    def _generate_investigation_recommendations(
        self, 
        techniques: List[Dict[str, Any]], 
        entity_type: str
    ) -> Dict[str, Any]:
        """Generate investigation recommendations based on identified techniques."""
        if not techniques:
            return {
                'priority': 'low',
                'next_steps': ['Review alert details', 'Check for false positive'],
                'focus_areas': []
            }
        
        # Determine investigation priority
        max_confidence = max(t['confidence'] for t in techniques)
        max_criticality = max(t.get('severity_impact', 1.0) for t in techniques)
        
        if max_confidence > 0.8 and max_criticality >= 1.5:
            priority = 'critical'
        elif max_confidence > 0.7 or max_criticality >= 1.5:
            priority = 'high'
        elif max_confidence > 0.5:
            priority = 'medium'
        else:
            priority = 'low'
        
        # Generate next steps based on techniques
        next_steps = []
        focus_areas = []
        
        technique_ids = [t['id'] for t in techniques]
        
        # Add specific recommendations based on techniques
        if 'T1110' in technique_ids:  # Brute Force
            next_steps.append('Check authentication logs for failed login patterns')
            focus_areas.append('Authentication Events')
        
        if 'T1486' in technique_ids:  # Data Encrypted for Impact
            next_steps.append('Immediately isolate affected systems')
            next_steps.append('Check for ransomware indicators')
            focus_areas.append('File System Changes')
        
        if any(t in technique_ids for t in ['T1071', 'T1041', 'T1105']):  # Network techniques
            next_steps.append('Analyze network traffic patterns')
            next_steps.append('Check for unusual outbound connections')
            focus_areas.append('Network Communications')
        
        if any(t in technique_ids for t in ['T1059', 'T1055', 'T1106']):  # Process techniques
            next_steps.append('Examine process execution history')
            next_steps.append('Check for suspicious command lines')
            focus_areas.append('Process Activity')
        
        # Add general recommendations
        if not next_steps:
            next_steps = [
                'Review system logs for anomalous activity',
                'Check for indicators of compromise',
                'Correlate with other security events'
            ]
        
        return {
            'priority': priority,
            'next_steps': next_steps,
            'focus_areas': focus_areas,
            'estimated_time': self._estimate_investigation_time(priority, len(techniques))
        }
    
    def _estimate_investigation_time(self, priority: str, num_techniques: int) -> str:
        """Estimate investigation time based on priority and complexity."""
        base_times = {
            'critical': 30,  # minutes
            'high': 20,
            'medium': 15,
            'low': 10
        }
        
        base_time = base_times.get(priority, 15)
        complexity_factor = min(2.0, 1.0 + (num_techniques - 1) * 0.2)
        estimated_minutes = int(base_time * complexity_factor)
        
        if estimated_minutes >= 60:
            hours = estimated_minutes // 60
            minutes = estimated_minutes % 60
            return f"{hours}h {minutes}m" if minutes > 0 else f"{hours}h"
        else:
            return f"{estimated_minutes}m"

# Testing the enhanced MITRE mapping
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create enhanced mapper
    mapper = EnhancedMitreMapper()
    
    # Test with sample alert
    sample_alert = {
        'entity': 'test_host',
        'entity_type': 'host',
        'timestamp': datetime.now().isoformat(),
        'severity': 'Medium',
        'prediction_score': 0.85,
        'detection_type': 'behavioral_analytics',
        'event_type': 'process',
        'features': {
            'network_traffic_volume_mean': 0.9,
            'number_of_logins_mean': 0.2,
            'number_of_failed_logins_mean': 0.8,
            'number_of_accessed_files_mean': 0.9,
            'number_of_email_sent_mean': 0.2,
            'cpu_usage_mean': 0.8,
            'memory_usage_mean': 0.4,
            'disk_io_mean': 0.2,
            'network_latency_mean': 0.1,
            'number_of_processes_mean': 0.7
        }
    }
    
    print("Testing Enhanced MITRE Mapping...")
    print(f"Original alert: {sample_alert['entity']} - {sample_alert['severity']}")
    
    # Enrich with enhanced MITRE mapping
    enriched_alert = mapper.enrich_alert_enhanced(sample_alert)
    
    # Display results
    if 'mitre_attack' in enriched_alert:
        mitre_info = enriched_alert['mitre_attack']
        print(f"\nEnhanced MITRE Analysis Results:")
        print(f"Overall Confidence: {mitre_info['confidence']:.3f}")
        print(f"Techniques Identified: {len(mitre_info['techniques'])}")
        print(f"Tactics Involved: {len(mitre_info['tactics'])}")
        
        if mitre_info['techniques']:
            print("\nTop Techniques:")
            for i, technique in enumerate(mitre_info['techniques'][:5]):
                print(f"  {i+1}. {technique['id']}: {technique['name']}")
                print(f"     Confidence: {technique['confidence']:.3f}")
                print(f"     Criticality: {technique['criticality']}")
                if 'mitigations' in technique:
                    print(f"     Mitigations: {len(technique['mitigations']['recommendations'])} recommendations")
        
        if 'investigation' in enriched_alert:
            inv = enriched_alert['investigation']
            print(f"\nInvestigation Recommendations:")
            print(f"Priority: {inv['priority']}")
            print(f"Estimated Time: {inv['estimated_time']}")
            print(f"Next Steps: {', '.join(inv['next_steps'][:2])}")
        
        if enriched_alert.get('severity_adjusted'):
            print(f"\nSeverity adjusted: {enriched_alert['original_severity']} → {enriched_alert['severity']}")
    else:
        print("No MITRE ATT&CK information generated")
