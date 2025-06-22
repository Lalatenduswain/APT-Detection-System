"""
Enhanced Metrics Module for APT Detection System

This module provides comprehensive evaluation functions for ML models and MITRE ATT&CK analysis,
specifically designed to measure the effectiveness of our enhanced threat detection system.

Key Features:
- MITRE technique identification accuracy metrics
- Confidence score validation and distribution analysis
- Alert quality metrics (before/after comparison)
- SOC operator efficiency measurements
- Real-time performance monitoring
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, roc_curve
from sklearn.metrics import classification_report, accuracy_score
import json
import time
from collections import defaultdict, Counter

class EnhancedMetrics:
    """
    Enhanced metrics system for APT detection with MITRE ATT&CK analysis.
    
    This class provides comprehensive metrics for evaluating:
    - ML model performance
    - MITRE technique identification effectiveness
    - Alert quality and actionable intelligence
    - SOC operator efficiency improvements
    """
    
    def __init__(self):
        """Initialize the enhanced metrics system."""
        self.logger = logging.getLogger(__name__)
        self.mitre_metrics = MitreMetrics()
        self.model_metrics = ModelMetrics()
        self.alert_metrics = AlertMetrics()
        self.soc_metrics = SOCMetrics()
        
        # Performance tracking
        self.start_time = datetime.now()
        self.metrics_cache = {}
        self.cache_ttl = 300  # 5 minutes cache TTL
        
        self.logger.info("Enhanced metrics system initialized")
    
    def calculate_comprehensive_metrics(self, alerts: List[Dict[str, Any]], 
                                      baseline_alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Calculate comprehensive metrics for the enhanced system.
        
        Args:
            alerts: List of current alerts with enhanced MITRE analysis
            baseline_alerts: Optional list of baseline alerts for comparison
            
        Returns:
            Dictionary containing all calculated metrics
        """
        self.logger.info(f"Calculating comprehensive metrics for {len(alerts)} alerts")
        
        # Calculate all metric categories
        mitre_results = self.mitre_metrics.calculate_mitre_effectiveness(alerts)
        model_results = self.model_metrics.calculate_model_performance(alerts)
        alert_results = self.alert_metrics.calculate_alert_quality(alerts, baseline_alerts)
        soc_results = self.soc_metrics.calculate_soc_efficiency(alerts)
        
        # Calculate noise reduction if baseline provided
        noise_reduction = {}
        if baseline_alerts:
            noise_reduction = self.calculate_noise_reduction(alerts, baseline_alerts)
        
        # Compile comprehensive results
        comprehensive_metrics = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {
                'total_alerts': len(alerts),
                'baseline_alerts': len(baseline_alerts) if baseline_alerts else 0,
                'analysis_period': self._calculate_analysis_period(alerts),
                'enhancement_version': '2.0'
            },
            'mitre_metrics': mitre_results,
            'model_metrics': model_results,
            'alert_metrics': alert_results,
            'soc_metrics': soc_results,
            'noise_reduction': noise_reduction,
            'summary': self._generate_summary_metrics(mitre_results, alert_results, soc_results)
        }
        
        self.logger.info("Comprehensive metrics calculation completed")
        return comprehensive_metrics
    
    def calculate_noise_reduction(self, enhanced_alerts: List[Dict[str, Any]], 
                                baseline_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate noise reduction metrics comparing enhanced vs baseline alerts.
        
        Args:
            enhanced_alerts: Alerts with enhanced MITRE analysis
            baseline_alerts: Original baseline alerts
            
        Returns:
            Dictionary containing noise reduction metrics
        """
        self.logger.info("Calculating noise reduction metrics")
        
        # Calculate baseline metrics
        baseline_actionable = sum(1 for alert in baseline_alerts 
                                if self._is_actionable_alert(alert, enhanced=False))
        baseline_techniques = sum(len(alert.get('mitre_attack', {}).get('techniques', [])) 
                                for alert in baseline_alerts)
        
        # Calculate enhanced metrics
        enhanced_actionable = sum(1 for alert in enhanced_alerts 
                                if self._is_actionable_alert(alert, enhanced=True))
        enhanced_techniques = sum(len(alert.get('mitre_attack', {}).get('techniques', [])) 
                                for alert in enhanced_alerts)
        
        # Calculate improvements
        actionable_improvement = ((enhanced_actionable / len(enhanced_alerts)) - 
                                (baseline_actionable / len(baseline_alerts))) if baseline_alerts else 0
        
        technique_improvement = (enhanced_techniques / len(enhanced_alerts)) - \
                              (baseline_techniques / len(baseline_alerts)) if baseline_alerts else 0
        
        return {
            'baseline_stats': {
                'total_alerts': len(baseline_alerts),
                'actionable_alerts': baseline_actionable,
                'actionable_percentage': (baseline_actionable / len(baseline_alerts)) * 100 if baseline_alerts else 0,
                'avg_techniques_per_alert': baseline_techniques / len(baseline_alerts) if baseline_alerts else 0
            },
            'enhanced_stats': {
                'total_alerts': len(enhanced_alerts),
                'actionable_alerts': enhanced_actionable,
                'actionable_percentage': (enhanced_actionable / len(enhanced_alerts)) * 100,
                'avg_techniques_per_alert': enhanced_techniques / len(enhanced_alerts)
            },
            'improvements': {
                'actionable_alert_improvement': actionable_improvement * 100,  # Percentage points
                'technique_identification_improvement': technique_improvement,
                'noise_reduction_factor': (enhanced_actionable / baseline_actionable) if baseline_actionable > 0 else float('inf'),
                'intelligence_multiplier': (enhanced_techniques / baseline_techniques) if baseline_techniques > 0 else float('inf')
            }
        }
    
    def _is_actionable_alert(self, alert: Dict[str, Any], enhanced: bool = True) -> bool:
        """
        Determine if an alert is actionable based on available intelligence.
        
        Args:
            alert: Alert dictionary
            enhanced: Whether this is an enhanced alert
            
        Returns:
            Boolean indicating if alert is actionable
        """
        if enhanced:
            # Enhanced alerts are actionable if they have MITRE techniques or investigation guidance
            has_techniques = len(alert.get('mitre_attack', {}).get('techniques', [])) > 0
            has_investigation = 'investigation' in alert and len(alert['investigation'].get('next_steps', [])) > 0
            has_mitigations = any(len(t.get('mitigations', {}).get('recommendations', [])) > 0 
                                for t in alert.get('mitre_attack', {}).get('techniques', []))
            return has_techniques or has_investigation or has_mitigations
        else:
            # Baseline alerts are actionable if they have basic threat information
            has_high_severity = alert.get('severity', '').lower() in ['high', 'critical']
            has_prediction_score = alert.get('prediction_score', 0) > 0.7
            return has_high_severity or has_prediction_score
    
    def _calculate_analysis_period(self, alerts: List[Dict[str, Any]]) -> Dict[str, str]:
        """Calculate the time period covered by the alerts."""
        if not alerts:
            return {'start': 'N/A', 'end': 'N/A', 'duration': 'N/A'}
        
        timestamps = []
        for alert in alerts:
            timestamp_str = alert.get('timestamp', '')
            if timestamp_str:
                try:
                    timestamps.append(datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')))
                except:
                    continue
        
        if not timestamps:
            return {'start': 'N/A', 'end': 'N/A', 'duration': 'N/A'}
        
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        
        return {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
            'duration': str(duration)
        }
    
    def _generate_summary_metrics(self, mitre_results: Dict, alert_results: Dict, soc_results: Dict) -> Dict[str, Any]:
        """Generate high-level summary metrics for dashboard display."""
        return {
            'overall_score': self._calculate_overall_score(mitre_results, alert_results, soc_results),
            'key_improvements': {
                'technique_identification_rate': mitre_results.get('technique_coverage', {}).get('percentage', 0),
                'average_confidence_score': mitre_results.get('confidence_analysis', {}).get('mean_confidence', 0),
                'alert_quality_score': alert_results.get('quality_score', 0),
                'investigation_efficiency': soc_results.get('efficiency_metrics', {}).get('avg_investigation_priority_score', 0)
            },
            'demo_metrics': {
                'techniques_per_alert': mitre_results.get('technique_coverage', {}).get('avg_techniques_per_alert', 0),
                'confidence_accuracy': mitre_results.get('confidence_analysis', {}).get('high_confidence_percentage', 0),
                'actionable_alerts_percentage': alert_results.get('actionable_percentage', 0),
                'investigation_time_reduction': soc_results.get('efficiency_metrics', {}).get('estimated_time_reduction_percentage', 0)
            }
        }
    
    def _calculate_overall_score(self, mitre_results: Dict, alert_results: Dict, soc_results: Dict) -> float:
        """Calculate an overall system effectiveness score (0-100)."""
        # Weight different components
        mitre_score = mitre_results.get('technique_coverage', {}).get('percentage', 0) * 0.4
        alert_score = alert_results.get('quality_score', 0) * 0.3
        soc_score = soc_results.get('efficiency_metrics', {}).get('avg_investigation_priority_score', 0) * 0.3
        
        return min(100, mitre_score + alert_score + soc_score)

class MitreMetrics:
    """Metrics specifically for MITRE ATT&CK technique identification and analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_mitre_effectiveness(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate comprehensive MITRE ATT&CK effectiveness metrics.
        
        Args:
            alerts: List of alerts with MITRE analysis
            
        Returns:
            Dictionary containing MITRE effectiveness metrics
        """
        self.logger.info("Calculating MITRE ATT&CK effectiveness metrics")
        
        # Extract MITRE data from alerts
        mitre_data = self._extract_mitre_data(alerts)
        
        # Calculate various MITRE metrics
        technique_coverage = self._calculate_technique_coverage(mitre_data)
        confidence_analysis = self._calculate_confidence_analysis(mitre_data)
        tactic_distribution = self._calculate_tactic_distribution(mitre_data)
        apt_pattern_analysis = self._calculate_apt_pattern_analysis(mitre_data)
        kill_chain_analysis = self._calculate_kill_chain_analysis(mitre_data)
        
        return {
            'technique_coverage': technique_coverage,
            'confidence_analysis': confidence_analysis,
            'tactic_distribution': tactic_distribution,
            'apt_pattern_analysis': apt_pattern_analysis,
            'kill_chain_analysis': kill_chain_analysis,
            'enhancement_effectiveness': self._calculate_enhancement_effectiveness(mitre_data)
        }
    
    def _extract_mitre_data(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract MITRE ATT&CK data from alerts."""
        mitre_data = []
        
        for alert in alerts:
            mitre_attack = alert.get('mitre_attack', {})
            if mitre_attack and mitre_attack.get('techniques'):
                mitre_data.append({
                    'alert_id': alert.get('entity', 'unknown'),
                    'timestamp': alert.get('timestamp', ''),
                    'techniques': mitre_attack.get('techniques', []),
                    'tactics': mitre_attack.get('tactics', []),
                    'overall_confidence': mitre_attack.get('confidence', 0),
                    'kill_chain_phases': mitre_attack.get('kill_chain_phases', []),
                    'apt_patterns': mitre_attack.get('apt_patterns', []),
                    'enhancement_version': mitre_attack.get('enhancement_version', 'unknown')
                })
        
        return mitre_data
    
    def _calculate_technique_coverage(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate technique identification coverage metrics."""
        if not mitre_data:
            return {'percentage': 0, 'avg_techniques_per_alert': 0, 'unique_techniques': 0}
        
        total_alerts_with_techniques = len(mitre_data)
        total_techniques = sum(len(data['techniques']) for data in mitre_data)
        unique_techniques = set()
        
        for data in mitre_data:
            for technique in data['techniques']:
                unique_techniques.add(technique['id'])
        
        return {
            'percentage': (total_alerts_with_techniques / len(mitre_data)) * 100,
            'avg_techniques_per_alert': total_techniques / len(mitre_data),
            'unique_techniques': len(unique_techniques),
            'total_technique_identifications': total_techniques,
            'technique_list': sorted(list(unique_techniques))
        }
    
    def _calculate_confidence_analysis(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze confidence scores for technique identification."""
        if not mitre_data:
            return {'mean_confidence': 0, 'confidence_distribution': {}}
        
        # Collect all confidence scores
        technique_confidences = []
        overall_confidences = []
        
        for data in mitre_data:
            overall_confidences.append(data['overall_confidence'])
            for technique in data['techniques']:
                technique_confidences.append(technique.get('confidence', 0))
        
        # Calculate confidence distribution
        confidence_ranges = {
            'high_confidence': sum(1 for c in technique_confidences if c >= 0.8),
            'medium_confidence': sum(1 for c in technique_confidences if 0.5 <= c < 0.8),
            'low_confidence': sum(1 for c in technique_confidences if c < 0.5)
        }
        
        return {
            'mean_confidence': np.mean(technique_confidences) if technique_confidences else 0,
            'median_confidence': np.median(technique_confidences) if technique_confidences else 0,
            'std_confidence': np.std(technique_confidences) if technique_confidences else 0,
            'confidence_distribution': confidence_ranges,
            'high_confidence_percentage': (confidence_ranges['high_confidence'] / len(technique_confidences)) * 100 if technique_confidences else 0,
            'overall_confidence_mean': np.mean(overall_confidences) if overall_confidences else 0
        }
    
    def _calculate_tactic_distribution(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate distribution of MITRE tactics."""
        tactic_counts = Counter()
        
        for data in mitre_data:
            for tactic in data['tactics']:
                tactic_counts[tactic['id']] += 1
        
        total_tactics = sum(tactic_counts.values())
        
        return {
            'tactic_frequency': dict(tactic_counts),
            'most_common_tactics': tactic_counts.most_common(5),
            'total_tactic_identifications': total_tactics,
            'unique_tactics': len(tactic_counts)
        }
    
    def _calculate_apt_pattern_analysis(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze APT pattern detection effectiveness."""
        pattern_counts = Counter()
        alerts_with_patterns = 0
        
        for data in mitre_data:
            if data['apt_patterns']:
                alerts_with_patterns += 1
                for pattern in data['apt_patterns']:
                    pattern_counts[pattern] += 1
        
        return {
            'pattern_detection_rate': (alerts_with_patterns / len(mitre_data)) * 100 if mitre_data else 0,
            'pattern_frequency': dict(pattern_counts),
            'most_common_patterns': pattern_counts.most_common(5),
            'alerts_with_patterns': alerts_with_patterns,
            'total_pattern_detections': sum(pattern_counts.values())
        }
    
    def _calculate_kill_chain_analysis(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze kill chain phase coverage."""
        phase_counts = Counter()
        
        for data in mitre_data:
            for phase in data['kill_chain_phases']:
                if phase:  # Filter out None values
                    phase_counts[phase] += 1
        
        return {
            'phase_coverage': dict(phase_counts),
            'most_common_phases': phase_counts.most_common(5),
            'total_phase_identifications': sum(phase_counts.values()),
            'unique_phases': len(phase_counts)
        }
    
    def _calculate_enhancement_effectiveness(self, mitre_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate effectiveness of the enhanced MITRE system."""
        enhanced_alerts = sum(1 for data in mitre_data if data['enhancement_version'] == '2.0')
        
        return {
            'enhanced_alerts': enhanced_alerts,
            'enhancement_adoption_rate': (enhanced_alerts / len(mitre_data)) * 100 if mitre_data else 0,
            'avg_techniques_enhanced': np.mean([len(data['techniques']) for data in mitre_data if data['enhancement_version'] == '2.0']) if enhanced_alerts else 0
        }

class ModelMetrics:
    """Metrics for ML model performance evaluation."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_model_performance(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate ML model performance metrics.
        
        Args:
            alerts: List of alerts with prediction scores
            
        Returns:
            Dictionary containing model performance metrics
        """
        self.logger.info("Calculating ML model performance metrics")
        
        # Extract prediction data
        prediction_scores = []
        severity_levels = []
        detection_types = []
        
        for alert in alerts:
            prediction_scores.append(alert.get('prediction_score', 0))
            severity_levels.append(alert.get('severity', 'Unknown'))
            detection_types.append(alert.get('detection_type', 'unknown'))
        
        # Calculate performance metrics
        score_distribution = self._calculate_score_distribution(prediction_scores)
        severity_analysis = self._calculate_severity_analysis(severity_levels)
        detection_type_analysis = self._calculate_detection_type_analysis(detection_types)
        
        return {
            'prediction_score_analysis': score_distribution,
            'severity_analysis': severity_analysis,
            'detection_type_analysis': detection_type_analysis,
            'model_effectiveness': self._calculate_model_effectiveness(prediction_scores, severity_levels)
        }
    
    def _calculate_score_distribution(self, scores: List[float]) -> Dict[str, Any]:
        """Calculate distribution of prediction scores."""
        if not scores:
            return {'mean': 0, 'distribution': {}}
        
        score_ranges = {
            'high_confidence': sum(1 for s in scores if s >= 0.8),
            'medium_confidence': sum(1 for s in scores if 0.5 <= s < 0.8),
            'low_confidence': sum(1 for s in scores if s < 0.5)
        }
        
        return {
            'mean': np.mean(scores),
            'median': np.median(scores),
            'std': np.std(scores),
            'min': np.min(scores),
            'max': np.max(scores),
            'distribution': score_ranges,
            'high_confidence_percentage': (score_ranges['high_confidence'] / len(scores)) * 100
        }
    
    def _calculate_severity_analysis(self, severities: List[str]) -> Dict[str, Any]:
        """Analyze severity level distribution."""
        severity_counts = Counter(severities)
        total = len(severities)
        
        return {
            'severity_distribution': dict(severity_counts),
            'severity_percentages': {k: (v/total)*100 for k, v in severity_counts.items()},
            'most_common_severity': severity_counts.most_common(1)[0] if severity_counts else ('Unknown', 0)
        }
    
    def _calculate_detection_type_analysis(self, detection_types: List[str]) -> Dict[str, Any]:
        """Analyze detection type distribution."""
        type_counts = Counter(detection_types)
        total = len(detection_types)
        
        return {
            'detection_type_distribution': dict(type_counts),
            'detection_type_percentages': {k: (v/total)*100 for k, v in type_counts.items()},
            'most_common_type': type_counts.most_common(1)[0] if type_counts else ('unknown', 0)
        }
    
    def _calculate_model_effectiveness(self, scores: List[float], severities: List[str]) -> Dict[str, Any]:
        """Calculate overall model effectiveness metrics."""
        if not scores:
            return {'effectiveness_score': 0}
        
        # Calculate correlation between prediction scores and severity
        severity_numeric = [self._severity_to_numeric(s) for s in severities]
        correlation = np.corrcoef(scores, severity_numeric)[0, 1] if len(scores) > 1 else 0
        
        return {
            'effectiveness_score': np.mean(scores) * 100,
            'score_severity_correlation': correlation,
            'high_confidence_alerts': sum(1 for s in scores if s >= 0.8),
            'actionable_alerts': sum(1 for s in scores if s >= 0.7)
        }
    
    def _severity_to_numeric(self, severity: str) -> int:
        """Convert severity string to numeric value."""
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        return severity_map.get(severity, 0)

class AlertMetrics:
    """Metrics for alert quality and actionable intelligence."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_alert_quality(self, alerts: List[Dict[str, Any]], 
                              baseline_alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Calculate alert quality metrics.
        
        Args:
            alerts: Current alerts to analyze
            baseline_alerts: Optional baseline alerts for comparison
            
        Returns:
            Dictionary containing alert quality metrics
        """
        self.logger.info("Calculating alert quality metrics")
        
        # Calculate current alert quality
        quality_metrics = self._calculate_quality_metrics(alerts)
        
        # Calculate improvement if baseline provided
        improvement_metrics = {}
        if baseline_alerts:
            baseline_quality = self._calculate_quality_metrics(baseline_alerts)
            improvement_metrics = self._calculate_quality_improvement(quality_metrics, baseline_quality)
        
        return {
            'current_quality': quality_metrics,
            'baseline_comparison': improvement_metrics,
            'quality_score': self._calculate_overall_quality_score(quality_metrics)
        }
    
    def _calculate_quality_metrics(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate quality metrics for a set of alerts."""
        if not alerts:
            return {'actionable_alerts': 0, 'actionable_percentage': 0}
        
        actionable_count = 0
        with_mitigations = 0
        with_investigation = 0
        with_techniques = 0
        severity_adjusted = 0
        
        for alert in alerts:
            # Check if alert is actionable
            mitre_attack = alert.get('mitre_attack', {})
            techniques = mitre_attack.get('techniques', [])
            investigation = alert.get('investigation', {})
            
            has_techniques = len(techniques) > 0
            has_mitigations = any(len(t.get('mitigations', {}).get('recommendations', [])) > 0 for t in techniques)
            has_investigation_steps = len(investigation.get('next_steps', [])) > 0
            is_severity_adjusted = alert.get('severity_adjusted', False)
            
            if has_techniques or has_mitigations or has_investigation_steps:
                actionable_count += 1
            
            if has_techniques:
                with_techniques += 1
            if has_mitigations:
                with_mitigations += 1
            if has_investigation_steps:
                with_investigation += 1
            if is_severity_adjusted:
                severity_adjusted += 1
        
        return {
            'total_alerts': len(alerts),
            'actionable_alerts': actionable_count,
            'actionable_percentage': (actionable_count / len(alerts)) * 100,
            'alerts_with_techniques': with_techniques,
            'alerts_with_mitigations': with_mitigations,
            'alerts_with_investigation': with_investigation,
            'severity_adjusted_alerts': severity_adjusted,
            'technique_percentage': (with_techniques / len(alerts)) * 100,
            'mitigation_percentage': (with_mitigations / len(alerts)) * 100,
            'investigation_percentage': (with_investigation / len(alerts)) * 100
        }
    
    def _calculate_quality_improvement(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate improvement metrics comparing current to baseline."""
        return {
            'actionable_improvement': current['actionable_percentage'] - baseline['actionable_percentage'],
            'technique_improvement': current['technique_percentage'] - baseline['technique_percentage'],
            'mitigation_improvement': current['mitigation_percentage'] - baseline['mitigation_percentage'],
            'investigation_improvement': current['investigation_percentage'] - baseline['investigation_percentage'],
            'quality_multiplier': current['actionable_percentage'] / baseline['actionable_percentage'] if baseline['actionable_percentage'] > 0 else float('inf')
        }
    
    def _calculate_overall_quality_score(self, quality_metrics: Dict[str, Any]) -> float:
        """Calculate an overall quality score (0-100)."""
        # Weight different quality factors
        actionable_score = quality_metrics['actionable_percentage'] * 0.4
        technique_score = quality_metrics['technique_percentage'] * 0.3
        mitigation_score = quality_metrics['mitigation_percentage'] * 0.2
        investigation_score = quality_metrics['investigation_percentage'] * 0.1
        
        return min(100, actionable_score + technique_score + mitigation_score + investigation_score)

class SOCMetrics:
    """Metrics for SOC operator efficiency and workflow improvements."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_soc_efficiency(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate SOC operator efficiency metrics.
        
        Args:
            alerts: List of alerts with investigation information
            
        Returns:
            Dictionary containing SOC efficiency metrics
        """
        self.logger.info("Calculating SOC efficiency metrics")
        
        # Extract investigation data
        investigation_data = self._extract_investigation_data(alerts)
        
        # Calculate efficiency metrics
        priority_analysis = self._calculate_priority_analysis(investigation_data)
        time_analysis = self._calculate_time_analysis(investigation_data)
        workflow_analysis = self._calculate_workflow_analysis(investigation_data)
        
        return {
            'efficiency_metrics': {
                'avg_investigation_priority_score': self._calculate_avg_priority_score(investigation_data),
                'estimated_time_reduction_percentage': self._calculate_time_reduction(investigation_data),
                'workflow_efficiency_score': self._calculate_workflow_efficiency(investigation_data)
            },
            'priority_analysis': priority_analysis,
            'time_analysis': time_analysis,
            'workflow_analysis': workflow_analysis
        }
    
    def _extract_investigation_data(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract investigation data from alerts."""
        investigation_data = []
        
        for alert in alerts:
            investigation = alert.get('investigation', {})
            if investigation:
                investigation_data.append({
                    'alert_id': alert.get('entity', 'unknown'),
                    'priority': investigation.get('priority', 'low'),
                    'estimated_time': investigation.get('estimated_time', '15m'),
                    'next_steps': investigation.get('next_steps', []),
                    'focus_areas': investigation.get('focus_areas', []),
                    'severity': alert.get('severity', 'Medium'),
                    'techniques_count': len(alert.get('mitre_attack', {}).get('techniques', []))
                })
        
        return investigation_data
    
    def _calculate_priority_analysis(self, investigation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze investigation priority distribution."""
        if not investigation_data:
            return {
                'priority_distribution': {},
                'priority_percentages': {},
                'high_priority_percentage': 0
            }
        
        priority_counts = Counter(data['priority'] for data in investigation_data)
        total = len(investigation_data)
        
        return {
            'priority_distribution': dict(priority_counts),
            'priority_percentages': {k: (v/total)*100 for k, v in priority_counts.items()},
            'high_priority_percentage': ((priority_counts.get('critical', 0) + priority_counts.get('high', 0)) / total) * 100
        }
    
    def _calculate_time_analysis(self, investigation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze estimated investigation times."""
        if not investigation_data:
            return {
                'avg_time_minutes': 0,
                'median_time_minutes': 0,
                'min_time_minutes': 0,
                'max_time_minutes': 0,
                'time_distribution': {}
            }
        
        # Convert time strings to minutes
        time_minutes = []
        for data in investigation_data:
            time_str = data['estimated_time']
            minutes = self._parse_time_to_minutes(time_str)
            time_minutes.append(minutes)
        
        return {
            'avg_time_minutes': np.mean(time_minutes) if time_minutes else 0,
            'median_time_minutes': np.median(time_minutes) if time_minutes else 0,
            'min_time_minutes': np.min(time_minutes) if time_minutes else 0,
            'max_time_minutes': np.max(time_minutes) if time_minutes else 0,
            'time_distribution': self._calculate_time_distribution(time_minutes)
        }
    
    def _calculate_workflow_analysis(self, investigation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze investigation workflow effectiveness."""
        if not investigation_data:
            return {'avg_steps_per_investigation': 0}
        
        step_counts = [len(data['next_steps']) for data in investigation_data]
        focus_area_counts = [len(data['focus_areas']) for data in investigation_data]
        
        return {
            'avg_steps_per_investigation': np.mean(step_counts) if step_counts else 0,
            'avg_focus_areas_per_investigation': np.mean(focus_area_counts) if focus_area_counts else 0,
            'investigations_with_steps': sum(1 for count in step_counts if count > 0),
            'investigations_with_focus_areas': sum(1 for count in focus_area_counts if count > 0),
            'workflow_completeness_percentage': (sum(1 for i, data in enumerate(investigation_data) 
                                                   if step_counts[i] > 0 and focus_area_counts[i] > 0) / len(investigation_data)) * 100
        }
    
    def _calculate_avg_priority_score(self, investigation_data: List[Dict[str, Any]]) -> float:
        """Calculate average priority score (0-100)."""
        if not investigation_data:
            return 0
        
        priority_scores = []
        for data in investigation_data:
            priority = data['priority'].lower()
            score = {'low': 25, 'medium': 50, 'high': 75, 'critical': 100}.get(priority, 25)
            priority_scores.append(score)
        
        return np.mean(priority_scores)
    
    def _calculate_time_reduction(self, investigation_data: List[Dict[str, Any]]) -> float:
        """Calculate estimated time reduction percentage."""
        if not investigation_data:
            return 0
        
        # Baseline assumption: without enhanced system, investigations take 50% longer
        baseline_multiplier = 1.5
        
        current_times = [self._parse_time_to_minutes(data['estimated_time']) for data in investigation_data]
        baseline_times = [time * baseline_multiplier for time in current_times]
        
        if not current_times:
            return 0
        
        current_avg = np.mean(current_times)
        baseline_avg = np.mean(baseline_times)
        
        reduction_percentage = ((baseline_avg - current_avg) / baseline_avg) * 100
        return max(0, reduction_percentage)
    
    def _calculate_workflow_efficiency(self, investigation_data: List[Dict[str, Any]]) -> float:
        """Calculate workflow efficiency score (0-100)."""
        if not investigation_data:
            return 0
        
        # Score based on completeness of investigation guidance
        total_score = 0
        for data in investigation_data:
            score = 0
            
            # Points for having next steps
            if len(data['next_steps']) > 0:
                score += 40
            
            # Points for having focus areas
            if len(data['focus_areas']) > 0:
                score += 30
            
            # Points for high priority (indicates good threat detection)
            if data['priority'] in ['high', 'critical']:
                score += 20
            
            # Points for having multiple techniques (rich analysis)
            if data['techniques_count'] > 3:
                score += 10
            
            total_score += score
        
        return total_score / len(investigation_data)
    
    def _parse_time_to_minutes(self, time_str: str) -> int:
        """Parse time string to minutes."""
        if not time_str:
            return 15  # Default 15 minutes
        
        time_str = time_str.lower().strip()
        
        # Handle different time formats
        if 'm' in time_str:
            # Minutes format (e.g., "24m", "15m")
            try:
                return int(time_str.replace('m', ''))
            except ValueError:
                return 15
        elif 'h' in time_str:
            # Hours format (e.g., "1h", "2h")
            try:
                hours = float(time_str.replace('h', ''))
                return int(hours * 60)
            except ValueError:
                return 60
        else:
            # Assume minutes if no unit
            try:
                return int(time_str)
            except ValueError:
                return 15
    
    def _calculate_time_distribution(self, time_minutes: List[int]) -> Dict[str, int]:
        """Calculate distribution of investigation times."""
        if not time_minutes:
            return {}
        
        return {
            'quick_investigations': sum(1 for t in time_minutes if t <= 15),  # <= 15 minutes
            'standard_investigations': sum(1 for t in time_minutes if 15 < t <= 30),  # 15-30 minutes
            'complex_investigations': sum(1 for t in time_minutes if t > 30)  # > 30 minutes
        }

# Utility functions for metrics testing and validation
def test_enhanced_metrics():
    """Test the enhanced metrics system with sample data."""
    import json
    from datetime import datetime
    
    # Create sample enhanced alerts
    sample_alerts = [
        {
            'entity': 'host1',
            'timestamp': datetime.now().isoformat(),
            'severity': 'High',
            'severity_adjusted': True,
            'original_severity': 'Medium',
            'prediction_score': 0.85,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1110',
                        'name': 'Brute Force',
                        'confidence': 0.89,
                        'criticality': 'high',
                        'supporting_features': ['number_of_failed_logins_mean'],
                        'mitigations': {
                            'recommendations': ['Implement account lockout', 'Enable MFA'],
                            'priority': 'critical'
                        }
                    },
                    {
                        'id': 'T1071',
                        'name': 'Application Layer Protocol',
                        'confidence': 0.76,
                        'criticality': 'medium',
                        'supporting_features': ['network_traffic_volume_mean']
                    }
                ],
                'tactics': [
                    {'id': 'TA0006', 'name': 'Credential Access'},
                    {'id': 'TA0011', 'name': 'Command and Control'}
                ],
                'confidence': 0.82,
                'kill_chain_phases': ['credential_access', 'command_and_control'],
                'apt_patterns': ['credential_access'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'high',
                'estimated_time': '24m',
                'focus_areas': ['Authentication Events', 'Network Traffic'],
                'next_steps': [
                    'Check authentication logs for failed login patterns',
                    'Review network connections for C2 activity'
                ]
            }
        },
        {
            'entity': 'host2',
            'timestamp': datetime.now().isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.72,
            'detection_type': 'ml_prediction',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1005',
                        'name': 'Data from Local System',
                        'confidence': 0.68,
                        'criticality': 'medium',
                        'supporting_features': ['number_of_accessed_files_mean']
                    }
                ],
                'tactics': [
                    {'id': 'TA0009', 'name': 'Collection'}
                ],
                'confidence': 0.68,
                'kill_chain_phases': ['collection'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'medium',
                'estimated_time': '18m',
                'focus_areas': ['File Access'],
                'next_steps': [
                    'Review file access logs for unusual patterns'
                ]
            }
        }
    ]
    
    # Create sample baseline alerts (Week 1 style)
    baseline_alerts = [
        {
            'entity': 'host1',
            'timestamp': datetime.now().isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.75,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        },
        {
            'entity': 'host2',
            'timestamp': datetime.now().isoformat(),
            'severity': 'Low',
            'prediction_score': 0.65,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        }
    ]
    
    # Test the metrics system
    metrics = EnhancedMetrics()
    results = metrics.calculate_comprehensive_metrics(sample_alerts, baseline_alerts)
    
    print("Enhanced Metrics Test Results:")
    print("=" * 50)
    print(f"Total Alerts Analyzed: {results['system_info']['total_alerts']}")
    print(f"Enhancement Version: {results['system_info']['enhancement_version']}")
    print()
    
    # MITRE Metrics
    mitre_metrics = results['mitre_metrics']
    print("MITRE ATT&CK Effectiveness:")
    print(f"  Technique Coverage: {mitre_metrics['technique_coverage']['percentage']:.1f}%")
    print(f"  Avg Techniques per Alert: {mitre_metrics['technique_coverage']['avg_techniques_per_alert']:.1f}")
    print(f"  Mean Confidence: {mitre_metrics['confidence_analysis']['mean_confidence']:.3f}")
    print(f"  High Confidence %: {mitre_metrics['confidence_analysis']['high_confidence_percentage']:.1f}%")
    print()
    
    # Alert Quality
    alert_metrics = results['alert_metrics']
    print("Alert Quality:")
    print(f"  Actionable Alerts: {alert_metrics['current_quality']['actionable_percentage']:.1f}%")
    print(f"  Quality Score: {alert_metrics['quality_score']:.1f}/100")
    print()
    
    # Noise Reduction
    if results['noise_reduction']:
        noise_reduction = results['noise_reduction']
        print("Noise Reduction (vs Baseline):")
        print(f"  Actionable Improvement: +{noise_reduction['improvements']['actionable_alert_improvement']:.1f} percentage points")
        print(f"  Technique Improvement: +{noise_reduction['improvements']['technique_identification_improvement']:.1f} techniques per alert")
        print(f"  Intelligence Multiplier: {noise_reduction['improvements']['intelligence_multiplier']:.1f}x")
    
    return results

if __name__ == "__main__":
    # Run test when module is executed directly
    test_results = test_enhanced_metrics()
    print("\nTest completed successfully!")
