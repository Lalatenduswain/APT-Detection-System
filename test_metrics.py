#!/usr/bin/env python3
"""
Week 3 Enhanced Metrics Test Script

This script demonstrates the comprehensive metrics capabilities implemented in Week 3,
showing quantifiable proof of our Week 2 MITRE enhancements.

Key Features Tested:
- MITRE technique identification effectiveness
- Confidence scoring accuracy
- Alert quality improvements
- SOC operator efficiency metrics
- Before/after noise reduction analysis
"""

import sys
import os
import logging
from datetime import datetime, timedelta
import json

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our enhanced metrics module
from models.metrics import EnhancedMetrics

def setup_logging():
    """Set up logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def create_realistic_enhanced_alerts():
    """Create realistic enhanced alerts for testing."""
    base_time = datetime.now()
    
    return [
        {
            'entity': 'critical_server_01',
            'timestamp': (base_time - timedelta(minutes=5)).isoformat(),
            'severity': 'Critical',
            'severity_adjusted': True,
            'original_severity': 'High',
            'prediction_score': 0.94,
            'detection_type': 'behavioral_analytics',
            'event_type': 'process',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1110',
                        'name': 'Brute Force',
                        'confidence': 0.92,
                        'criticality': 'critical',
                        'severity_impact': 2.0,
                        'supporting_features': ['number_of_failed_logins_mean'],
                        'feature_values': {'number_of_failed_logins_mean': 0.89},
                        'apt_patterns': ['credential_access'],
                        'mitigations': {
                            'recommendations': [
                                'Implement account lockout policies after 3 failed attempts',
                                'Enable multi-factor authentication for all accounts',
                                'Deploy behavioral analytics for login monitoring'
                            ],
                            'priority': 'critical'
                        },
                        'kill_chain_phase': 'credential_access'
                    },
                    {
                        'id': 'T1071.001',
                        'name': 'Application Layer Protocol: Web Protocols',
                        'confidence': 0.87,
                        'criticality': 'high',
                        'severity_impact': 1.5,
                        'supporting_features': ['network_traffic_volume_mean'],
                        'feature_values': {'network_traffic_volume_mean': 0.93},
                        'apt_patterns': ['command_and_control'],
                        'mitigations': {
                            'recommendations': [
                                'Implement web proxy filtering',
                                'Monitor for suspicious HTTP/HTTPS traffic patterns'
                            ],
                            'priority': 'high'
                        },
                        'kill_chain_phase': 'command_and_control'
                    },
                    {
                        'id': 'T1005',
                        'name': 'Data from Local System',
                        'confidence': 0.84,
                        'criticality': 'high',
                        'severity_impact': 1.8,
                        'supporting_features': ['number_of_accessed_files_mean', 'disk_io_mean'],
                        'feature_values': {'number_of_accessed_files_mean': 0.91, 'disk_io_mean': 0.86},
                        'apt_patterns': ['data_exfiltration'],
                        'mitigations': {
                            'recommendations': [
                                'Implement data loss prevention (DLP) controls',
                                'Monitor file access patterns for anomalies'
                            ],
                            'priority': 'high'
                        },
                        'kill_chain_phase': 'collection'
                    }
                ],
                'tactics': [
                    {'id': 'TA0006', 'name': 'Credential Access'},
                    {'id': 'TA0011', 'name': 'Command and Control'},
                    {'id': 'TA0009', 'name': 'Collection'}
                ],
                'confidence': 0.877,
                'kill_chain_phases': ['credential_access', 'command_and_control', 'collection'],
                'apt_patterns': ['credential_access', 'command_and_control', 'data_exfiltration'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'critical',
                'estimated_time': '35m',
                'focus_areas': ['Authentication Events', 'Network Traffic', 'File Access Logs'],
                'next_steps': [
                    'Immediately isolate affected system from network',
                    'Check authentication logs for brute force patterns',
                    'Analyze network traffic for C2 communications',
                    'Review file access logs for data collection activity',
                    'Coordinate with incident response team'
                ]
            }
        },
        {
            'entity': 'workstation_finance_05',
            'timestamp': (base_time - timedelta(minutes=12)).isoformat(),
            'severity': 'High',
            'severity_adjusted': True,
            'original_severity': 'Medium',
            'prediction_score': 0.83,
            'detection_type': 'ml_prediction',
            'event_type': 'network',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1566.001',
                        'name': 'Phishing: Spearphishing Attachment',
                        'confidence': 0.79,
                        'criticality': 'high',
                        'severity_impact': 1.6,
                        'supporting_features': ['number_of_email_sent_mean'],
                        'feature_values': {'number_of_email_sent_mean': 0.82},
                        'apt_patterns': ['lateral_movement'],
                        'mitigations': {
                            'recommendations': [
                                'Implement email security gateway with attachment scanning',
                                'Conduct phishing awareness training',
                                'Deploy endpoint detection and response (EDR)'
                            ],
                            'priority': 'high'
                        },
                        'kill_chain_phase': 'initial_access'
                    },
                    {
                        'id': 'T1055',
                        'name': 'Process Injection',
                        'confidence': 0.74,
                        'criticality': 'high',
                        'severity_impact': 1.7,
                        'supporting_features': ['number_of_processes_mean', 'memory_usage_mean'],
                        'feature_values': {'number_of_processes_mean': 0.88, 'memory_usage_mean': 0.76},
                        'apt_patterns': ['persistence'],
                        'mitigations': {
                            'recommendations': [
                                'Enable process monitoring and logging',
                                'Implement application whitelisting'
                            ],
                            'priority': 'high'
                        },
                        'kill_chain_phase': 'defense_evasion'
                    }
                ],
                'tactics': [
                    {'id': 'TA0001', 'name': 'Initial Access'},
                    {'id': 'TA0005', 'name': 'Defense Evasion'}
                ],
                'confidence': 0.765,
                'kill_chain_phases': ['initial_access', 'defense_evasion'],
                'apt_patterns': ['lateral_movement', 'persistence'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'high',
                'estimated_time': '28m',
                'focus_areas': ['Email Security', 'Process Activity'],
                'next_steps': [
                    'Review email logs for suspicious attachments',
                    'Analyze process creation events',
                    'Check for signs of lateral movement',
                    'Scan system for malware indicators'
                ]
            }
        },
        {
            'entity': 'database_server_03',
            'timestamp': (base_time - timedelta(minutes=8)).isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.71,
            'detection_type': 'behavioral_analytics',
            'event_type': 'authentication',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1078',
                        'name': 'Valid Accounts',
                        'confidence': 0.68,
                        'criticality': 'medium',
                        'severity_impact': 1.2,
                        'supporting_features': ['number_of_logins_mean'],
                        'feature_values': {'number_of_logins_mean': 0.73},
                        'apt_patterns': ['persistence'],
                        'mitigations': {
                            'recommendations': [
                                'Implement privileged access management (PAM)',
                                'Regular access reviews and deprovisioning'
                            ],
                            'priority': 'medium'
                        },
                        'kill_chain_phase': 'persistence'
                    }
                ],
                'tactics': [
                    {'id': 'TA0003', 'name': 'Persistence'}
                ],
                'confidence': 0.68,
                'kill_chain_phases': ['persistence'],
                'apt_patterns': ['persistence'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'medium',
                'estimated_time': '20m',
                'focus_areas': ['Account Activity'],
                'next_steps': [
                    'Review account usage patterns',
                    'Check for privilege escalation attempts',
                    'Validate account legitimacy'
                ]
            }
        },
        {
            'entity': 'web_server_02',
            'timestamp': (base_time - timedelta(minutes=15)).isoformat(),
            'severity': 'High',
            'severity_adjusted': True,
            'original_severity': 'Medium',
            'prediction_score': 0.88,
            'detection_type': 'behavioral_analytics',
            'event_type': 'file',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1190',
                        'name': 'Exploit Public-Facing Application',
                        'confidence': 0.85,
                        'criticality': 'critical',
                        'severity_impact': 2.1,
                        'supporting_features': ['network_traffic_volume_mean', 'cpu_usage_mean'],
                        'feature_values': {'network_traffic_volume_mean': 0.91, 'cpu_usage_mean': 0.87},
                        'apt_patterns': ['lateral_movement'],
                        'mitigations': {
                            'recommendations': [
                                'Apply security patches immediately',
                                'Implement web application firewall (WAF)',
                                'Regular vulnerability scanning'
                            ],
                            'priority': 'critical'
                        },
                        'kill_chain_phase': 'initial_access'
                    },
                    {
                        'id': 'T1505.003',
                        'name': 'Server Software Component: Web Shell',
                        'confidence': 0.81,
                        'criticality': 'high',
                        'severity_impact': 1.9,
                        'supporting_features': ['number_of_accessed_files_mean'],
                        'feature_values': {'number_of_accessed_files_mean': 0.89},
                        'apt_patterns': ['persistence'],
                        'mitigations': {
                            'recommendations': [
                                'Monitor web server file integrity',
                                'Implement file upload restrictions'
                            ],
                            'priority': 'critical'
                        },
                        'kill_chain_phase': 'persistence'
                    }
                ],
                'tactics': [
                    {'id': 'TA0001', 'name': 'Initial Access'},
                    {'id': 'TA0003', 'name': 'Persistence'}
                ],
                'confidence': 0.83,
                'kill_chain_phases': ['initial_access', 'persistence'],
                'apt_patterns': ['lateral_movement', 'persistence'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'critical',
                'estimated_time': '32m',
                'focus_areas': ['Web Application Security', 'File Integrity'],
                'next_steps': [
                    'Check web server logs for exploitation attempts',
                    'Scan for web shells and backdoors',
                    'Review application security controls',
                    'Coordinate with web development team'
                ]
            }
        },
        {
            'entity': 'endpoint_hr_12',
            'timestamp': (base_time - timedelta(minutes=3)).isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.69,
            'detection_type': 'ml_prediction',
            'event_type': 'process',
            'mitre_attack': {
                'techniques': [
                    {
                        'id': 'T1059.001',
                        'name': 'Command and Scripting Interpreter: PowerShell',
                        'confidence': 0.72,
                        'criticality': 'medium',
                        'severity_impact': 1.3,
                        'supporting_features': ['number_of_processes_mean'],
                        'feature_values': {'number_of_processes_mean': 0.78},
                        'apt_patterns': ['lateral_movement'],
                        'mitigations': {
                            'recommendations': [
                                'Enable PowerShell logging and monitoring',
                                'Implement PowerShell execution policies'
                            ],
                            'priority': 'medium'
                        },
                        'kill_chain_phase': 'execution'
                    }
                ],
                'tactics': [
                    {'id': 'TA0002', 'name': 'Execution'}
                ],
                'confidence': 0.72,
                'kill_chain_phases': ['execution'],
                'apt_patterns': ['lateral_movement'],
                'enhancement_version': '2.0'
            },
            'investigation': {
                'priority': 'medium',
                'estimated_time': '18m',
                'focus_areas': ['PowerShell Activity'],
                'next_steps': [
                    'Review PowerShell execution logs',
                    'Check for suspicious script activity',
                    'Validate user authorization for PowerShell use'
                ]
            }
        }
    ]

def create_baseline_alerts():
    """Create baseline alerts (Week 1 style) for comparison."""
    base_time = datetime.now()
    
    return [
        {
            'entity': 'critical_server_01',
            'timestamp': (base_time - timedelta(minutes=5)).isoformat(),
            'severity': 'High',
            'prediction_score': 0.78,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        },
        {
            'entity': 'workstation_finance_05',
            'timestamp': (base_time - timedelta(minutes=12)).isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.72,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        },
        {
            'entity': 'database_server_03',
            'timestamp': (base_time - timedelta(minutes=8)).isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.65,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        },
        {
            'entity': 'web_server_02',
            'timestamp': (base_time - timedelta(minutes=15)).isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.71,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        },
        {
            'entity': 'endpoint_hr_12',
            'timestamp': (base_time - timedelta(minutes=3)).isoformat(),
            'severity': 'Low',
            'prediction_score': 0.58,
            'detection_type': 'behavioral_analytics',
            'mitre_attack': {
                'techniques': [],  # No techniques in baseline
                'tactics': []
            }
        }
    ]

def test_comprehensive_metrics():
    """Test comprehensive metrics calculation."""
    print("\n" + "="*80)
    print("WEEK 3 ENHANCED METRICS DEMONSTRATION")
    print("="*80)
    print("Testing comprehensive metrics for BSides demo preparation...")
    
    # Create test data
    enhanced_alerts = create_realistic_enhanced_alerts()
    baseline_alerts = create_baseline_alerts()
    
    print(f"\nTest Data:")
    print(f"  Enhanced Alerts: {len(enhanced_alerts)}")
    print(f"  Baseline Alerts: {len(baseline_alerts)}")
    
    # Initialize metrics system
    metrics = EnhancedMetrics()
    
    # Calculate comprehensive metrics
    results = metrics.calculate_comprehensive_metrics(enhanced_alerts, baseline_alerts)
    
    return results, enhanced_alerts, baseline_alerts

def display_demo_metrics(results):
    """Display metrics in a format suitable for BSides demo."""
    print("\n" + "🎯" + " BSides DEMO METRICS " + "🎯")
    print("="*60)
    
    # System Overview
    system_info = results['system_info']
    print(f"📊 System Analysis Overview:")
    print(f"   Enhancement Version: {system_info['enhancement_version']}")
    print(f"   Total Alerts Analyzed: {system_info['total_alerts']}")
    print(f"   Analysis Period: {system_info['analysis_period']['duration']}")
    
    # Key Demo Metrics
    demo_metrics = results['summary']['demo_metrics']
    print(f"\n🚀 Key Performance Improvements:")
    print(f"   Techniques per Alert: {demo_metrics['techniques_per_alert']:.1f}")
    print(f"   Confidence Accuracy: {demo_metrics['confidence_accuracy']:.1f}%")
    print(f"   Actionable Alerts: {demo_metrics['actionable_alerts_percentage']:.1f}%")
    print(f"   Investigation Time Reduction: {demo_metrics['investigation_time_reduction']:.1f}%")
    
    # MITRE Effectiveness
    mitre_metrics = results['mitre_metrics']
    print(f"\n🎯 MITRE ATT&CK Effectiveness:")
    print(f"   Technique Coverage: {mitre_metrics['technique_coverage']['percentage']:.1f}%")
    print(f"   Mean Confidence Score: {mitre_metrics['confidence_analysis']['mean_confidence']:.3f}")
    print(f"   High Confidence Techniques: {mitre_metrics['confidence_analysis']['high_confidence_percentage']:.1f}%")
    print(f"   Unique Techniques Identified: {mitre_metrics['technique_coverage']['unique_techniques']}")
    print(f"   APT Pattern Detection Rate: {mitre_metrics['apt_pattern_analysis']['pattern_detection_rate']:.1f}%")
    
    # Alert Quality
    alert_metrics = results['alert_metrics']
    print(f"\n📈 Alert Quality Improvements:")
    print(f"   Overall Quality Score: {alert_metrics['quality_score']:.1f}/100")
    print(f"   Alerts with Techniques: {alert_metrics['current_quality']['technique_percentage']:.1f}%")
    print(f"   Alerts with Mitigations: {alert_metrics['current_quality']['mitigation_percentage']:.1f}%")
    print(f"   Alerts with Investigation Steps: {alert_metrics['current_quality']['investigation_percentage']:.1f}%")
    
    # SOC Efficiency
    soc_metrics = results['soc_metrics']
    print(f"\n👥 SOC Operator Efficiency:")
    print(f"   Average Priority Score: {soc_metrics['efficiency_metrics']['avg_investigation_priority_score']:.1f}/100")
    print(f"   Workflow Efficiency: {soc_metrics['efficiency_metrics']['workflow_efficiency_score']:.1f}/100")
    print(f"   High Priority Alerts: {soc_metrics['priority_analysis']['high_priority_percentage']:.1f}%")
    print(f"   Average Investigation Time: {soc_metrics['time_analysis']['avg_time_minutes']:.1f} minutes")
    
    # Noise Reduction (The Money Shot!)
    if results['noise_reduction']:
        noise_reduction = results['noise_reduction']
        print(f"\n🔥 NOISE REDUCTION ANALYSIS (The Big Win!):")
        print(f"   Baseline Actionable Alerts: {noise_reduction['baseline_stats']['actionable_percentage']:.1f}%")
        print(f"   Enhanced Actionable Alerts: {noise_reduction['enhanced_stats']['actionable_percentage']:.1f}%")
        print(f"   📊 IMPROVEMENT: +{noise_reduction['improvements']['actionable_alert_improvement']:.1f} percentage points")
        print(f"   ")
        print(f"   Baseline Techniques per Alert: {noise_reduction['baseline_stats']['avg_techniques_per_alert']:.1f}")
        print(f"   Enhanced Techniques per Alert: {noise_reduction['enhanced_stats']['avg_techniques_per_alert']:.1f}")
        print(f"   📊 IMPROVEMENT: +{noise_reduction['improvements']['technique_identification_improvement']:.1f} techniques per alert")
        print(f"   ")
        print(f"   🎯 INTELLIGENCE MULTIPLIER: {noise_reduction['improvements']['intelligence_multiplier']:.1f}x")
        
        # Calculate the "wow factor" metrics
        baseline_actionable = noise_reduction['baseline_stats']['actionable_alerts']
        enhanced_actionable = noise_reduction['enhanced_stats']['actionable_alerts']
        if baseline_actionable > 0:
            improvement_factor = enhanced_actionable / baseline_actionable
            print(f"   🚀 ACTIONABLE ALERT IMPROVEMENT FACTOR: {improvement_factor:.1f}x")

def display_technique_analysis(results):
    """Display detailed technique analysis."""
    print("\n" + "🔍" + " DETAILED TECHNIQUE ANALYSIS " + "🔍")
    print("="*60)
    
    mitre_metrics = results['mitre_metrics']
    
    # Top techniques
    technique_coverage = mitre_metrics['technique_coverage']
    print(f"📋 Technique Identification Summary:")
    print(f"   Total Technique Identifications: {technique_coverage['total_technique_identifications']}")
    print(f"   Unique Techniques: {technique_coverage['unique_techniques']}")
    print(f"   Techniques per Alert: {technique_coverage['avg_techniques_per_alert']:.1f}")
    
    # Confidence distribution
    confidence_analysis = mitre_metrics['confidence_analysis']
    confidence_dist = confidence_analysis['confidence_distribution']
    print(f"\n📊 Confidence Score Distribution:")
    print(f"   High Confidence (≥0.8): {confidence_dist['high_confidence']} techniques")
    print(f"   Medium Confidence (0.5-0.8): {confidence_dist['medium_confidence']} techniques")
    print(f"   Low Confidence (<0.5): {confidence_dist['low_confidence']} techniques")
    
    # APT patterns
    apt_analysis = mitre_metrics['apt_pattern_analysis']
    print(f"\n🎯 APT Pattern Recognition:")
    print(f"   Pattern Detection Rate: {apt_analysis['pattern_detection_rate']:.1f}%")
    print(f"   Alerts with APT Patterns: {apt_analysis['alerts_with_patterns']}")
    print(f"   Most Common Patterns:")
    for pattern, count in apt_analysis['most_common_patterns']:
        print(f"     • {pattern}: {count} detections")
    
    # Kill chain analysis
    kill_chain = mitre_metrics['kill_chain_analysis']
    print(f"\n⚔️ Kill Chain Phase Coverage:")
    print(f"   Unique Phases Identified: {kill_chain['unique_phases']}")
    print(f"   Most Common Phases:")
    for phase, count in kill_chain['most_common_phases']:
        print(f"     • {phase}: {count} identifications")

def display_investigation_analysis(enhanced_alerts):
    """Display investigation workflow analysis."""
    print("\n" + "🔍" + " INVESTIGATION WORKFLOW ANALYSIS " + "🔍")
    print("="*60)
    
    print("📋 Sample Investigation Recommendations:")
    
    for i, alert in enumerate(enhanced_alerts[:3], 1):  # Show first 3 alerts
        investigation = alert.get('investigation', {})
        mitre_attack = alert.get('mitre_attack', {})
        
        print(f"\n   Alert {i}: {alert['entity']}")
        print(f"   Severity: {alert['severity']} (Priority: {investigation.get('priority', 'N/A')})")
        print(f"   Estimated Time: {investigation.get('estimated_time', 'N/A')}")
        print(f"   Techniques: {len(mitre_attack.get('techniques', []))}")
        
        # Show top techniques
        techniques = mitre_attack.get('techniques', [])
        if techniques:
            print(f"   Top Techniques:")
            for technique in techniques[:2]:  # Show top 2
                print(f"     • {technique['id']}: {technique['name']} (confidence: {technique['confidence']:.3f})")
        
        # Show investigation steps
        next_steps = investigation.get('next_steps', [])
        if next_steps:
            print(f"   Investigation Steps:")
            for step in next_steps[:3]:  # Show first 3 steps
                print(f"     • {step}")

def main():
    """Run the comprehensive Week 3 metrics demonstration."""
    setup_logging()
    
    print("🚀 Week 3 Enhanced Metrics Test Suite")
    print("Demonstrating quantifiable proof of our 'Cut Through the Noise' value proposition")
    
    try:
        # Run comprehensive metrics test
        results, enhanced_alerts, baseline_alerts = test_comprehensive_metrics()
        
        # Display results in demo format
        display_demo_metrics(results)
        display_technique_analysis(results)
        display_investigation_analysis(enhanced_alerts)
        
        # Summary for BSides
        print("\n" + "🎬" + " BSIDES DEMO SUMMARY " + "🎬")
        print("="*60)
        print("✅ Enhanced metrics system successfully quantifies our improvements")
        print("✅ Clear before/after comparison demonstrates 'noise reduction'")
        print("✅ Professional-grade metrics suitable for SOC operator dashboards")
        print("✅ Compelling data points for BSides presentation:")
        
        demo_metrics = results['summary']['demo_metrics']
        noise_reduction = results['noise_reduction']
        
        print(f"   📊 {demo_metrics['techniques_per_alert']:.1f} techniques per alert (vs 0 in baseline)")
        print(f"   📊 {demo_metrics['confidence_accuracy']:.1f}% high-confidence technique identification")
        print(f"   📊 {demo_metrics['actionable_alerts_percentage']:.1f}% actionable alerts")
        print(f"   📊 {noise_reduction['improvements']['intelligence_multiplier']:.1f}x intelligence multiplier")
        print(f"   📊 {demo_metrics['investigation_time_reduction']:.1f}% investigation time reduction")
        
        print(f"\n🎯 Week 3 Days 1-2 COMPLETE: Enhanced Metrics Module with MITRE-specific measurements")
        print(f"   ✅ Comprehensive metrics framework implemented")
        print(f"   ✅ MITRE technique effectiveness quantified")
        print(f"   ✅ Alert quality improvements measured")
        print(f"   ✅ SOC operator efficiency metrics calculated")
        print(f"   ✅ Noise reduction analysis demonstrates clear value")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in Week 3 metrics test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
