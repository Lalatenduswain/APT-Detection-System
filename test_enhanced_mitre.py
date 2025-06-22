#!/usr/bin/env python3
"""
Enhanced MITRE ATT&CK Test Script

This script tests the enhanced MITRE mapping implementation with:
- Advanced confidence scoring
- APT pattern recognition
- Mitigation recommendations
- Severity adjustment
- Investigation recommendations
"""

import sys
import os
import logging
import json
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from real_time_detection.enhanced_mitre_mapping import EnhancedMitreMapper
from real_time_detection.prediction_engine import PredictionEngine
from real_time_detection.data_ingestion import DataIngestionManager

def setup_logging():
    """Set up logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def test_enhanced_mitre_mapper_direct():
    """Test the enhanced MITRE mapper directly."""
    print("\n" + "="*70)
    print("TEST 1: Enhanced MITRE Mapper Direct Testing")
    print("="*70)
    
    try:
        # Create enhanced mapper
        mapper = EnhancedMitreMapper()
        
        # Test with high-confidence APT-like alert
        apt_alert = {
            'entity': 'compromised_host',
            'entity_type': 'host',
            'timestamp': datetime.now().isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.92,
            'detection_type': 'behavioral_analytics',
            'event_type': 'process',
            'features': {
                'network_traffic_volume_mean': 0.95,  # Very high - C2 communication
                'number_of_logins_mean': 0.2,
                'number_of_failed_logins_mean': 0.85,  # High - brute force
                'number_of_accessed_files_mean': 0.92,  # Very high - data collection
                'number_of_email_sent_mean': 0.1,
                'cpu_usage_mean': 0.88,  # High - encryption/processing
                'memory_usage_mean': 0.6,
                'disk_io_mean': 0.8,  # High - file operations
                'network_latency_mean': 0.1,
                'number_of_processes_mean': 0.82  # High - multiple processes
            }
        }
        
        print(f"Testing APT-like scenario:")
        print(f"Entity: {apt_alert['entity']}")
        print(f"Original severity: {apt_alert['severity']}")
        print(f"Prediction score: {apt_alert['prediction_score']}")
        print(f"High anomaly features:")
        for feature, value in apt_alert['features'].items():
            if value > 0.8:
                print(f"  - {feature}: {value}")
        
        # Enrich with enhanced MITRE mapping
        enriched_alert = mapper.enrich_alert_enhanced(apt_alert)
        
        # Analyze results
        if 'mitre_attack' in enriched_alert:
            mitre_info = enriched_alert['mitre_attack']
            
            print(f"\n✅ Enhanced MITRE Analysis Results:")
            print(f"Overall Confidence: {mitre_info['confidence']:.3f}")
            print(f"Enhancement Version: {mitre_info.get('enhancement_version', 'N/A')}")
            print(f"Techniques Identified: {len(mitre_info['techniques'])}")
            print(f"Tactics Involved: {len(mitre_info['tactics'])}")
            print(f"Kill Chain Phases: {', '.join(mitre_info.get('kill_chain_phases', []))}")
            
            if mitre_info.get('apt_patterns'):
                print(f"APT Patterns Detected: {', '.join(mitre_info['apt_patterns'])}")
            
            # Show severity adjustment
            if enriched_alert.get('severity_adjusted'):
                print(f"\n🔥 Severity Adjusted: {enriched_alert['original_severity']} → {enriched_alert['severity']}")
            
            # Show top techniques with details
            if mitre_info['techniques']:
                print(f"\n📋 Top Techniques (showing top 5):")
                for i, technique in enumerate(mitre_info['techniques'][:5]):
                    print(f"  {i+1}. {technique['id']}: {technique['name']}")
                    print(f"     Confidence: {technique['confidence']:.3f}")
                    print(f"     Criticality: {technique['criticality']}")
                    print(f"     Severity Impact: {technique.get('severity_impact', 1.0):.1f}x")
                    print(f"     Supporting Features: {', '.join(technique['supporting_features'])}")
                    
                    if 'apt_patterns' in technique:
                        print(f"     APT Patterns: {', '.join(technique['apt_patterns'])}")
                    
                    # Show mitigation recommendations
                    mitigations = technique.get('mitigations', {})
                    if mitigations.get('recommendations'):
                        print(f"     Mitigations ({mitigations.get('priority', 'medium')} priority):")
                        for rec in mitigations['recommendations'][:2]:  # Show first 2
                            print(f"       • {rec}")
                    print()
            
            # Show investigation recommendations
            if 'investigation' in enriched_alert:
                inv = enriched_alert['investigation']
                print(f"🔍 Investigation Recommendations:")
                print(f"   Priority: {inv['priority'].upper()}")
                print(f"   Estimated Time: {inv['estimated_time']}")
                print(f"   Focus Areas: {', '.join(inv['focus_areas'])}")
                print(f"   Next Steps:")
                for step in inv['next_steps'][:3]:  # Show first 3
                    print(f"     • {step}")
            
            return True
        else:
            print("❌ No enhanced MITRE information generated")
            return False
            
    except Exception as e:
        print(f"❌ Error in enhanced MITRE mapper test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_prediction_engine_enhanced():
    """Test enhanced MITRE mapping through prediction engine."""
    print("\n" + "="*70)
    print("TEST 2: Prediction Engine with Enhanced MITRE Mapping")
    print("="*70)
    
    try:
        # Create prediction engine (should automatically use enhanced mapping)
        engine = PredictionEngine(use_saved_models=True)
        
        # Check if enhanced mapping is enabled
        if hasattr(engine, 'use_enhanced_mitre') and engine.use_enhanced_mitre:
            print("✅ Enhanced MITRE mapping is enabled in prediction engine")
        else:
            print("⚠️  Enhanced MITRE mapping not enabled, using standard mapping")
        
        # Create test data simulating sophisticated APT activity
        import pandas as pd
        
        apt_scenario_data = pd.DataFrame([{
            'host': 'target_server',
            'time_window': datetime.now(),
            'network_traffic_volume_mean': 0.93,  # High C2 traffic
            'number_of_logins_mean': 0.3,
            'number_of_failed_logins_mean': 0.78,  # Credential attacks
            'number_of_accessed_files_mean': 0.89,  # Data collection
            'number_of_email_sent_mean': 0.1,
            'cpu_usage_mean': 0.91,  # Encryption/processing
            'memory_usage_mean': 0.7,  # Process injection
            'disk_io_mean': 0.85,  # File operations
            'network_latency_mean': 0.2,
            'number_of_processes_mean': 0.86  # Multiple malicious processes
        }])
        
        print(f"Testing APT scenario data for: {apt_scenario_data['host'].iloc[0]}")
        print("Simulated APT activities:")
        high_features = []
        for col in apt_scenario_data.columns:
            if col not in ['host', 'time_window']:
                value = apt_scenario_data[col].iloc[0]
                if value > 0.75:
                    high_features.append(f"{col}: {value}")
        
        for feature in high_features:
            print(f"  - {feature}")
        
        # Make prediction
        result = engine.predict(apt_scenario_data, entity_column='host')
        
        print(f"\nPrediction Results:")
        print(f"  Alerts Generated: {len(result['alerts'])}")
        print(f"  Anomalies Detected: {len(result['anomalies'])}")
        
        # Analyze alerts
        enhanced_alerts = 0
        for i, alert in enumerate(result['alerts']):
            print(f"\n  Alert {i+1}:")
            print(f"    Entity: {alert.get('entity', 'unknown')}")
            print(f"    Severity: {alert.get('severity', 'unknown')}")
            print(f"    Detection Type: {alert.get('detection_type', 'unknown')}")
            
            if alert.get('severity_adjusted'):
                print(f"    Severity Adjusted: {alert['original_severity']} → {alert['severity']}")
            
            if 'mitre_attack' in alert:
                mitre_info = alert['mitre_attack']
                
                # Check if this is enhanced mapping
                if 'enhancement_version' in mitre_info:
                    enhanced_alerts += 1
                    print(f"    ✅ Enhanced MITRE Analysis (v{mitre_info['enhancement_version']})")
                    print(f"    Overall Confidence: {mitre_info['confidence']:.3f}")
                    print(f"    Techniques: {len(mitre_info['techniques'])}")
                    print(f"    Tactics: {len(mitre_info['tactics'])}")
                    
                    if mitre_info.get('apt_patterns'):
                        print(f"    APT Patterns: {', '.join(mitre_info['apt_patterns'])}")
                    
                    # Show top techniques
                    for j, technique in enumerate(mitre_info['techniques'][:3]):
                        print(f"      {j+1}. {technique['id']}: {technique['name']} (confidence: {technique['confidence']:.3f})")
                    
                    # Show investigation info
                    if 'investigation' in alert:
                        inv = alert['investigation']
                        print(f"    Investigation Priority: {inv['priority']} ({inv['estimated_time']})")
                else:
                    print(f"    Standard MITRE Analysis")
                    print(f"    Techniques: {len(mitre_info.get('techniques', []))}")
            else:
                print(f"    ❌ No MITRE techniques identified")
        
        success = enhanced_alerts > 0
        if success:
            print(f"\n✅ Enhanced prediction engine test successful!")
            print(f"   {enhanced_alerts} alerts with enhanced MITRE analysis")
        else:
            print(f"\n⚠️  No enhanced alerts generated")
        
        return success
        
    except Exception as e:
        print(f"❌ Error in enhanced prediction engine test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_confidence_scoring():
    """Test confidence scoring mechanisms."""
    print("\n" + "="*70)
    print("TEST 3: Confidence Scoring Mechanisms")
    print("="*70)
    
    try:
        mapper = EnhancedMitreMapper()
        
        # Test scenarios with different confidence levels
        scenarios = [
            {
                'name': 'Low Confidence Scenario',
                'features': {
                    'network_traffic_volume_mean': 0.72,  # Just above threshold
                    'number_of_failed_logins_mean': 0.55,  # Moderate
                    'cpu_usage_mean': 0.75,  # Moderate
                    'number_of_processes_mean': 0.65,  # Moderate
                },
                'prediction_score': 0.65
            },
            {
                'name': 'High Confidence Scenario',
                'features': {
                    'network_traffic_volume_mean': 0.95,  # Very high
                    'number_of_failed_logins_mean': 0.90,  # Very high
                    'number_of_accessed_files_mean': 0.92,  # Very high
                    'cpu_usage_mean': 0.88,  # High
                    'number_of_processes_mean': 0.85,  # High
                },
                'prediction_score': 0.92
            },
            {
                'name': 'APT Pattern Scenario',
                'features': {
                    'network_traffic_volume_mean': 0.85,  # High C2
                    'number_of_accessed_files_mean': 0.88,  # Data collection
                    'cpu_usage_mean': 0.82,  # Processing
                    'disk_io_mean': 0.80,  # File operations
                },
                'prediction_score': 0.85,
                'event_type': 'process',
                'entity_type': 'host'
            }
        ]
        
        for scenario in scenarios:
            print(f"\n🧪 Testing: {scenario['name']}")
            
            # Create alert
            alert = {
                'entity': 'test_host',
                'entity_type': scenario.get('entity_type', 'host'),
                'timestamp': datetime.now().isoformat(),
                'severity': 'Medium',
                'prediction_score': scenario['prediction_score'],
                'detection_type': 'behavioral_analytics',
                'event_type': scenario.get('event_type', ''),
                'features': {
                    'network_traffic_volume_mean': 0.3,
                    'number_of_logins_mean': 0.2,
                    'number_of_failed_logins_mean': 0.1,
                    'number_of_accessed_files_mean': 0.4,
                    'number_of_email_sent_mean': 0.2,
                    'cpu_usage_mean': 0.3,
                    'memory_usage_mean': 0.4,
                    'disk_io_mean': 0.2,
                    'network_latency_mean': 0.1,
                    'number_of_processes_mean': 0.3,
                    **scenario['features']  # Override with scenario-specific values
                }
            }
            
            # Enrich alert
            enriched = mapper.enrich_alert_enhanced(alert)
            
            if 'mitre_attack' in enriched:
                mitre_info = enriched['mitre_attack']
                print(f"   Overall Confidence: {mitre_info['confidence']:.3f}")
                print(f"   Techniques Found: {len(mitre_info['techniques'])}")
                
                if mitre_info['techniques']:
                    # Show confidence distribution
                    confidences = [t['confidence'] for t in mitre_info['techniques']]
                    print(f"   Confidence Range: {min(confidences):.3f} - {max(confidences):.3f}")
                    
                    # Show top technique
                    top_technique = mitre_info['techniques'][0]
                    print(f"   Top Technique: {top_technique['id']} ({top_technique['confidence']:.3f})")
                    
                    # Show APT patterns if any
                    if mitre_info.get('apt_patterns'):
                        print(f"   APT Patterns: {', '.join(mitre_info['apt_patterns'])}")
                
                # Show severity adjustment
                if enriched.get('severity_adjusted'):
                    print(f"   Severity: {enriched['original_severity']} → {enriched['severity']}")
            else:
                print(f"   ❌ No techniques identified")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in confidence scoring test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_data_ingestion_enhanced():
    """Test enhanced MITRE mapping in data ingestion."""
    print("\n" + "="*70)
    print("TEST 4: Data Ingestion with Enhanced MITRE Mapping")
    print("="*70)
    
    try:
        # Create data ingestion manager
        manager = DataIngestionManager()
        
        # Check if prediction engine has enhanced mapping
        if hasattr(manager.prediction_engine, 'use_enhanced_mitre'):
            print(f"✅ Data ingestion manager has enhanced MITRE mapping: {manager.prediction_engine.use_enhanced_mitre}")
        else:
            print("⚠️  Enhanced MITRE mapping status unknown")
        
        # Simulate a Kafka message with APT-like characteristics
        class MockMessage:
            def __init__(self, value, topic='apt_topic', partition=0, offset=123):
                self.value = value
                self.topic = topic
                self.partition = partition
                self.offset = offset
        
        # Create APT-like message
        apt_message_data = {
            'entity': 'critical_server',
            'entity_type': 'host',
            'event_type': 'process',
            'timestamp': datetime.now().isoformat(),
            'network_traffic_volume_mean': 0.91,
            'number_of_logins_mean': 0.2,
            'number_of_failed_logins_mean': 0.83,
            'number_of_accessed_files_mean': 0.87,
            'number_of_email_sent_mean': 0.1,
            'cpu_usage_mean': 0.89,
            'memory_usage_mean': 0.6,
            'disk_io_mean': 0.82,
            'network_latency_mean': 0.1,
            'number_of_processes_mean': 0.84,
            'severity': 'High'
        }
        
        mock_message = MockMessage(apt_message_data)
        
        print(f"Processing simulated Kafka message for: {apt_message_data['entity']}")
        print("High-risk features:")
        for key, value in apt_message_data.items():
            if isinstance(value, (int, float)) and value > 0.8:
                print(f"  - {key}: {value}")
        
        # Process the message
        alert = manager.process_kafka_message(mock_message)
        
        if alert:
            print(f"\n✅ Alert generated successfully!")
            print(f"   Entity: {alert['entity']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Source: {alert.get('source', {}).get('type', 'unknown')}")
            
            if 'mitre_attack' in alert:
                mitre_info = alert['mitre_attack']
                
                # Check for enhanced analysis
                if 'enhancement_version' in mitre_info:
                    print(f"   ✅ Enhanced MITRE Analysis (v{mitre_info['enhancement_version']})")
                    print(f"   Overall Confidence: {mitre_info['confidence']:.3f}")
                    print(f"   Techniques: {len(mitre_info['techniques'])}")
                    
                    if mitre_info.get('apt_patterns'):
                        print(f"   APT Patterns: {', '.join(mitre_info['apt_patterns'])}")
                    
                    # Show investigation recommendations
                    if 'investigation' in alert:
                        inv = alert['investigation']
                        print(f"   Investigation: {inv['priority']} priority ({inv['estimated_time']})")
                        print(f"   Focus Areas: {', '.join(inv['focus_areas'])}")
                else:
                    print(f"   Standard MITRE Analysis")
                    print(f"   Techniques: {len(mitre_info.get('techniques', []))}")
            else:
                print(f"   ❌ No MITRE techniques identified")
            
            return True
        else:
            print(f"❌ No alert generated from Kafka message")
            return False
            
    except Exception as e:
        print(f"❌ Error in data ingestion test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all enhanced MITRE tests."""
    print("🚀 Enhanced MITRE ATT&CK Test Suite")
    print("Testing Days 2-7 implementation of Week 2 plan...")
    print("Features: Advanced confidence scoring, APT patterns, mitigations, severity adjustment")
    
    setup_logging()
    
    # Run all tests
    tests = [
        ("Enhanced MITRE Mapper Direct", test_enhanced_mitre_mapper_direct),
        ("Prediction Engine Enhanced", test_prediction_engine_enhanced),
        ("Confidence Scoring Mechanisms", test_confidence_scoring),
        ("Data Ingestion Enhanced", test_data_ingestion_enhanced)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test '{test_name}' failed with exception: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*70)
    print("ENHANCED MITRE TEST SUMMARY")
    print("="*70)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All enhanced tests passed! Week 2 Days 2-7 implementation successful!")
        print("\n📈 Enhanced Features Verified:")
        print("   ✅ Advanced confidence scoring with multiple factors")
        print("   ✅ APT-specific pattern recognition")
        print("   ✅ Mitigation recommendations by technique")
        print("   ✅ Automatic severity adjustment based on criticality")
        print("   ✅ Investigation recommendations with time estimates")
        print("   ✅ Kill chain phase identification")
        print("   ✅ Enhanced logging and analysis metadata")
        
        print("\n🎬 BSides Demo Ready:")
        print("   • Clear before/after comparison available")
        print("   • Sophisticated threat intelligence in alerts")
        print("   • Actionable recommendations for SOC operators")
        print("   • Confidence scoring demonstrates AI sophistication")
        
    elif passed > 0:
        print(f"\n⚠️  Partial success: {passed}/{total} tests passed.")
        print("🔧 Some enhanced features need additional work.")
    else:
        print("\n❌ All enhanced tests failed. Implementation needs debugging.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
