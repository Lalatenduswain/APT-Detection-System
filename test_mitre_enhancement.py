#!/usr/bin/env python3
"""
Test script to verify MITRE ATT&CK enhancement is working.

This script tests the enhanced alert generation to ensure all alerts
are properly enriched with MITRE ATT&CK technique information.
"""

import sys
import os
import logging
import json
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from real_time_detection.prediction_engine import PredictionEngine
from real_time_detection.mitre_attack_mapping import enrich_alert_with_mitre_attack, generate_alert
from real_time_detection.behavioral_analytics import BehavioralAnalytics

def setup_logging():
    """Set up logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def test_mitre_enrichment_direct():
    """Test MITRE enrichment function directly."""
    print("\n" + "="*60)
    print("TEST 1: Direct MITRE ATT&CK Enrichment")
    print("="*60)
    
    # Create a sample alert
    sample_alert = {
        'entity': 'test_host',
        'entity_type': 'host',
        'timestamp': datetime.now().isoformat(),
        'severity': 'High',
        'prediction_score': 0.85,
        'detection_type': 'behavioral_analytics',
        'event_type': 'process',
        'features': {
            'network_traffic_volume_mean': 0.9,  # High network traffic
            'number_of_logins_mean': 0.2,
            'number_of_failed_logins_mean': 0.8,  # High failed logins
            'number_of_accessed_files_mean': 0.9,  # High file access
            'number_of_email_sent_mean': 0.2,
            'cpu_usage_mean': 0.8,  # High CPU usage
            'memory_usage_mean': 0.4,
            'disk_io_mean': 0.2,
            'network_latency_mean': 0.1,
            'number_of_processes_mean': 0.7  # High process count
        }
    }
    
    print(f"Original alert: {sample_alert['entity']} - {sample_alert['severity']}")
    print(f"Features with high values:")
    for feature, value in sample_alert['features'].items():
        if value > 0.7:
            print(f"  - {feature}: {value}")
    
    # Enrich with MITRE ATT&CK
    enriched_alert = enrich_alert_with_mitre_attack(sample_alert)
    
    # Check results
    if 'mitre_attack' in enriched_alert:
        techniques = enriched_alert['mitre_attack']['techniques']
        tactics = enriched_alert['mitre_attack']['tactics']
        
        print(f"\n✅ MITRE ATT&CK enrichment successful!")
        print(f"Techniques identified: {len(techniques)}")
        print(f"Tactics identified: {len(tactics)}")
        
        if techniques:
            print("\nTop techniques:")
            for i, technique in enumerate(techniques[:5]):
                print(f"  {i+1}. {technique['id']}: {technique['name']}")
        
        if tactics:
            print("\nTactics involved:")
            for tactic in tactics:
                print(f"  - {tactic['id']}: {tactic['name']} ({len(tactic['techniques'])} techniques)")
        
        if 'confidence' in enriched_alert['mitre_attack']:
            print(f"\nConfidence score: {enriched_alert['mitre_attack']['confidence']}")
        
        return True
    else:
        print("❌ No MITRE ATT&CK information found in enriched alert")
        return False

def test_prediction_engine_integration():
    """Test MITRE enrichment through the prediction engine."""
    print("\n" + "="*60)
    print("TEST 2: Prediction Engine Integration")
    print("="*60)
    
    try:
        # Create prediction engine
        engine = PredictionEngine(use_saved_models=True)
        
        # Create test data with anomalous features
        import pandas as pd
        import numpy as np
        
        test_data = pd.DataFrame([{
            'host': 'test_host_2',
            'time_window': datetime.now(),
            'network_traffic_volume_mean': 0.95,  # Very high
            'number_of_logins_mean': 0.2,
            'number_of_failed_logins_mean': 0.9,   # Very high
            'number_of_accessed_files_mean': 0.85, # High
            'number_of_email_sent_mean': 0.1,
            'cpu_usage_mean': 0.9,                 # Very high
            'memory_usage_mean': 0.4,
            'disk_io_mean': 0.2,
            'network_latency_mean': 0.1,
            'number_of_processes_mean': 0.8        # High
        }])
        
        print(f"Test data created for: {test_data['host'].iloc[0]}")
        print("High anomaly features:")
        for col in test_data.columns:
            if col not in ['host', 'time_window']:
                value = test_data[col].iloc[0]
                if value > 0.7:
                    print(f"  - {col}: {value}")
        
        # Make prediction
        result = engine.predict(test_data, entity_column='host')
        
        print(f"\nPrediction results:")
        print(f"  Alerts generated: {len(result['alerts'])}")
        print(f"  Anomalies detected: {len(result['anomalies'])}")
        
        # Check alerts for MITRE enrichment
        mitre_enriched_count = 0
        for i, alert in enumerate(result['alerts']):
            print(f"\n  Alert {i+1}:")
            print(f"    Entity: {alert.get('entity', 'unknown')}")
            print(f"    Severity: {alert.get('severity', 'unknown')}")
            print(f"    Detection type: {alert.get('detection_type', 'unknown')}")
            
            if 'mitre_attack' in alert and alert['mitre_attack'].get('techniques', []):
                mitre_enriched_count += 1
                techniques = alert['mitre_attack']['techniques']
                print(f"    ✅ MITRE techniques: {len(techniques)}")
                for j, technique in enumerate(techniques[:3]):
                    print(f"      {j+1}. {technique['id']}: {technique['name']}")
            else:
                print(f"    ❌ No MITRE techniques identified")
        
        # Check anomalies for MITRE enrichment
        for i, anomaly in enumerate(result['anomalies']):
            print(f"\n  Anomaly {i+1}:")
            print(f"    Entity: {anomaly.get('entity', 'unknown')}")
            print(f"    Severity: {anomaly.get('severity', 'unknown')}")
            print(f"    Anomaly score: {anomaly.get('anomaly_score', 0):.2f}")
        
        success = mitre_enriched_count > 0 or len(result['anomalies']) > 0
        if success:
            print(f"\n✅ Prediction engine integration successful!")
            print(f"   {mitre_enriched_count} alerts with MITRE enrichment")
        else:
            print(f"\n❌ No alerts or anomalies generated")
        
        return success
        
    except Exception as e:
        print(f"❌ Error in prediction engine test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_behavioral_analytics_integration():
    """Test MITRE enrichment through behavioral analytics."""
    print("\n" + "="*60)
    print("TEST 3: Behavioral Analytics Integration")
    print("="*60)
    
    try:
        # Create behavioral analytics module
        analytics = BehavioralAnalytics()
        
        # Load or create baseline models
        try:
            analytics.load_baseline_models()
            print("✅ Loaded existing baseline models")
        except:
            print("📝 Creating new baseline models...")
            # Create synthetic historical data
            import pandas as pd
            import numpy as np
            
            historical_data = []
            for i in range(100):  # 100 data points
                historical_data.append({
                    'time_window': datetime.now(),
                    'host': 'test_host_3',
                    'network_traffic_volume_mean': np.random.normal(0.3, 0.1),
                    'number_of_logins_mean': np.random.normal(0.2, 0.05),
                    'number_of_failed_logins_mean': np.random.normal(0.1, 0.05),
                    'number_of_accessed_files_mean': np.random.normal(0.4, 0.1),
                    'number_of_email_sent_mean': np.random.normal(0.2, 0.05),
                    'cpu_usage_mean': np.random.normal(0.3, 0.1),
                    'memory_usage_mean': np.random.normal(0.4, 0.1),
                    'disk_io_mean': np.random.normal(0.2, 0.05),
                    'network_latency_mean': np.random.normal(0.1, 0.05),
                    'number_of_processes_mean': np.random.normal(0.3, 0.1),
                    'data_source': 'test'
                })
            
            df_historical = pd.DataFrame(historical_data)
            analytics.establish_baseline(df_historical, entity_column='host')
            print("✅ Baseline models created")
        
        # Create anomalous test data
        anomalous_data = pd.DataFrame([{
            'time_window': datetime.now(),
            'host': 'test_host_3',
            'network_traffic_volume_mean': 0.95,  # Very high
            'number_of_logins_mean': 0.2,
            'number_of_failed_logins_mean': 0.9,   # Very high
            'number_of_accessed_files_mean': 0.85, # High
            'number_of_email_sent_mean': 0.1,
            'cpu_usage_mean': 0.9,                 # Very high
            'memory_usage_mean': 0.4,
            'disk_io_mean': 0.2,
            'network_latency_mean': 0.1,
            'number_of_processes_mean': 0.8,       # High
            'data_source': 'test'
        }])
        
        print(f"\nTesting anomaly detection for: {anomalous_data['host'].iloc[0]}")
        
        # Detect anomalies
        result_data, anomaly_alerts = analytics.detect_anomalies(anomalous_data, entity_column='host')
        
        print(f"Anomalies detected: {len(anomaly_alerts)}")
        
        # Test MITRE enrichment on anomaly alerts
        enriched_count = 0
        for i, anomaly in enumerate(anomaly_alerts):
            print(f"\n  Anomaly {i+1}:")
            print(f"    Entity: {anomaly.get('entity', 'unknown')}")
            print(f"    Severity: {anomaly.get('severity', 'unknown')}")
            print(f"    Anomaly score: {anomaly.get('anomaly_score', 0):.2f}")
            
            # Create alert from anomaly and enrich
            alert = {
                'entity': anomaly['entity'],
                'entity_type': anomaly.get('entity_type', 'host'),
                'timestamp': anomaly['timestamp'],
                'severity': anomaly['severity'],
                'anomaly_score': anomaly['anomaly_score'],
                'features': anomaly['features'],
                'prediction_score': anomaly['anomaly_score'],
                'detection_type': 'behavioral_analytics',
                'event_type': anomaly.get('event_type', '')
            }
            
            # Enrich with MITRE ATT&CK
            enriched_alert = enrich_alert_with_mitre_attack(alert)
            
            if 'mitre_attack' in enriched_alert and enriched_alert['mitre_attack'].get('techniques', []):
                enriched_count += 1
                techniques = enriched_alert['mitre_attack']['techniques']
                print(f"    ✅ MITRE techniques: {len(techniques)}")
                for j, technique in enumerate(techniques[:3]):
                    print(f"      {j+1}. {technique['id']}: {technique['name']}")
            else:
                print(f"    ❌ No MITRE techniques identified")
        
        success = enriched_count > 0
        if success:
            print(f"\n✅ Behavioral analytics integration successful!")
            print(f"   {enriched_count} anomalies with MITRE enrichment")
        else:
            print(f"\n❌ No anomalies with MITRE enrichment")
        
        return success
        
    except Exception as e:
        print(f"❌ Error in behavioral analytics test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_generate_alert_function():
    """Test the generate_alert function from MITRE mapping module."""
    print("\n" + "="*60)
    print("TEST 4: Generate Alert Function")
    print("="*60)
    
    try:
        # Create sample prediction results
        predictions = {
            'lgbm_model': [0.85],  # High prediction score
            'bilstm_model': [0.78]
        }
        
        # Create sample features
        features = {
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
        
        print("Testing generate_alert function...")
        print(f"Prediction scores: LightGBM={predictions['lgbm_model'][0]}, Bi-LSTM={predictions['bilstm_model'][0]}")
        print("High anomaly features:")
        for feature, value in features.items():
            if value > 0.7:
                print(f"  - {feature}: {value}")
        
        # Generate alert
        alert = generate_alert(predictions, features, threshold=0.7)
        
        if alert:
            print(f"\n✅ Alert generated successfully!")
            print(f"   Prediction score: {alert.get('prediction_score', 0):.2f}")
            print(f"   Severity: {alert.get('severity', 'unknown')}")
            
            if 'mitre_attack' in alert and alert['mitre_attack'].get('techniques', []):
                techniques = alert['mitre_attack']['techniques']
                print(f"   ✅ MITRE techniques: {len(techniques)}")
                for i, technique in enumerate(techniques[:3]):
                    print(f"     {i+1}. {technique['id']}: {technique['name']}")
                
                if 'confidence' in alert['mitre_attack']:
                    print(f"   Confidence: {alert['mitre_attack']['confidence']}")
                
                return True
            else:
                print(f"   ❌ No MITRE techniques in generated alert")
                return False
        else:
            print(f"❌ No alert generated (prediction score may be below threshold)")
            return False
            
    except Exception as e:
        print(f"❌ Error in generate_alert test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("🚀 MITRE ATT&CK Enhancement Test Suite")
    print("Testing Day 1 implementation of Week 2 plan...")
    
    setup_logging()
    
    # Run all tests
    tests = [
        ("Direct MITRE Enrichment", test_mitre_enrichment_direct),
        ("Prediction Engine Integration", test_prediction_engine_integration),
        ("Behavioral Analytics Integration", test_behavioral_analytics_integration),
        ("Generate Alert Function", test_generate_alert_function)
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
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! MITRE ATT&CK enhancement is working correctly.")
        print("✅ Day 1 of Week 2 implementation successful!")
    elif passed > 0:
        print(f"\n⚠️  Partial success: {passed}/{total} tests passed.")
        print("🔧 Some components need additional work.")
    else:
        print("\n❌ All tests failed. MITRE ATT&CK enhancement needs debugging.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
