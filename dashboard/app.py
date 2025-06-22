import os
import sys
import yaml
import logging
import json
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from visualization import create_entity_behavior_plot, create_alert_timeline_plot, create_severity_distribution_plot, create_source_distribution_plot, create_entity_feature_plot
from real_time_detection.data_ingestion import get_alerts, DataIngestionManager
from real_time_detection.prediction_engine import PredictionEngine
from models.metrics import EnhancedMetrics

app = Flask(__name__)
app.config['SECRET_KEY'] = 'apt-detection-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize managers
data_ingestion_manager = None
prediction_engine = None
enhanced_metrics = None

# Global variables for real-time streaming
alert_stream_active = False
alert_stream_thread = None

# Make visualization functions available in templates
app.jinja_env.globals.update(
    create_entity_feature_plot=create_entity_feature_plot,
    create_entity_behavior_plot=create_entity_behavior_plot,
    create_alert_timeline_plot=create_alert_timeline_plot,
    create_severity_distribution_plot=create_severity_distribution_plot,
    create_source_distribution_plot=create_source_distribution_plot
)

def initialize_managers():
    """Initialize data ingestion manager, prediction engine, and enhanced metrics."""
    global data_ingestion_manager, prediction_engine, enhanced_metrics
    
    if data_ingestion_manager is None:
        data_ingestion_manager = DataIngestionManager()
    
    if prediction_engine is None:
        prediction_engine = PredictionEngine()
    
    if enhanced_metrics is None:
        enhanced_metrics = EnhancedMetrics()

def load_config():
    """Load configuration from config.yaml file."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

@app.route('/')
def index():
    """Display the main dashboard page."""
    # Get alert statistics
    all_alerts = get_alerts()
    
    # Log the number of alerts for debugging
    logging.info(f"Dashboard index: Retrieved {len(all_alerts)} alerts")
    
    # Count alerts by severity
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    # Count alerts by source
    source_counts = {}
    
    # Count alerts by entity
    entity_counts = {}
    
    # Get recent alerts
    recent_alerts = []
    
    for alert in all_alerts:
        # Count by severity
        severity = alert.get('severity', 'Unknown')
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Count by source
        source_type = alert.get('source', {}).get('type', 'Unknown')
        source_counts[source_type] = source_counts.get(source_type, 0) + 1
        
        # Count by entity
        entity = alert.get('entity', 'Unknown')
        entity_counts[entity] = entity_counts.get(entity, 0) + 1
        
        # Add to recent alerts (last 5)
        if len(recent_alerts) < 5:
            recent_alerts.append(alert)
    
    # Create plots
    alert_timeline_plot = create_alert_timeline_plot(all_alerts)
    entity_plot = create_entity_behavior_plot(entity_counts)
    severity_plot = create_severity_distribution_plot(severity_counts)
    source_plot = create_source_distribution_plot(source_counts)
    
    # Log counts for debugging
    logging.info(f"Dashboard stats: {len(all_alerts)} alerts, {len(recent_alerts)} recent, {sum(severity_counts.values())} by severity")
    
    return render_template(
        'index.html',
        alert_count=len(all_alerts),
        severity_counts=severity_counts,
        source_counts=source_counts,
        entity_counts=entity_counts,
        recent_alerts=recent_alerts,
        alert_timeline_plot=alert_timeline_plot,
        entity_plot=entity_plot,
        severity_plot=severity_plot,
        source_plot=source_plot
    )

@app.route('/alerts')
def alerts():
    """Display alerts with MITRE ATT&CK TTPs."""
    # Get filter parameters
    severity = request.args.get('severity', '')
    source_type = request.args.get('source_type', '')
    entity = request.args.get('entity', '')
    days = int(request.args.get('days', 7))
    
    # Get all alerts
    all_alerts = get_alerts()
    
    # Filter alerts
    filtered_alerts = []
    cutoff_date = datetime.now() - timedelta(days=days)
    
    for alert in all_alerts:
        # Check timestamp
        timestamp = alert.get('timestamp')
        if timestamp:
            try:
                alert_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if alert_date < cutoff_date:
                    continue
            except (ValueError, TypeError):
                pass
        
        # Check severity
        if severity and alert.get('severity') != severity:
            continue
        
        # Check source type
        if source_type and alert.get('source', {}).get('type') != source_type:
            continue
        
        # Check entity
        if entity and alert.get('entity') != entity:
            continue
        
        filtered_alerts.append(alert)
    
    # Get unique values for filters
    severities = sorted(set(alert.get('severity', 'Unknown') for alert in all_alerts))
    source_types = sorted(set(alert.get('source', {}).get('type', 'Unknown') for alert in all_alerts))
    entities = sorted(set(alert.get('entity', 'Unknown') for alert in all_alerts))
    
    return render_template(
        'alerts.html',
        alerts=filtered_alerts,
        severities=severities,
        source_types=source_types,
        entities=entities,
        selected_severity=severity,
        selected_source_type=source_type,
        selected_entity=entity,
        selected_days=days
    )

@app.route('/metrics')
def metrics_dashboard():
    """Display enhanced metrics dashboard."""
    # Initialize managers if needed
    initialize_managers()
    
    # Get all alerts
    all_alerts = get_alerts()
    
    # Calculate enhanced metrics if we have alerts
    enhanced_metrics_data = None
    if all_alerts and enhanced_metrics:
        try:
            # Create some baseline alerts for comparison (simulate Week 1 style)
            baseline_alerts = []
            for alert in all_alerts[:5]:  # Use first 5 as baseline simulation
                baseline_alert = {
                    'entity': alert.get('entity'),
                    'timestamp': alert.get('timestamp'),
                    'severity': alert.get('severity', 'Medium'),
                    'prediction_score': alert.get('prediction_score', 0.5),
                    'detection_type': alert.get('detection_type', 'behavioral_analytics'),
                    'mitre_attack': {
                        'techniques': [],  # No techniques in baseline
                        'tactics': []
                    }
                }
                baseline_alerts.append(baseline_alert)
            
            # Calculate comprehensive metrics
            enhanced_metrics_data = enhanced_metrics.calculate_comprehensive_metrics(
                all_alerts, baseline_alerts
            )
        except Exception as e:
            logging.error(f"Error calculating enhanced metrics: {str(e)}")
            enhanced_metrics_data = None
    
    return render_template(
        'metrics.html',
        metrics_data=enhanced_metrics_data,
        alert_count=len(all_alerts)
    )

@app.route('/api/enhanced_metrics')
def api_enhanced_metrics():
    """API endpoint for enhanced metrics data."""
    # Initialize managers if needed
    initialize_managers()
    
    # Get all alerts
    all_alerts = get_alerts()
    
    if not all_alerts or not enhanced_metrics:
        return jsonify({
            'error': 'No alerts available or metrics system not initialized',
            'alert_count': len(all_alerts)
        })
    
    try:
        # Create baseline alerts for comparison
        baseline_alerts = []
        for alert in all_alerts[:min(5, len(all_alerts))]:
            baseline_alert = {
                'entity': alert.get('entity'),
                'timestamp': alert.get('timestamp'),
                'severity': alert.get('severity', 'Medium'),
                'prediction_score': alert.get('prediction_score', 0.5),
                'detection_type': alert.get('detection_type', 'behavioral_analytics'),
                'mitre_attack': {
                    'techniques': [],
                    'tactics': []
                }
            }
            baseline_alerts.append(baseline_alert)
        
        # Calculate comprehensive metrics
        metrics_data = enhanced_metrics.calculate_comprehensive_metrics(
            all_alerts, baseline_alerts
        )
        
        return jsonify(metrics_data)
        
    except Exception as e:
        logging.error(f"Error calculating enhanced metrics: {str(e)}")
        return jsonify({
            'error': f'Error calculating metrics: {str(e)}',
            'alert_count': len(all_alerts)
        }), 500

@app.route('/api/mitre_metrics')
def api_mitre_metrics():
    """API endpoint for MITRE ATT&CK specific metrics."""
    # Initialize managers if needed
    initialize_managers()
    
    # Get all alerts
    all_alerts = get_alerts()
    
    if not all_alerts or not enhanced_metrics:
        return jsonify({
            'error': 'No alerts available or metrics system not initialized'
        })
    
    try:
        # Calculate MITRE-specific metrics
        mitre_results = enhanced_metrics.mitre_metrics.calculate_mitre_effectiveness(all_alerts)
        return jsonify(mitre_results)
        
    except Exception as e:
        logging.error(f"Error calculating MITRE metrics: {str(e)}")
        return jsonify({
            'error': f'Error calculating MITRE metrics: {str(e)}'
        }), 500

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts data."""
    # Get filter parameters
    severity = request.args.get('severity', '')
    source_type = request.args.get('source_type', '')
    entity = request.args.get('entity', '')
    days = int(request.args.get('days', 7))
    
    # Get all alerts
    all_alerts = get_alerts()
    
    # Filter alerts
    filtered_alerts = []
    cutoff_date = datetime.now() - timedelta(days=days)
    
    for alert in all_alerts:
        # Check timestamp
        timestamp = alert.get('timestamp')
        if timestamp:
            try:
                alert_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if alert_date < cutoff_date:
                    continue
            except (ValueError, TypeError):
                pass
        
        # Check severity
        if severity and alert.get('severity') != severity:
            continue
        
        # Check source type
        if source_type and alert.get('source', {}).get('type') != source_type:
            continue
        
        # Check entity
        if entity and alert.get('entity') != entity:
            continue
        
        filtered_alerts.append(alert)
    
    return jsonify(filtered_alerts)

@app.route('/entity/<entity>')
def entity_analysis(entity):
    """Display entity behavior analysis."""
    # Initialize managers if needed
    initialize_managers()
    
    # Get entity behavior analysis
    behavior = prediction_engine.analyze_entity(entity)
    
    # Get alerts for this entity
    all_alerts = get_alerts()
    entity_alerts = [alert for alert in all_alerts if alert.get('entity') == entity]
    
    # Create plots for entity
    timeline_plot = create_alert_timeline_plot(entity_alerts)
    feature_plot = create_entity_feature_plot(behavior)
    
    return render_template(
        'entity.html',
        entity=entity,
        behavior=behavior,
        alerts=entity_alerts,
        timeline_plot=timeline_plot,
        feature_plot=feature_plot
    )

@app.route('/api/entity/<entity>')
def api_entity_analysis(entity):
    """API endpoint for entity behavior analysis."""
    # Initialize managers if needed
    initialize_managers()
    
    # Get entity behavior analysis
    behavior = prediction_engine.analyze_entity(entity)
    
    return jsonify(behavior)

@app.route('/models')
def models():
    """Display information about saved models."""
    config = load_config()
    
    # Get base directory for models
    base_dir = config['model_paths']['base_dir']
    
    # Construct full paths to model files
    lgbm_path = os.path.join(base_dir, config['model_paths']['lightgbm'])
    bilstm_path = os.path.join(base_dir, config['model_paths']['bilstm'])
    
    # Check for baseline models
    baseline_dir = os.path.join(base_dir, 'baselines')
    baseline_models = []
    
    if os.path.exists(baseline_dir):
        for file in os.listdir(baseline_dir):
            if file.endswith('_model.pkl'):
                entity = file.replace('_model.pkl', '')
                model_path = os.path.join(baseline_dir, file)
                scaler_path = os.path.join(baseline_dir, f"{entity}_scaler.pkl")
                
                baseline_models.append({
                    'entity': entity,
                    'model_exists': os.path.exists(model_path),
                    'scaler_exists': os.path.exists(scaler_path),
                    'model_size': f"{os.path.getsize(model_path) / 1024:.2f} KB" if os.path.exists(model_path) else "N/A"
                })
    
    model_info = {
        'lightgbm': {
            'exists': os.path.exists(lgbm_path),
            'path': lgbm_path,
            'size': f"{os.path.getsize(lgbm_path) / 1024:.2f} KB" if os.path.exists(lgbm_path) else "N/A"
        },
        'bilstm': {
            'exists': os.path.exists(bilstm_path),
            'path': bilstm_path,
            'size': f"{os.path.getsize(bilstm_path) / 1024:.2f} KB" if os.path.exists(bilstm_path) else "N/A"
        }
    }
    
    return render_template(
        'models.html',
        model_info=model_info,
        baseline_models=baseline_models
    )

@app.route('/connectors')
def connectors():
    """Display information about data source connectors."""
    config = load_config()
    
    # Get connector configuration
    data_sources = config.get('data_sources', {})
    
    # Format connector information
    connector_info = []
    
    # Wazuh connector
    if 'wazuh' in data_sources:
        wazuh_config = data_sources['wazuh']
        connector_info.append({
            'name': 'Wazuh EDR',
            'type': 'EDR',
            'enabled': wazuh_config.get('enabled', False),
            'api_url': wazuh_config.get('api_url', ''),
            'fetch_interval': wazuh_config.get('fetch_interval', 60)
        })
    
    # Elasticsearch connector
    if 'elasticsearch' in data_sources:
        es_config = data_sources['elasticsearch']
        connector_info.append({
            'name': 'Elasticsearch SIEM',
            'type': 'SIEM',
            'enabled': es_config.get('enabled', False),
            'hosts': es_config.get('hosts', []),
            'index_pattern': es_config.get('index_pattern', ''),
            'fetch_interval': es_config.get('fetch_interval', 60)
        })
    
    # Kafka connector
    if 'kafka' in config:
        kafka_config = config['kafka']
        connector_info.append({
            'name': 'Kafka',
            'type': 'Message Queue',
            'enabled': True,  # Kafka is always enabled
            'bootstrap_servers': kafka_config.get('bootstrap_servers', ''),
            'topic': kafka_config.get('topic', '')
        })
    
    return render_template(
        'connectors.html',
        connector_info=connector_info
    )

@app.route('/timeline')
def timeline():
    """Display attack timeline visualization."""
    return render_template('timeline.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Display and update settings."""
    if request.method == 'POST':
        # TODO: Implement settings update
        return redirect(url_for('settings'))
    
    config = load_config()
    
    return render_template(
        'settings.html',
        settings=config.get('settings', {}),
        model_paths=config.get('model_paths', {})
    )

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics."""
    # Get all alerts
    all_alerts = get_alerts()
    
    # Count alerts by severity
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    # Count alerts by source
    source_counts = {}
    
    # Count alerts by entity
    entity_counts = {}
    
    # Count alerts by day
    day_counts = {}
    
    for alert in all_alerts:
        # Count by severity
        severity = alert.get('severity', 'Unknown')
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Count by source
        source_type = alert.get('source', {}).get('type', 'Unknown')
        source_counts[source_type] = source_counts.get(source_type, 0) + 1
        
        # Count by entity
        entity = alert.get('entity', 'Unknown')
        entity_counts[entity] = entity_counts.get(entity, 0) + 1
        
        # Count by day
        timestamp = alert.get('timestamp')
        if timestamp:
            try:
                date = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).date().isoformat()
                day_counts[date] = day_counts.get(date, 0) + 1
            except (ValueError, TypeError):
                pass
    
    # Format day counts for timeline
    timeline_data = [{'date': date, 'count': count} for date, count in day_counts.items()]
    timeline_data.sort(key=lambda x: x['date'])
    
    return jsonify({
        'alert_count': len(all_alerts),
        'severity_counts': severity_counts,
        'source_counts': source_counts,
        'entity_counts': entity_counts,
        'timeline_data': timeline_data
    })

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logging.info('Client connected to WebSocket')
    emit('status', {'message': 'Connected to APT Detection System'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logging.info('Client disconnected from WebSocket')

@socketio.on('start_alert_stream')
def handle_start_alert_stream():
    """Start real-time alert streaming."""
    global alert_stream_active, alert_stream_thread
    
    if not alert_stream_active:
        alert_stream_active = True
        alert_stream_thread = threading.Thread(target=alert_stream_worker)
        alert_stream_thread.daemon = True
        alert_stream_thread.start()
        emit('stream_status', {'active': True, 'message': 'Alert stream started'})
        logging.info('Alert stream started')
    else:
        emit('stream_status', {'active': True, 'message': 'Alert stream already active'})

@socketio.on('stop_alert_stream')
def handle_stop_alert_stream():
    """Stop real-time alert streaming."""
    global alert_stream_active
    
    alert_stream_active = False
    emit('stream_status', {'active': False, 'message': 'Alert stream stopped'})
    logging.info('Alert stream stopped')

def alert_stream_worker():
    """Worker function for streaming alerts in real-time."""
    global alert_stream_active
    
    last_alert_count = 0
    
    while alert_stream_active:
        try:
            # Get current alerts
            all_alerts = get_alerts()
            current_count = len(all_alerts)
            
            # Check if we have new alerts
            if current_count > last_alert_count:
                # Get the new alerts
                new_alerts = all_alerts[last_alert_count:]
                
                for alert in new_alerts:
                    # Format alert for streaming
                    stream_alert = {
                        'id': alert.get('id', f"alert_{int(time.time())}"),
                        'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                        'entity': alert.get('entity', 'Unknown'),
                        'severity': alert.get('severity', 'Medium'),
                        'prediction_score': alert.get('prediction_score', 0.5),
                        'detection_type': alert.get('detection_type', 'behavioral_analytics'),
                        'mitre_techniques': [t.get('technique_id', '') for t in alert.get('mitre_attack', {}).get('techniques', [])],
                        'description': alert.get('description', 'Anomalous behavior detected')
                    }
                    
                    # Emit new alert to all connected clients
                    socketio.emit('new_alert', stream_alert)
                
                last_alert_count = current_count
            
            # Update dashboard statistics
            stats = {
                'total_alerts': current_count,
                'timestamp': datetime.now().isoformat()
            }
            socketio.emit('stats_update', stats)
            
            # Sleep for a short interval
            time.sleep(2)
            
        except Exception as e:
            logging.error(f"Error in alert stream worker: {str(e)}")
            time.sleep(5)

@app.route('/api/stream/start')
def api_start_stream():
    """API endpoint to start alert streaming."""
    global alert_stream_active, alert_stream_thread
    
    if not alert_stream_active:
        alert_stream_active = True
        alert_stream_thread = threading.Thread(target=alert_stream_worker)
        alert_stream_thread.daemon = True
        alert_stream_thread.start()
        return jsonify({'status': 'started', 'message': 'Alert stream started'})
    else:
        return jsonify({'status': 'already_active', 'message': 'Alert stream already active'})

@app.route('/api/stream/stop')
def api_stop_stream():
    """API endpoint to stop alert streaming."""
    global alert_stream_active
    
    alert_stream_active = False
    return jsonify({'status': 'stopped', 'message': 'Alert stream stopped'})

@app.route('/api/stream/status')
def api_stream_status():
    """API endpoint to get stream status."""
    return jsonify({'active': alert_stream_active})

def run(host=None, port=None, debug=None):
    """Run the Flask application with configurable parameters."""
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Flask app with SocketIO...")
    
    # Initialize managers
    initialize_managers()
    
    # If parameters not provided, load from config
    if host is None or port is None or debug is None:
        config = load_config()
        host = host or config['dashboard']['host']
        port = port or config['dashboard']['port']
        debug = debug if debug is not None else config['dashboard']['debug']
    
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)

if __name__ == '__main__':
    run()
