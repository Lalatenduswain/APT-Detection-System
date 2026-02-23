# APT Detection System — Complete Project Explanation

---

## 1. FOUNDATION: What problem does it solve and who is it for?

**Problem:** Advanced Persistent Threats (APTs) are sophisticated, long-term cyberattacks that evade traditional security tools (firewalls, signature-based IDS). They move slowly through kill chain stages — initial access, lateral movement, data exfiltration — making them extremely hard to catch with rule-based systems.

**Solution:** This system uses **hybrid machine learning** + **behavioral analytics** + **MITRE ATT&CK threat intelligence** to detect APTs in real time by analyzing patterns that no single detection method would catch alone.

**Who it's for:**
- SOC (Security Operations Center) analysts monitoring enterprise networks
- Security engineers integrating detection with Wazuh EDR / Elasticsearch SIEM
- Researchers studying APT detection with ML approaches

**Tech Stack:**

| Layer | Technology | Why |
|-------|-----------|-----|
| ML Models | LightGBM + Bi-LSTM (TensorFlow/Keras) | Tree-based + sequence-based = complementary strengths |
| Behavioral Analytics | Isolation Forest (scikit-learn) | Unsupervised anomaly detection per entity |
| Feature Selection | HHOSSSA (custom metaheuristic) | Novel hybrid optimization for feature reduction |
| Data Balancing | SMOTE (imbalanced-learn) | APT samples are rare; synthetic oversampling |
| Data Ingestion | Kafka + custom connectors | Real-time streaming + direct EDR/SIEM pulls |
| Storage | Redis (primary) + in-memory (fallback) | Fast, persistent, shared across processes |
| Dashboard | Flask + Flask-SocketIO | Lightweight Python web framework with WebSocket |
| Frontend | Bootstrap 5 + Chart.js/Plotly | Responsive UI with interactive visualizations |
| Config | YAML | Human-readable, easy to modify |

---

## 2. DATA FLOW: How does data enter, move through, and exit?

```
┌─────────────────── DATA SOURCES ───────────────────┐
│  Wazuh EDR    Elasticsearch SIEM    Kafka Streams  │
└──────────┬──────────────┬──────────────┬───────────┘
           │              │              │
           ▼              ▼              ▼
┌─────────────────── INGESTION LAYER ────────────────┐
│  ConnectorManager          KafkaConsumer            │
│  - Auth (API key/Basic)    - Topic: apt_topic       │
│  - Polling (60s interval)  - Consumer group          │
│  - Feature normalization   - JSON deserialization    │
└──────────────────────┬─────────────────────────────┘
                       │
                       ▼  (normalized 10-feature vectors)
┌─────────────────── DETECTION LAYER ────────────────┐
│                                                     │
│  ┌─── ML Pipeline ───┐  ┌─ Behavioral Pipeline ─┐  │
│  │ LightGBM predict   │  │ Isolation Forest      │  │
│  │ Bi-LSTM predict    │  │ Per-entity baselines  │  │
│  │ Average ensemble   │  │ Anomaly scoring       │  │
│  │ → prediction_score │  │ → anomaly_score       │  │
│  └────────────────────┘  └───────────────────────┘  │
│                                                     │
└──────────────────────┬─────────────────────────────┘
                       │
                       ▼  (if score ≥ threshold)
┌─────────────────── ENRICHMENT LAYER ───────────────┐
│  MITRE ATT&CK Mapping                              │
│  - Feature → Technique mapping (22 techniques)     │
│  - Confidence scoring (0.1–0.95)                   │
│  - Kill chain phase identification                  │
│  - Investigation recommendations                    │
│  - Severity adjustment                              │
└──────────────────────┬─────────────────────────────┘
                       │
                       ▼
┌─────────────────── STORAGE LAYER ──────────────────┐
│  Redis (primary)  →  In-Memory List (fallback)     │
│  Key: apt_detection:alerts                          │
│  Max: 1000 alerts (FIFO trimming)                  │
└──────────────────────┬─────────────────────────────┘
                       │
                       ▼
┌─────────────────── PRESENTATION LAYER ─────────────┐
│  Flask Dashboard (port 5000)                        │
│  - REST APIs: /api/alerts, /api/stats, etc.        │
│  - WebSocket: real-time alert streaming (2s poll)  │
│  - 8 pages: overview, alerts, metrics, timeline... │
└────────────────────────────────────────────────────┘
```

**The 10 features that flow through the system:**

1. `network_traffic_volume_mean`
2. `number_of_logins_mean`
3. `number_of_failed_logins_mean`
4. `number_of_accessed_files_mean`
5. `number_of_email_sent_mean`
6. `cpu_usage_mean`
7. `memory_usage_mean`
8. `disk_io_mean`
9. `network_latency_mean`
10. `number_of_processes_mean`

All computed as 10-minute rolling window aggregations.

---

## 3. CORE LOGIC: What are the key modules and algorithms?

### Module Map

| Module | File(s) | Purpose |
|--------|---------|---------|
| **Entry Point** | `main.py` | CLI argument parsing, thread orchestration |
| **Hybrid Classifier** | `models/hybrid_classifier.py` | Ensemble: `(LightGBM_proba + BiLSTM_pred) / 2` |
| **LightGBM** | `models/lightgbm_model.py` | Gradient-boosted tree classifier |
| **Bi-LSTM** | `models/bilstm_model.py` | Bidirectional LSTM neural network |
| **Training** | `models/train_models.py` | Orchestrates full training pipeline |
| **Feature Selection** | `feature_selection/hhosssa_feature_selection.py` | HHOSSSA metaheuristic (Harmony Search + Owl Search + Salp Swarm) |
| **Data Balancing** | `data_balancing/hhosssa_smote.py` | SMOTE synthetic oversampling |
| **Preprocessing** | `data_preprocessing/` | Load CSV, clean (ffill/bfill), rolling window features |
| **Prediction Engine** | `real_time_detection/prediction_engine.py` | Core detection loop |
| **Behavioral Analytics** | `real_time_detection/behavioral_analytics.py` | Isolation Forest per-entity baselines |
| **Data Ingestion** | `real_time_detection/data_ingestion.py` | Kafka consumer + connector collection |
| **MITRE Mapping** | `real_time_detection/mitre_attack_mapping.py` | Standard technique mapping |
| **Enhanced MITRE** | `real_time_detection/enhanced_mitre_mapping.py` | Advanced: confidence, kill chain, APT patterns |
| **Connectors** | `real_time_detection/connectors/` | Wazuh + Elasticsearch plugin architecture |
| **Redis Storage** | `redis_storage.py` | Alert persistence with fallback |
| **Dashboard** | `dashboard/app.py` | Flask + SocketIO web interface |
| **Simulation** | `simulation/` | Event generators + attack scenarios |
| **Metrics** | `models/metrics.py` | MITRE effectiveness, model performance, SOC efficiency |

### Key Algorithms Explained

#### A. HHOSSSA (Hybrid Harmony-Owl Search-Salp Swarm Algorithm)

A novel metaheuristic combining 3 nature-inspired optimizers:

- **Harmony Search**: Like musicians improvising — explores diverse feature subsets
- **Owl Search**: Like owls hunting — exploits promising regions of the search space
- **Salp Swarm**: Like marine salps chaining — rapid convergence to optimal solution

Used to select the best subset of features that maximizes classification accuracy.

#### B. Hybrid Ensemble

```python
final_score = (lightgbm.predict_proba(X)[:, 1] + bilstm.predict(X).flatten()) / 2
```

- **LightGBM**: Fast, great for tabular data, interpretable feature importance
- **Bi-LSTM**: Captures temporal/sequential attack patterns bidirectionally
- **Simple average**: Robust, reduces individual model bias

#### C. Isolation Forest (Behavioral Analytics)

- Unsupervised anomaly detection — no labels needed
- Per-entity models (each host gets its own baseline)
- Anomalies require fewer tree splits to isolate → shorter path = more anomalous
- Score conversion: `anomaly_score = 1 - (raw_score + 1) / 2`
- Severity thresholds:
  - ≥0.95 → Critical
  - ≥0.9 → High
  - ≥0.8 → Medium
  - <0.8 → Low

---

## 4. STORAGE: What databases/storage and data model?

### Redis (Primary)

```
Key:    apt_detection:alerts
Type:   Redis List (FIFO)
Format: JSON-serialized alert dicts
Max:    1000 alerts (oldest auto-trimmed)
Ops:    RPUSH (add), LRANGE (read all), LTRIM (trim), LLEN (count)
```

### In-Memory (Fallback)

```python
alerts = []                    # Python list
alerts_lock = threading.Lock() # Thread-safe access
# Same 1000 alert cap
```

### Alert Data Model

```python
{
    "entity": "host1",                    # Host/user identifier
    "entity_type": "host",                # host, user, network
    "timestamp": "2026-02-23T10:30:00",   # ISO 8601
    "severity": "High",                   # Critical/High/Medium/Low
    "prediction_score": 0.87,             # ML ensemble confidence (0-1)
    "anomaly_score": 0.92,                # Behavioral anomaly score (0-1)
    "detection_type": "ml_prediction",    # ml_prediction, behavioral_analytics
    "event_type": "network_connection",   # Event category
    "source": {
        "type": "kafka",                  # kafka, connector, behavioral_analytics
        "timestamp": "2026-02-23T10:30:00"
    },
    "features": {                         # Feature values that triggered alert
        "network_traffic_volume_mean": 0.95,
        "number_of_failed_logins_mean": 0.82
    },
    "mitre_attack": {                     # MITRE enrichment
        "techniques": [
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "confidence": 0.85,
                "criticality": "high",
                "kill_chain_phase": "Command and Control",
                "mitigations": {}
            }
        ],
        "tactics": ["Command and Control"],
        "confidence": 0.85,
        "kill_chain_phases": ["Command and Control"],
        "apt_patterns": []
    },
    "investigation": {                    # SOC analyst guidance
        "priority": "high",
        "next_steps": ["Check network logs", "Isolate host"],
        "focus_areas": ["Outbound traffic analysis"],
        "estimated_time": "1h 15m"
    }
}
```

---

## 5. APIs & INTEGRATION

### External Integrations (Inbound)

| Source | Protocol | Auth Method |
|--------|----------|-------------|
| **Wazuh EDR** | REST API (HTTPS) | Basic Auth → Token header |
| **Elasticsearch** | REST API (HTTPS) | Basic Auth / API Key / Cloud ID |
| **Kafka** | TCP | Consumer group, topic subscription |

### APIs Exposed (Dashboard)

#### REST Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/stats` | GET | Alert counts, severity/source/entity distributions |
| `/api/alerts?severity=&entity=&days=` | GET | Filtered alert retrieval |
| `/api/entity/<entity>` | GET | Entity behavior analysis |
| `/api/enhanced_metrics` | GET | Model performance + MITRE effectiveness |
| `/api/mitre_metrics` | GET | MITRE-specific effectiveness data |
| `/api/stream/start` | GET | Start alert streaming |
| `/api/stream/stop` | GET | Stop alert streaming |
| `/api/stream/status` | GET | Stream status check |

#### WebSocket Events

| Event | Direction | Purpose |
|-------|-----------|---------|
| `connect` | Client→Server | Establish WebSocket connection |
| `start_alert_stream` | Client→Server | Begin real-time streaming |
| `stop_alert_stream` | Client→Server | Stop streaming |
| `new_alert` | Server→Client | Push new alert data |
| `stats_update` | Server→Client | Push dashboard statistics |
| `stream_status` | Server→Client | Stream state notifications |

---

## 6. SECURITY

### What's Implemented

- Wazuh/Elasticsearch SSL/TLS support
- Multiple auth methods (Basic, API Key, Cloud)
- Thread-safe data access with mutex locks
- Credentials in config file (not hardcoded in logic)
- Input type-casting and date validation
- Graceful fallback architecture

### What's Missing (Security Gaps)

| Gap | Risk | Status |
|-----|------|--------|
| No dashboard authentication | Anyone can view alerts | Not implemented |
| CORS: `*` (all origins) | Cross-site request forgery | Open |
| Hardcoded Flask secret key | Session tampering | Hardcoded string |
| No rate limiting | API abuse/DoS | Not implemented |
| No CSRF protection | Form-based attacks | Not implemented |
| Redis password optional | Unauthorized data access | Config-dependent |
| Kafka no TLS by default | Data interception | Not configured |
| Config credentials unencrypted | Credential exposure | Plain text YAML |

---

## 7. CONFIGURATION

**Single config file:** `config/config.yaml`

| Section | Controls |
|---------|----------|
| `model_paths` | LightGBM (.pkl) and Bi-LSTM (.h5) file locations |
| `training_params` | Hyperparameters for both models |
| `data_sources.wazuh` | URL, username, password, fetch interval, SSL |
| `data_sources.elasticsearch` | Hosts, auth, index pattern, fetch interval |
| `kafka` | Bootstrap servers, topic, consumer group |
| `dashboard` | Host (0.0.0.0), port (5000), debug mode |
| `settings` | Collection interval, anomaly threshold (0.75) |
| `settings.behavioral_analytics` | Isolation Forest params, baseline period |
| `simulation` | Enabled flag, realism level, entities, event rate, scenarios |

---

## 8. TESTING

### Test Files (all at project root)

| File | Framework | Tests |
|------|-----------|-------|
| `test_metrics.py` | pytest | Metrics calculation, MITRE effectiveness, model performance analysis |
| `test_redis.py` | standalone (python) | Redis connection, CRUD operations, fallback behavior |
| `test_mitre_attack.py` | standalone | Basic MITRE technique mapping accuracy |
| `test_enhanced_mitre.py` | standalone | Enhanced mapping: confidence scores, kill chain, APT patterns |

### Run Commands

```bash
pytest                         # Run all pytest-compatible tests
pytest test_metrics.py         # Specific test suite
python test_redis.py           # Standalone Redis test
python test_mitre_attack.py    # Standalone MITRE test
```

---

## 9. DEPLOYMENT & OPERATIONS

### Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Optional: install & start Redis
# Optional: install & configure Kafka
```

### Run Modes

| Command | What It Does |
|---------|-------------|
| `python main.py` | Production mode (predict + dashboard) |
| `python main.py --production` | Same as above, explicit |
| `python main.py --all` | Everything: ingestion + simulation + Kafka + dashboard |
| `python main.py --train` | Train models only (generates .pkl and .h5) |
| `python main.py --predict` | Prediction engine only (no dashboard) |
| `python main.py --dashboard` | Dashboard only (Flask on port 5000) |
| `python main.py --simulation` | Simulation only |
| `./run_production.sh` | Production wrapper script |

### Threading Model

```
main.py
├── Data Ingestion Thread (daemon) — Kafka consumer + connector polling
├── Simulation Thread (daemon) — Event generation (if enabled)
└── Dashboard Thread (main/blocking) — Flask + SocketIO on port 5000
    └── Alert Stream Worker Thread (daemon) — WebSocket push every 2s
```

System exits when the dashboard thread stops.

### Key Dependencies

- Python 3.8+, Flask, Flask-SocketIO, LightGBM, TensorFlow/Keras
- scikit-learn, pandas, numpy, imbalanced-learn, PyYAML
- redis (Python client), kafka-python
- Optional: Redis server, Kafka broker, Wazuh, Elasticsearch

---

## 10. CODE ORGANIZATION

```
APT-Detection-System/
├── main.py                          # Entry point, CLI args, thread orchestration
├── config/
│   └── config.yaml                  # All runtime configuration
├── models/
│   ├── hybrid_classifier.py         # Ensemble combiner
│   ├── lightgbm_model.py            # LightGBM training/prediction
│   ├── bilstm_model.py              # Bi-LSTM training/prediction
│   ├── train_models.py              # Training orchestrator
│   └── metrics.py                   # Enhanced metrics analysis
├── data_preprocessing/
│   ├── load_dataset.py              # CSV loader
│   ├── data_cleaning.py             # Missing value handling
│   └── feature_engineering.py       # Rolling window features
├── feature_selection/
│   └── hhosssa_feature_selection.py  # HHOSSSA algorithm
├── data_balancing/
│   └── hhosssa_smote.py             # SMOTE oversampling
├── evaluation/
│   ├── evaluation_metrics.py        # Accuracy, ROC-AUC, classification report
│   └── cross_validation.py          # 5-fold stratified CV
├── real_time_detection/
│   ├── prediction_engine.py         # Core detection loop
│   ├── behavioral_analytics.py      # Isolation Forest baselines
│   ├── data_ingestion.py            # Kafka + connector data collection
│   ├── mitre_attack_mapping.py      # Standard MITRE mapping
│   ├── enhanced_mitre_mapping.py    # Advanced MITRE enrichment
│   ├── redis_integration.py         # Redis with in-memory fallback
│   └── connectors/
│       ├── connector_manager.py     # Plugin manager
│       ├── wazuh_connector.py       # Wazuh EDR connector
│       └── elasticsearch_connector.py # ES SIEM connector
├── redis_storage.py                 # Standalone Redis storage module
├── dashboard/
│   ├── app.py                       # Flask + SocketIO app
│   ├── templates/                   # 8 HTML templates
│   │   ├── index.html               # Overview dashboard
│   │   ├── alerts.html              # Alert list + filters
│   │   ├── metrics.html             # Enhanced metrics
│   │   ├── timeline.html            # Attack timeline
│   │   ├── entity.html              # Entity analysis
│   │   ├── models.html              # Model status
│   │   ├── connectors.html          # Connector status
│   │   └── settings.html            # Configuration
│   └── static/                      # CSS, JS assets
├── simulation/
│   ├── simulator.py                 # Main simulator coordinator
│   ├── config.py                    # Simulation configuration
│   ├── entities/                    # Host, User entity classes
│   ├── generators/                  # Network, Endpoint, User event generators
│   ├── scenarios/                   # DataExfiltration, BruteForce scenarios
│   └── outputs/                     # Redis, Kafka output adapters
├── simulation_runner.py             # Standalone simulation CLI
├── produce_messages.py              # Kafka test message producer
├── test_*.py                        # Test files at root
├── requirements.txt                 # Python dependencies
├── run_production.sh                # Production startup script
└── ARCHITECTURE.md                  # Architecture documentation
```

### Design Patterns Used

- **Plugin Architecture**: Connectors can be added without modifying core code
- **Strategy Pattern**: Different ML models behind a common predict interface
- **Observer Pattern**: WebSocket event-driven alert streaming
- **Fallback Pattern**: Redis → in-memory graceful degradation
- **Factory Pattern**: Simulation entity/generator/scenario creation

---

## 11. LIMITATIONS & POTENTIAL IMPROVEMENTS

### Current Limitations

1. **No dashboard authentication** — anyone on the network can access alerts
2. **Equal-weight ensemble** — no adaptive weighting between LightGBM and Bi-LSTM
3. **HHOSSSA is simplified** — current code uses a hardcoded feature list rather than full evolutionary optimization
4. **Model files not in git** — must train locally before running predictions
5. **No horizontal scaling** — single-process threading model
6. **No alert deduplication** — same event can trigger multiple alerts
7. **No TLS for Kafka/Redis** by default
8. **Config credentials in plain text** YAML

### Potential Improvements

1. Add Flask-Login or JWT authentication to dashboard
2. Implement weighted/stacked ensemble with meta-learner
3. Full HHOSSSA evolutionary feature optimization
4. Dockerize with docker-compose for reproducible deployment
5. Add Celery workers for distributed processing
6. Alert deduplication and correlation engine
7. Encrypt credentials with Vault or environment variables
8. Add comprehensive E2E integration tests
9. Implement model retraining pipeline (periodic or drift-triggered)
10. Add RBAC (Role-Based Access Control) for multi-analyst teams
