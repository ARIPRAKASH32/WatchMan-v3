# 🤖🛡️ Watch Man — AI-Powered Intrusion Detection & Response System (IDRS)

> A state-of-the-art, autonomous **Intrusion Detection and Response System (IDRS)** combining real-time network packet feature engineering, hybrid Machine Learning (Random Forest + Isolation Forest), rule-based signatures, dynamic risk quantification, and multi-channel automated countermeasures. Built for professional SOC environments and high-security network monitoring.

---

## 🌟 Architectural & AI Overview

```
                        [ Live Interface / Pcap Capture ]
                                       │
                                       ▼
                       [ Packet Queue & Flow Tracker ]
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
[ Feature Extractor ]       [ Signature Engine ]         [ Flow Statistics ]
  (8D Numerical Vec)           (7 Rule-Based IDS)          (PPS, BPS, Durations)
        │                              │                              │
        ▼                              ▼                              │
[ Machine Learning ]        [ Rule Alert Candidates ]                 │
  ├─ Random Forest                     │                              │
  └─ Isolation Forest                  │                              │
        │                              │                              │
        └───────────────┬──────────────┘                              │
                        ▼                                             │
               [ AI Risk Engine ] ◄───────────────────────────────────┘
         (Composite Risk Score 0–100)
                        │
                        ├──────────────────────────────────────┐
                        ▼                                      ▼
           [ Recommendation Engine ]             [ Auto-Response Engine ]
        (SOC Mitigation Strategies)           (iptables Block & Rate Limit)
                        │                                      │
                        └───────────────┬──────────────────────┘
                                        ▼
                               [ Alert Manager ]
                   (Deduplication + SMTP/Twilio Dispatch)
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
       [ SQLite WAL & Ring Store ]                [ SOC Glassmorphic UI ]
```

---

## ✨ Advanced AI & Security Features

| Feature | Description |
|---------|-------------|
| 🧠 **Hybrid ML Inference** | Real-time classification via **Random Forest** (SYN Flood, DoS, Brute Force, Port Scan) paired with zero-day outlier detection via **Isolation Forest**. |
| 📊 **Stateful Feature Engineering** | Computes an 8-dimensional feature vector per flow in real-time (`proto_code`, `sport`, `dport`, `packet_size`, `flags_code`, `flow_duration`, `bytes_per_sec`, `packets_per_sec`). |
| ⚡ **AI Composite Risk Engine** | Quantifies threat posture on a **0–100 weighted scale** combining rule severity (40%), ML confidence (40%), and anomaly deviation (20%), categorized into *Low*, *Medium*, *High*, and *Critical*. |
| 🛡️ **Autonomous Countermeasures** | Automatically blocks critical threats (`Risk Score > 80`) via dynamic **iptables/ufw** firewall drops, appends rules to `rules/block_rules.sh`, and applies rate limits. |
| 💡 **AI SOC Recommendations** | Maps detected patterns to actionable, professional mitigation strategies (e.g., connection rate limits, SYN cookies, SSH hardening) displayed directly inside the dashboard. |
| 🚨 **Multi-Channel Alert Dispatch** | Sends instant security notifications via **SMTP Email**, **Twilio SMS**, and **Twilio Voice Calls**, protected by strict sliding-window deduplication and anti-flooding controls. |
| 🗃️ **Asynchronous Persistence** | High-throughput packet & incident logging to **SQLite WAL** paired with JSON, CSV, and comprehensive **PDF executive threat reports**. |
| 🌌 **Glassmorphic SOC Dashboard** | Dark-mode, neon-accented UI featuring interactive SVG risk meters, ML confidence bars, real-time threat timelines, top attacker rankings, and flow heat maps. |

---

## 🗂️ Project Directory Structure

```
watchman/
├── app.py                         ← Flask REST API & WebSocket polling server
├── config.yaml                    ← Master configuration (ML paths, risk weights, credentials)
├── requirements.txt               ← Python dependencies
├── README.md                      ← System documentation
├── architecture_diagram.mmd       ← Mermaid architecture diagram source
├── detector/                      ← AI IDRS Detection Pipeline Layer
│   ├── __init__.py
│   ├── detector.py                ← Worker queue processing & engine controller
│   ├── feature_extractor.py       ← 8D flow feature extraction engine
│   ├── ml_models.py               ← RandomForest & IsolationForest manager
│   ├── risk_engine.py             ← Composite 0-100 risk scoring & levels
│   ├── alert_manager.py           ← Multi-channel alerting & anti-flood throttling
│   ├── auto_response.py           ← Firewall blocking & rate limiting counter-measures
│   └── recommendation_engine.py   ← SOC mitigation strategy generator
├── sniffer/                       ← Packet Capture & Simulation Layer
│   ├── __init__.py
│   ├── capture.py                 ← Scapy sniffer engine & realistic demo simulator
│   ├── flow_tracker.py            ← Stateful session tracker
│   └── logger.py                  ← Disk log writer
├── models/                        ← Data Persistence & Shared Memory Layer
│   ├── __init__.py
│   ├── data_store.py              ← Thread-safe in-memory ring buffers & counters
│   ├── database.py                ← SQLite WAL async batch worker & schema
│   ├── ml_models.py               ← Shared model abstractions
├── blueprints/                    ← REST API Blueprints
│   ├── __init__.py
│   └── email_api.py               ← Gmail Alert System & Settings API
├── detector/                      ← Core AI/ML Detection Engine
│   ├── __init__.py
│   ├── alert_manager.py           ← Automated Gmail alert dispatcher & deduplication
│   ├── auto_response.py           ← Autonomous iptables countermeasures
│   ├── feature_extractor.py       ← 8D flow vectorization
│   └── risk_engine.py             ← Composite Risk Quantification (0-100)
├── logs/                          ← Persistent application logs
├── models/                        ← Trained Machine Learning Models & SQLite WAL
│   ├── __init__.py
│   ├── database.py                ← SQLite WAL persistence & email_logs audit schema
│   ├── random_forest.pkl          ← Trained RandomForest model (auto-generates if missing)
│   └── isolation_forest.pkl       ← Trained IsolationForest model
├── notifications/                 ← Alert Providers & OOP Managers
│   ├── __init__.py
│   ├── email_manager.py           ← Reusable OOP Gmail Alert Manager
│   └── email_provider.py          ← Provider interface wrapper
├── rules/                         ← Auto-generated defense scripts
│   └── block_rules.sh             ← Persistent iptables drop script
├── tests/                         ← Comprehensive Unit & Integration Tests
│   ├── test_feature_extractor.py
│   ├── test_risk_engine.py
│   ├── test_alert_manager.py
│   ├── test_auto_response.py
│   ├── test_email_manager.py      ← Verification tests for Gmail SMTP & audit logs
│   └── test_integration.py
├── utils/                         ← Rule-Based IDS & Reporting Utilities
│   ├── __init__.py
│   ├── dos.py / portscan.py / arp.py / bruteforce.py / signatures.py
│   └── reporter.py                ← PDF/JSON report generation
└── static/ & templates/           ← Premium Glassmorphic Web Dashboard
```

---

## ⚙️ Installation & Setup

### Prerequisites
- **Python 3.10+** (Tested on Python 3.12 Linux)
- `pip` & `virtualenv`
- (Optional) Root privileges on Linux for live interface capturing and active `iptables` blocking.

### 1. Clone & Prepare Environment
```bash
cd watchman
python3 -m venv venv_idrs
source venv_idrs/bin/activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Gmail Alert System & Credentials
Watch Man uses pure **Gmail SMTP** (`smtp.gmail.com:587`) with TLS encryption for automated critical security notifications. All legacy Twilio SMS/Voice dependencies have been removed.

Configure your credentials either by creating a `.env` file in the project root or editing `config.yaml`:

#### Option A: Secure `.env` Configuration (Recommended)
Copy `.env.example` to `.env` and set your Gmail credentials:
```env
EMAIL_USERNAME=ariprakash32@gmail.com
EMAIL_PASSWORD=gwcrpqhejjwsolbk
EMAIL_RECIPIENT=ariprakash741@gmail.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
```

#### Option B: `config.yaml` Fallback
```yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "ariprakash32@gmail.com"
  password: "gwcrpqhejjwsolbk"
  from_address: "ariprakash32@gmail.com"
  to_address: "ariprakash32@gmail.com"
```

> **Note:** You can also dynamically update and test your Gmail credentials directly through the **Glassmorphic Settings Dashboard** (`http://127.0.0.1:5000` → **SETTINGS** tab).

---

## 🚀 Running Watch Man IDRS

### 🧪 Demo Mode (Simulation / No Root Required)
Generates high-fidelity synthetic network traffic including normal web flows, SYN flood attacks, port scans, and SSH brute-force attempts to exercise the AI pipeline right out of the box:
```bash
cd ~/Downloads/WatchMan---v3\ \(2\).2/WatchMan---Network-Traffic-Analyzer-main
source venv_idrs/bin/activate
python app.py --demo
```
Access the SOC Dashboard at: **http://127.0.0.1:5000**

### 📡 Live Mode (Real Network Traffic & Active Mitigation)
Captures live packets from your network interface (`eth0`, `wlan0`, or `any`) and actively executes firewall rules against attackers (Linux Root Required):
```bash
cd ~/Downloads/WatchMan---v3\ \(2\).2/WatchMan---Network-Traffic-Analyzer-main
source venv_idrs/bin/activate
sudo ./venv_idrs/bin/python3 app.py
```

#### If Port 5000 Is Already in Use
If you encounter a port binding error when starting the server, check for any running process on port 5000 and terminate it:
```bash
sudo lsof -i :5000
sudo kill -9 <PID>
```

**Example:**
```bash
sudo kill -9 4798
```

Then run Live Mode again:
```bash
sudo ./venv_idrs/bin/python3 app.py
```

---

## 🧪 Testing Suite & Verification

The project includes an exhaustive unit and end-to-end integration test suite verifying feature extraction, risk score calculations, alert deduplication, and automated countermeasures:
```bash
./venv_idrs/bin/python3 -m unittest discover -s tests -v
```

**Test Coverage:**
- `test_feature_extractor.py`: Verifies packet parsing, flow duration calculations, and 8D numerical vector encoding (`TCP` → 1, `UDP` → 2, etc.).
- `test_risk_engine.py`: Verifies weighted scoring logic (0–100) across normal flows, medium threats, and critical SYN flood/ML attack detections.
- `test_alert_manager.py`: Verifies sliding-window cooldown (`300s`) and confidence threshold suppression.
- `test_auto_response.py`: Verifies duplicate block protection and rule tracking.
- `test_integration.py`: Enqueues 50 synthetic attack packets, exercises the worker queue, verifies AI state updates, and confirms composite risk quantification.

---

## 🌐 REST API & AI Telemetry Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Glassmorphic SOC Web Dashboard |
| `/api/risk_score` | GET | Returns live composite AI risk metrics (`{"score": 15, "level": "Low"}`) |
| `/api/ml_prediction` | GET | Returns latest ML classification (`{"prediction": "Normal", "confidence": 98.0}`) |
| `/api/anomaly_score` | GET | Returns Isolation Forest anomaly metric (`{"anomaly_score": 5.0}`) |
| `/api/threat_stats` | GET | Deep telemetry for Threat Dashboard (heat maps, top attackers, timeline) |
| `/traffic` | GET | Full traffic snapshot and per-second counters (JSON) |
| `/alerts` | GET | Threat incident list with AI recommendations & action taken (JSON) |
| `/stats` | GET | KPI summary (total packets, data volume, PPS, critical alerts) |
| `/export/csv` | GET | Download complete traffic captures as CSV |
| `/export/alerts/csv` | GET | Download detailed AI threat incident log as CSV |
| `/clear-alerts` | POST | Clear stored incidents and reset backend threat counters |

---

## 🔮 Future Enhancements
- **Deep Learning Sequence Models:** Integrating LSTM / Transformer models for multi-step attack chain prediction across prolonged sessions.
- **BGP / Cloudflare Flow Spec:** Extending auto-response measures to push BGP FlowSpec rules or Cloudflare API block rules for upstream DDoS mitigation.
- **PCAP Replay Engine:** Adding a web UI file upload allowing analysts to drag-and-drop offline `.pcap` files for instant AI forensic reporting.
