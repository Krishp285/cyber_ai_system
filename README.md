# ⬡ CYBER·AI — Threat Intelligence & Attack Prediction System

> A production-ready AI-powered cybersecurity platform combining Machine Learning, Real-time Threat Detection, and Data Science into a unified dashboard.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![React](https://img.shields.io/badge/React-18.x-61dafb)
![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-97.1%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [ML Model Details](#-ml-model-details)
- [API Reference](#-api-reference)
- [Security Modules](#-security-modules)
- [Viva / Interview Guide](#-viva--interview-guide)
- [Future Scope](#-future-scope)

---

## 🎯 Overview

The **AI Cyber Threat Intelligence & Attack Prediction System** is a full-stack cybersecurity platform that:

- **Monitors** simulated network/system logs in real-time
- **Detects** cyber attacks using a trained Random Forest ML model
- **Scores** threat risk on a 0–100 scale using a multi-factor engine
- **Predicts** future threats using time-series forecasting
- **Visualizes** all data through an interactive dark-themed React dashboard

The system demonstrates the intersection of **Artificial Intelligence**, **Cybersecurity**, and **Data Science** — making it ideal for final-year projects, research demonstrations, and placement portfolios.

---

## ✨ Features

### 🤖 AI/ML Engine
| Feature | Detail |
|---------|--------|
| Random Forest Classifier | 9-class attack detection, 97.1% accuracy |
| Isolation Forest | Anomaly detection for zero-day threats |
| Feature Engineering | 17-dimensional feature vectors from network logs |
| Risk Scorer | Multi-factor 0-100 risk computation |
| Model Artifacts | Pickled `.pkl` models for fast inference |

### 🔐 Security Modules
| Feature | Detail |
|---------|--------|
| JWT Authentication | Access + refresh token flow |
| Brute Force Detection | IP-based attempt counting with auto-block |
| Simulated Firewall | IP blocklist management |
| Rule-based Alerts | 7 alert rules across severity levels |
| IP Tracking | Login attempt logging per IP |
| Risk Classification | LOW / MEDIUM / HIGH / CRITICAL tiers |

### 📊 Data Science
| Feature | Detail |
|---------|--------|
| Attacks Per Day | 30-day time series |
| Attack Type Breakdown | Bar + radar charts |
| Top Attacker IPs | Ranked by frequency and max risk |
| Geo Distribution | Country-level origin mapping |
| Hourly Pattern | 24-hour attack heatmap |
| 7-Day Forecast | Moving average + noise prediction |
| Protocol Analysis | TCP/UDP/ICMP distribution |

### 🌐 Frontend
| Feature | Detail |
|---------|--------|
| Login Page | JWT auth with brute force warning |
| Dashboard | Stats, charts, live feed, blocked IPs |
| Threat Monitor | ML predictions, live simulation, alert management |
| Analytics | Full data science visualization suite |
| Dark Theme | Cybersecurity-grade dark UI |
| Real-time Updates | Auto-refresh every 15s, live simulation mode |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    REACT FRONTEND (Port 3000)           │
│   Login │ Dashboard │ Threat Monitor │ Analytics        │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API (JWT)
┌──────────────────────▼──────────────────────────────────┐
│                FLASK BACKEND (Port 5000)                 │
│  /login /predict /simulate /logs /alerts /analytics     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │ Auth Module  │  │  ML Engine   │  │ Alert Engine  │ │
│  │ JWT + Brute  │  │  RF + ISO    │  │ Rule-based    │ │
│  │ Force Detect │  │  Forest      │  │ 7 Alert Rules │ │
│  └──────────────┘  └──────────────┘  └───────────────┘ │
└──────────────────────┬──────────────────────────────────┘
                       │ SQLAlchemy ORM
┌──────────────────────▼──────────────────────────────────┐
│           DATABASE (MySQL / SQLite fallback)             │
│  users │ network_logs │ attack_predictions │ alerts     │
│  blocked_ips │ login_attempts │ threat_forecasts        │
└─────────────────────────────────────────────────────────┘
                       ▲
┌──────────────────────┴──────────────────────────────────┐
│              ML MODEL (ml_model/)                        │
│  rf_model.pkl (Random Forest — 97.1% accuracy)         │
│  iso_model.pkl (Isolation Forest — Anomaly Detection)   │
│  scaler.pkl (StandardScaler)                            │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18 + React Router | SPA, navigation |
| **Charts** | Recharts | All visualizations |
| **HTTP Client** | Axios | API calls + interceptors |
| **Backend** | Flask 3.0 | REST API server |
| **Auth** | Flask-JWT-Extended | JWT tokens |
| **ORM** | Flask-SQLAlchemy | Database abstraction |
| **Database** | MySQL (SQLite fallback) | Persistence |
| **ML** | Scikit-learn | Random Forest + Isolation Forest |
| **Data Science** | Pandas, NumPy | Feature engineering |
| **Visualization** | Matplotlib, Seaborn | Chart generation |
| **Security** | Werkzeug, bcrypt | Password hashing |

---

## 📂 Project Structure

```
cyber_ai_system/
│
├── backend/                    # Flask API server
│   ├── app.py                  # App factory, DB init, seed data
│   ├── models.py               # SQLAlchemy ORM models
│   ├── requirements.txt        # Python dependencies
│   ├── config/
│   │   └── config.py           # Dev/Prod/Test configurations
│   ├── model/
│   │   └── predictor.py        # ML inference engine
│   ├── routes/
│   │   ├── auth_routes.py      # /login /logout /me /refresh
│   │   ├── prediction_routes.py# /predict /simulate /bulk-simulate
│   │   ├── log_routes.py       # /logs /logs/stats /logs/recent
│   │   ├── alert_routes.py     # /alerts /alerts/resolve
│   │   └── analytics_routes.py # /analytics/overview /analytics/chart
│   └── utils/
│       ├── auth.py             # JWT helpers, brute force detection
│       ├── log_generator.py    # Synthetic log simulation engine
│       ├── risk_scorer.py      # Multi-factor risk scoring
│       └── alert_engine.py     # Rule-based alert system
│
├── frontend/                   # React application
│   ├── package.json
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.js              # Router + protected routes
│       ├── index.js
│       ├── styles/
│       │   └── global.css      # Dark cybersecurity theme
│       ├── hooks/
│       │   └── useAuth.js      # Auth context + hook
│       ├── utils/
│       │   └── api.js          # Axios client + all API calls
│       ├── components/
│       │   └── Layout.js       # Sidebar + shell layout
│       └── pages/
│           ├── LoginPage.js    # Auth page
│           ├── DashboardPage.js# Main overview
│           ├── ThreatMonitorPage.js # ML predictions + alerts
│           └── AnalyticsPage.js    # Data science charts
│
├── database/
│   └── schema.sql              # MySQL DDL + seed data
│
├── ml_model/
│   ├── train_model.py          # Full training script
│   ├── rf_model.pkl            # Trained Random Forest
│   ├── iso_model.pkl           # Trained Isolation Forest
│   ├── scaler.pkl              # StandardScaler
│   ├── label_encoder.pkl       # Label encoder
│   ├── feature_columns.json    # Feature list
│   └── reports/
│       ├── confusion_matrix.png
│       ├── feature_importance.png
│       └── rf_metrics.json
│
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- MySQL 8.0+ (or use SQLite fallback — no config needed)

### 1. Clone & Setup Backend

```bash
cd cyber_ai_system/backend
pip install -r requirements.txt

# Optional: set environment variables
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
# For MySQL: export DATABASE_URL=mysql+pymysql://user:pass@localhost/cyber_ai_db
# SQLite fallback is used automatically in development mode

python app.py
# Backend runs at http://localhost:5000
```

### 2. Train the ML Model

```bash
cd cyber_ai_system
python ml_model/train_model.py
# Generates rf_model.pkl, iso_model.pkl, scaler.pkl
# Shows accuracy ~97% and saves confusion matrix PNG
```

### 3. Setup Frontend

```bash
cd cyber_ai_system/frontend
npm install
npm start
# Frontend runs at http://localhost:3000
```

### 4. Login

```
URL:      http://localhost:3000/login
Username: admin
Password: Admin@123
```

### MySQL Setup (Optional)

```bash
mysql -u root -p < database/schema.sql
export DATABASE_URL=mysql+pymysql://root:root@localhost/cyber_ai_db
```

---

## 🤖 ML Model Details

### Random Forest Classifier

| Property | Value |
|----------|-------|
| Algorithm | Random Forest |
| Trees | 150 estimators |
| Max Depth | 20 |
| Training Samples | 6,400 (80% of 8,000) |
| Test Samples | 1,600 (20%) |
| **Accuracy** | **97.12%** |
| **F1 Score** | **97.11%** |

### Attack Classes
| Class | Description | Risk Level |
|-------|-------------|-----------|
| Normal | Legitimate traffic | LOW |
| DoS | Denial of Service | HIGH |
| DDoS | Distributed DoS | CRITICAL |
| Probe | Network reconnaissance | MEDIUM |
| PortScan | Port scanning | MEDIUM |
| BruteForce | Credential attacks | HIGH |
| R2L | Remote-to-Local | HIGH |
| U2R | User-to-Root (privilege escalation) | CRITICAL |
| SQLInjection | SQL injection attempt | CRITICAL |

### Feature Vector (17 dimensions)
```
duration, bytes_sent, bytes_received, packets_sent, packets_received,
source_port, destination_port,
protocol_TCP, protocol_UDP, protocol_ICMP,
service_http, service_https, service_ftp, service_ssh, service_smtp,
service_dns, service_other
```

### Isolation Forest (Anomaly Detection)
- Detects zero-day / unseen attacks
- Contamination factor: 15%
- Score < -0.3 flags as anomaly
- Adds bonus to risk score when triggered

### Risk Scoring Formula
```
score = base_attack_score
      + (confidence - 0.5) × 20      [confidence adjustment]
      + protocol_risk_factor           [ICMP +2, UDP +1]
      + port_risk_bonus               [SSH/MySQL/Redis +8]
      + volume_bonus                  [high bytes/packets]
      + anomaly_bonus                 [if Isolation Forest flags]

level = CRITICAL if score ≥ 85
        HIGH     if score ≥ 65
        MEDIUM   if score ≥ 40
        LOW      otherwise
```

---

## 🔗 API Reference

### Authentication
```
POST /api/login       { username, password } → { access_token, refresh_token, user }
POST /api/logout      (auth) → { message }
GET  /api/me          (auth) → { user }
POST /api/refresh     (refresh token) → { access_token }
```

### Prediction
```
POST /api/predict       (auth) → { prediction: { attack_type, confidence, risk_score, risk_level } }
POST /api/simulate      (auth) → { log, prediction }   # generate + predict one log
POST /api/bulk-simulate (auth) { count } → { summary, results }
GET  /api/predictions   (auth) ?risk_level=&attack_type=&page=&limit= → { predictions, total }
```

### Logs
```
GET /api/logs        (auth) ?page=&limit=&source_ip=&action=&protocol= → { logs, total }
GET /api/logs/recent (auth) → { logs }    # last 20
GET /api/logs/stats  (auth) → { total_logs, total_attacks, active_alerts, ... }
```

### Alerts
```
GET  /api/alerts                (auth) ?severity=&resolved= → { alerts, total }
GET  /api/alerts/recent         (auth) → { alerts }  # top 10 unresolved
GET  /api/alerts/summary        (auth) → { summary }
POST /api/alerts/{id}/resolve   (auth) → { alert }
POST /api/alerts/resolve-all    (auth) → { message }
```

### Firewall
```
GET  /api/blocked-ips              (auth) → { blocked_ips }
POST /api/blocked-ips/{id}/unblock (auth) → { ip }
```

### Analytics
```
GET /api/analytics/overview         (auth) → full analytics JSON
GET /api/analytics/chart/{type}     (auth) → PNG image
    types: attacks_per_day | attack_types | risk_levels | top_ips
```

---

## 🔐 Security Modules

### Brute Force Detection
1. Every login attempt → stored in `login_attempts` table
2. Failed attempts counted per IP in last 5 minutes
3. If failed count ≥ 5 → IP auto-blocked in `blocked_ips`
4. CRITICAL alert created and email simulated

### Rule-based Alert Engine (7 rules)
| Rule | Trigger | Severity |
|------|---------|----------|
| RULE_001 | CRITICAL risk prediction | CRITICAL |
| RULE_002 | HIGH risk prediction | HIGH |
| RULE_003 | DoS/DDoS with >80% confidence | CRITICAL |
| RULE_004 | U2R (privilege escalation) | CRITICAL |
| RULE_005 | Probe / Port scan | WARNING |
| RULE_006 | R2L (remote access) | HIGH |
| RULE_007 | Isolation Forest anomaly | WARNING |

### JWT Flow
```
Login → access_token (8hr) + refresh_token (7d)
All API calls → Bearer {access_token} header
On 401 → auto-refresh using refresh_token
On refresh fail → redirect to /login
```

---

## 🎓 Interview Guide

### Q: What machine learning algorithm did you use and why?
**A:** Random Forest — an ensemble of 150 decision trees. It handles imbalanced classes well (attack types vary in frequency), provides feature importance, is robust to overfitting, and achieves 97.1% accuracy on our 9-class classification problem without extensive hyperparameter tuning.

### Q: How does the Isolation Forest work?
**A:** Isolation Forest isolates anomalies by randomly partitioning the feature space. Anomalous points (unusual traffic patterns) require fewer partitions to isolate, giving them a lower anomaly score. We use this to detect zero-day attacks not seen during training.

### Q: Explain the risk scoring system.
**A:** It's a multi-factor 0-100 score. Base score comes from the attack type, then we adjust for ML confidence, protocol risk, destination port sensitivity, traffic volume, and whether Isolation Forest flagged it as anomalous. Scores ≥85 = CRITICAL, ≥65 = HIGH, ≥40 = MEDIUM.

### Q: How does JWT authentication work?
**A:** Login returns a short-lived access token (8hr) and a long-lived refresh token (7 days). The React app attaches the access token to every API call. When it expires, Axios interceptors automatically use the refresh token to get a new access token — seamless for the user.

### Q: How does brute force detection work?
**A:** Every login attempt (success or failure) is stored in `login_attempts` table with the source IP and timestamp. Before each login attempt, we count failed attempts from that IP in the last 5 minutes. If ≥5, the IP is auto-added to `blocked_ips` and a HIGH alert is created.

### Q: What dataset did you use?
**A:** We built a synthetic NSL-KDD style dataset with statistically distinct distributions per attack class (DoS has high bytes/packets, PortScan has tiny packets, BruteForce targets SSH/RDP ports, etc.). In production, real NSL-KDD or CICIDS2017 CSV can be loaded instead.

### Q: How is the data stored?
**A:** MySQL (SQLite in dev). 7 tables: `users` (auth), `network_logs` (raw traffic), `attack_predictions` (ML outputs), `alerts` (triggered rules), `blocked_ips` (firewall), `login_attempts` (brute force tracking), `threat_forecasts` (predictions).

---

## 🔮 Future Scope

| Enhancement | Description |
|------------|-------------|
| **Real PCAP Ingestion** | Parse actual `.pcap` files using Scapy |
| **CICIDS2017 Dataset** | Train on real-world labeled network dataset |
| **Deep Learning** | LSTM for sequential traffic pattern detection |
| **Real-time WebSocket** | Push alerts instantly via WebSocket |
| **GeoIP API** | Live IP geolocation using MaxMind or ip-api.com |
| **SIEM Integration** | Forward alerts to Splunk / Elastic SIEM |
| **Threat Intelligence Feeds** | Integrate AlienVault OTX, VirusTotal APIs |
| **Honeypot Module** | Simulate vulnerable services to lure attackers |
| **Email/Slack Alerts** | Real alerting via SMTP / Slack webhooks |
| **Docker Compose** | One-command deployment |
| **Role-based Access** | Granular permissions per user role |
| **Model Auto-retrain** | Scheduled retraining on new attack data |

---

## 📊 Key Metrics Summary

```
┌──────────────────────────────────────────┐
│  ML Model Performance                    │
│  ─────────────────────────────────────── │
│  Algorithm    : Random Forest (150 trees)│
│  Accuracy     : 97.12%                  │
│  F1 Score     : 97.11%                  │
│  Classes      : 9 attack categories     │
│  Features     : 17 dimensions           │
│  Training Set : 6,400 samples           │
│  Test Set     : 1,600 samples           │
│                                          │
│  Per-Class F1 Scores:                   │
│  Normal       1.00  ████████████████    │
│  DoS          1.00  ████████████████    │
│  DDoS         1.00  ████████████████    │
│  PortScan     0.97  ███████████████     │
│  Probe        0.97  ███████████████     │
│  BruteForce   0.93  ██████████████      │
│  U2R          0.91  ██████████████      │
│  SQLInjection 0.91  ██████████████      │
│  R2L          0.89  █████████████       │
└──────────────────────────────────────────┘
```

---

## 👨‍💻 Author

Built as a final-year project demonstrating:
- Full-stack development (React + Flask)
- Machine Learning in production (sklearn)
- Cybersecurity engineering (JWT, brute force, firewall simulation)
- Data Science & visualization (Pandas, Matplotlib, Recharts)

---

*© 2026 CYBER·AI — AI Threat Intelligence System*
