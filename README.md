# TRACE-X // AI-Powered Bitcoin Transaction Monitoring & Forensic Intelligence Workstation

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-blue?style=flat-square)](#)
[![Python](https://img.shields.io/badge/Python-3.12%2B-cyan?style=flat-square&logo=python)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=flat-square&logo=fastapi)](#)
[![Machine Learning](https://img.shields.io/badge/ML-Isolation%20Forest%20%2B%20Ensemble-orange?style=flat-square)](#)
[![Database](https://img.shields.io/badge/Database-SQLite%203%20%2F%20SQLAlchemy-003B57?style=flat-square&logo=sqlite)](#)
[![PDF Generation](https://img.shields.io/badge/Reports-ReportLab%20Vector%20Engine-red?style=flat-square)](#)

> **Detect. Correlate. Investigate.**  
> TRACE-X is an offline-ready, publication-grade cryptocurrency forensic workstation designed to correlate **Bitcoin on-chain blockchain transaction activity** with **network-layer observations** (IP addresses, ports, ASNs, geographic locations, and propagation timing) to detect anomalies, analyze high-risk entities, visualize transaction flows, and generate certified intelligence dossiers.

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. System Architecture](#2-system-architecture)
- [3. Core Forensic Capabilities](#3-core-forensic-capabilities)
  - [3.1 Command Center](#31-command-center)
  - [3.2 Wallet Forensic Dossier](#32-wallet-forensic-dossier)
  - [3.3 Transaction Forensic Flow](#33-transaction-forensic-flow)
  - [3.4 Network Graph Topology](#34-network-graph-topology)
  - [3.5 Threat Intelligence & Alerts](#35-threat-intelligence--alerts)
  - [3.6 Dataset Ingestion & Multi-Model Pipeline](#36-dataset-ingestion--multi-model-pipeline)
  - [3.7 Analysis Sessions & Audit Log](#37-analysis-sessions--audit-log)
  - [3.8 Certified Forensic Report Dossier & PDF Export](#38-certified-forensic-report-dossier--pdf-export)
  - [3.9 System Diagnostics & Workstation Health](#39-system-diagnostics--workstation-health)
- [4. Multi-Vector Risk Engine & ML Pipeline](#4-multi-vector-risk-engine--ml-pipeline)
- [5. Technology Stack](#5-technology-stack)
- [6. Directory Structure](#6-directory-structure)
- [7. Installation & Setup](#7-installation--setup)
- [8. Quick Start & Execution](#8-quick-start--execution)
- [9. REST API Reference](#9-rest-api-reference)
- [10. Data Integrity & Ethical Disclaimer](#10-data-integrity--ethical-disclaimer)

---

## 1. Executive Summary

Traditional blockchain intelligence tools analyze on-chain transaction data in isolation, while network security monitors observe traffic without blockchain context. **TRACE-X bridges this divide.**

TRACE-X normalizes cryptocurrency transactions alongside observed IP addresses, ports, autonomous systems (ASNs), and timestamps. It uses an unsupervised machine-learning engine (**Isolation Forest**) paired with multi-vector heuristic risk scoring to detect anomalous transaction velocity, peeling chains, mixing patterns, and distributed relay infrastructure.

```
┌─────────────────────────┐       ┌──────────────────────────┐
│   On-Chain Blockchain   │       │ Network-Layer Telemetry  │
│ TXIDs / Inputs / Outputs│       │ IPs / Ports / ASNs / Geo │
└────────────┬────────────┘       └─────────────┬────────────┘
             │                                  │
             └─────────────────┬────────────────┘
                               ▼
            ┌───────────────────────────────────────┐
            │   TRACE-X Ingestion & Normalization   │
            └──────────────────┬────────────────────┘
                               ▼
            ┌───────────────────────────────────────┐
            │   Feature Extraction & Multi-Vector   │
            │          Isolation Forest ML          │
            └──────────────────┬────────────────────┘
                               ▼
            ┌───────────────────────────────────────┐
            │  4-Vector Risk Scoring & Explanation  │
            └──────────────────┬────────────────────┘
                               ▼
       ┌─────────────────────────────────────────────────┐
       │   TRACE-X Forensic Intelligence Workstation     │
       │   Dossiers • Flows • Graphs • Alerts • Reports  │
       └─────────────────────────────────────────────────┘
```

---

## 2. System Architecture

```
                               TRACE-X WORKSTATION
                                        │
        ┌───────────────────────────────┴───────────────────────────────┐
        │                                                               │
┌───────▼────────┐                                              ┌───────▼────────┐
│  DATA LAYER    │                                              │ PRESENTATION   │
├────────────────┤                                              ├────────────────┤
│ • SQLite DB    │                                              │ • Vanilla HTML5│
│ • SQLAlchemy   │                                              │ • Vanilla CSS3 │
│ • CSV Ingest   │                                              │ • Vanilla ES6  │
│ • DB-IP MMDB   │                                              │ • Force Canvas │
└───────┬────────┘                                              └───────▲────────┘
        │                                                               │
        ▼                                                               │
┌───────────────────────────────────────────────────────────────┐       │
│                     FASTAPI REST BACKEND                      ├───────┘
├───────────────────────────────────────────────────────────────┤
│ • /api/overview       • /api/wallet/{address}  • /api/datasets│
│ • /api/alerts         • /api/transaction/{tx}  • /api/reports │
│ • /api/system/health  • /api/graph             • /api/sessions│
└───────┬───────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│                   MACHINE LEARNING PIPELINE                   │
├───────────────────────────────────────────────────────────────┤
│ • 9-Dimensional Behavioral & Network Feature Engineering      │
│ • StandardScaler Normalization                                │
│ • Isolation Forest Anomaly Detection (300 Estimators)         │
│ • 4-Vector Risk Engine (ML, Velocity, Network, Graph)         │
│ • Multi-Model Synthetic Dataset Generator                     │
└───────────────────────────────────────────────────────────────┘
```

---

## 3. Core Forensic Capabilities

### 3.1 Command Center
* **Live HUD Intelligence Metrics**: Displays Total Monitored Wallets, High-Risk Entities, ML Anomalies, Fleet Average Risk, and Observed IP Nodes.
* **Risk Distribution Bar**: Visual categorical breakdown across Critical ($\ge 80$), High ($60\text{--}79$), Medium ($35\text{--}59$), and Safe ($< 35$) risk bands.
* **Priority Threat Feed**: Real-time high-priority alerts with one-click entity inspection.
* **Workstation Health Strip**: Live status of the backend API gateway, SQLite database engine, and ML model inference pipeline.

### 3.2 Wallet Forensic Dossier
* **Entity Identity Lookup**: Search bar supporting direct query of any Bitcoin address (`bc1...`, `1...`, `3...`) with error fallback.
* **4-Vector Risk Dimension Breakdown**:
  * `ML Classification (50%)`: Isolation Forest behavioral outlier confidence.
  * `Velocity & Flow (20%)`: Anomaly metrics derived from transaction frequency and volume dispersion.
  * `Network Infrastructure (15%)`: Risk associated with observed IP diversity, VPN/TOR/bulletproof hosting, and ASNs.
  * `Graph Centrality (15%)`: Proximity and hub connectivity to known illicit clusters.
* **Net Flow Ledger**: Explicit calculations for Total Received, Total Sent, Net Balance Delta, and Transaction Volume.
* **Connected Counterparties Dossier**: Detailed table documenting counterparties, entity types, direct transaction count, transferred volume, and composite risk levels.
* **Chronological Audit Trail**: Full transaction history tagged with directional markers (`INCOMING` vs `OUTGOING`).

### 3.3 Transaction Forensic Flow
* **Interactive TXID Search**: Direct lookup supporting arbitrary transaction hashes.
* **3-Column Forensic Topology Diagram**:
  $$\text{Inputs (Sender Wallets)} \longrightarrow \text{Transaction Hash Core Node} \longrightarrow \text{Outputs (Recipient Wallets)}$$
* **Multi-Vector Investigative Evidence**: Synthetic rationale cards highlighting fan-out dispersion, round-value heuristics, peeling patterns, and fee anomalies.
* **Network-Layer Observations**: Correlates source/destination IP addresses, observation ports, ISP nodes, ASNs, and relay timestamps.

### 3.4 Network Graph Topology
* **Interactive Canvas Physics Engine**: Deterministic force-directed layout utilizing Euclidean distance calculations (`Math.hypot`).
* **Graph Synopsis Strip**: Live graph metrics showing total node count, active edges, graph density %, high-risk node density, and mean degree.
* **Multi-Level Scope Filter**:
  * **Focused Target Subgraph**: Isolates a specific suspect wallet and its 1st/2nd degree counterparties.
  * **Global Dataset Overview**: Renders full sampled fleet topology.
* **Workstation Tools**: Node limit selectors ($60, 120, 200$), zoom/pan controls, node ID search drawer, and entity inspector sidebar.

### 3.5 Threat Intelligence & Alerts
* **Ranked Priority Queue**: Sorted by composite risk score with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`).
* **Filtering Controls**: Filter alerts by risk threshold, anomaly label, or address.
* **Direct Workstation Navigation**: 1-click jump to Wallet Dossier, Network Graph, or Forensic Report.

### 3.6 Dataset Ingestion & Multi-Model Pipeline
* **Multi-Source Ingestion**: Drag-and-drop or file browsing for RFC-4180 CSV transaction datasets.
* **Preset Ingestion**: 1-click loading of the standardized benchmark dataset (`bitcoin_traffic.csv`).
* **Fresh Dataset Synthesis**: Generates fresh, multi-model synthetic datasets without overwriting historical data.
* **Generated Dataset Archive & History**: Persistent SQLite-backed repository tracking all historical datasets with sample counts, transaction counts, anomaly counts, generation dates, and model signatures.
* **Operational Actions**:
  * `[INGEST & TRAIN]`: Feeds dataset directly into the active database and runs the ML pipeline.
  * `[DOWNLOAD CSV]`: Streams raw dataset file directly from disk.
  * `[DELETE]`: Safely purges non-default datasets and their disk artifacts.

### 3.7 Analysis Sessions & Audit Log
* **Session Records**: Complete audit trail of all ingestion and ML training executions.
* **Session Metadata**: Tracks dataset name, start time, completion duration, transaction volume, wallet count, alerts detected, and peak risk scores.

### 3.8 Certified Forensic Report Dossier & PDF Export
* **12-Section Cyber-Intel Dossier**:
  1. Header & Case Identification
  2. Executive Findings & Threat Overview
  3. Evidentiary Integrity & Cryptographic SHA-256 Checksum
  4. Entity Identity & Scope
  5. 4-Vector Risk Assessment Breakdown
  6. Machine Learning Model Scorecard
  7. Behavioral Profile & Anomaly Flags
  8. Network Infrastructure & Relay Telemetry
  9. Transaction Audit Trail
  10. Connected Counterparty Fleet Analysis
  11. Forensic Analysis Session History
  12. Formal Investigator Attestation & Sign-Off Block
* **ReportLab Vector PDF Generator**: Generates publication-grade, vector-drawn PDF files (`/api/reports/pdf`) with headers, risk scorecards, styled audit tables, and tamper-evident hashes.
* **Target Scope Selector**: Switch between Global Dataset Audits and Suspect-Targeted Wallet Dossiers.

### 3.9 System Diagnostics & Workstation Health
* **Database Engine**: Live row counts for `wallets`, `transactions`, `network_observations`, `ips`, and `sessions`.
* **ML Model Registry**: Active model signatures, feature vector dimensions, tree counts ($300$ estimators), and contamination factors ($0.08$).
* **Environment Specs**: Python version, OS platform, and Uvicorn runtime configuration.

---

## 4. Multi-Vector Risk Engine & ML Pipeline

### 4.1 Feature Engineering (9 Vectors)

| Feature | Category | Description |
| :--- | :--- | :--- |
| `transaction_count` | Velocity | Total transactions associated with the wallet |
| `total_received` | Value | Aggregate inbound volume in BTC |
| `total_sent` | Value | Aggregate outbound volume in BTC |
| `source_ip_count` | Infrastructure | Count of distinct originating IP addresses |
| `destination_ip_count` | Infrastructure | Count of distinct recipient IP addresses |
| `asn_count` | Network | Count of distinct Autonomous Systems observed |
| `tx_per_ip` | Ratio | Transaction density per observed IP node |
| `flow_imbalance` | Flow | Normalized difference between received and sent volume |
| `network_diversity` | Network | Entropy of IP and ASN infrastructure |

### 4.2 Composite Risk Formula

$$\text{Risk Score} = \min\left(100, \; 0.50 \cdot S_{\text{ML}} + 0.20 \cdot S_{\text{Velocity}} + 0.15 \cdot S_{\text{Network}} + 0.15 \cdot S_{\text{Flow}}\right)$$

Where:
* $S_{\text{ML}} = \text{Isolation Forest Anomaly Confidence} \times 100$
* $S_{\text{Velocity}} = \min\left(100, \; \frac{\text{tx\_count}}{30} \times 100\right)$
* $S_{\text{Network}} = \min\left(100, \; \frac{\text{asn\_count} + \text{source\_ip\_count}}{10} \times 100\right)$
* $S_{\text{Flow}} = |\text{flow\_imbalance}| \times 100$

---

## 5. Technology Stack

* **Runtime & Language**: Python 3.12+
* **Backend Web Framework**: FastAPI (Async REST API)
* **ASGI Server**: Uvicorn
* **Database & ORM**: SQLite 3 / SQLAlchemy
* **Machine Learning**: Scikit-Learn (`IsolationForest`, `StandardScaler`), NumPy, Pandas
* **Model Serialization**: Joblib
* **PDF Vector Engine**: ReportLab
* **GeoIP & ASN Lookup**: MaxMind GeoIP2 / DB-IP Lite MMDB
* **Frontend UI**: Vanilla HTML5, Vanilla CSS3 (Custom Design System, Glassmorphism), Vanilla JavaScript ES6 (Custom Single-Page Router & Canvas Graph Engine)

---

## 6. Directory Structure

```
trace-x/
├── requirements.txt            # Python dependencies
├── README.md                   # Platform documentation
│
├── backend/
│   ├── init_db.py              # Database schema initialization
│   ├── ingest.py               # CLI dataset ingestion script
│   ├── train_model.py          # ML Isolation Forest training pipeline
│   ├── generate_alerts.py      # Batch risk scoring & alert generator
│   ├── update_geoip.py         # DB-IP GeoIP/ASN updater
│   │
│   └── app/
│       ├── main.py             # FastAPI entrypoint & static mount
│       ├── api/
│       │   └── routes.py       # REST API route handlers
│       ├── core/
│       │   └── database.py     # SQLite engine & session management
│       ├── models/
│       │   └── entities.py     # SQLAlchemy ORM models
│       ├── services/
│       │   ├── geoip.py        # MaxMind / DB-IP enrichment
│       │   └── report_generator.py # 12-Section JSON & ReportLab PDF engine
│       ├── ml/
│       │   ├── features.py     # 9-vector feature extraction
│       │   ├── detector.py     # Isolation Forest wrapper
│       │   ├── risk.py         # Composite 4-vector risk evaluation
│       │   ├── generator.py    # Multi-model synthetic dataset generator
│       │   ├── registry.py     # ML model registry & versioning
│       │   └── pipeline.py     # End-to-end training & scoring pipeline
│       ├── graph/
│       │   └── network.py      # NetworkX graph analysis & synopsis
│       └── ingestion/
│           └── loader.py       # CSV dataset ingestion & normalization
│
├── frontend/
│   ├── index.html              # Single-page workstation shell
│   ├── style.css               # Cyber-intelligence design system
│   └── app.js                  # SPA routing engine & view controllers
│
├── data/
│   ├── raw/
│   │   ├── bitcoin_traffic.csv # Standard benchmark dataset (3,000 TXs)
│   │   └── dataset_*.csv       # Generated dataset archive
│   └── geoip/
│       ├── dbip-country-lite.mmdb
│       └── dbip-asn-lite.mmdb
│
└── models/
    ├── wallet_anomaly_model.joblib # Trained Isolation Forest model
    └── risk_scoring_engine.json    # Calibrated risk weights & caps
```

---

## 7. Installation & Setup

### Prerequisites
* **macOS** (Apple Silicon or Intel) or **Linux** (x86_64 / aarch64)
* **Python 3.12+** (Conda recommended)
* **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/risshitm-imtb/trace-x.git
cd trace-x
```

### 2. Create & Activate Conda Environment
```bash
conda create -n tracex python=3.12 -y
conda activate tracex
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 8. Quick Start & Execution

### One-Click Launch (Recommended)
From the repository root:
```bash
./run.sh
```
*Auto-detects the Python Conda environment, terminates any stale processes on port `8000`, starts the Uvicorn server, and opens `http://127.0.0.1:8000` in your browser.*

### Manual Step-by-Step CLI Execution
If you prefer running pipeline stages individually:

```bash
# 1. Initialize SQLite Database
python -m backend.init_db

# 2. Ingest Benchmark Traffic Dataset
python -m backend.ingest

# 3. Train Isolation Forest Machine Learning Model
python -m backend.train_model

# 4. Generate Investigative Alerts & Risk Scores
python -m backend.generate_alerts

# 5. Launch FastAPI Server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open **`http://127.0.0.1:8000`** in your web browser.

---

## 9. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service operational health check |
| `GET` | `/api/system/health` | Complete system diagnostics (DB counts, ML model registry, runtime specs) |
| `GET` | `/api/overview` | High-level intelligence metrics, counts, and risk distribution |
| `GET` | `/api/alerts` | Prioritized high-risk entity alerts list |
| `GET` | `/api/wallets` | Full wallet registry with risk scores |
| `GET` | `/api/wallet/{address}` | Deep wallet dossier (4-vector dimensions, flows, counterparties, signals) |
| `GET` | `/api/transactions` | Paginated transaction ledger |
| `GET` | `/api/transaction/{txid}` | 3-column transaction flow topology, evidence, and network observations |
| `GET` | `/api/graph` | Global network graph nodes, edges, and synopsis statistics |
| `GET` | `/api/graph/focused` | Subgraph centered on a specific target wallet address |
| `GET` | `/api/datasets` | Repository archive of persisted datasets with metadata |
| `GET` | `/api/datasets/{id}/download` | Stream and download raw CSV file for a given dataset ID |
| `POST` | `/api/datasets/{id}/ingest` | Re-ingest and retrain active database using a historical dataset |
| `DELETE` | `/api/datasets/{id}` | Safely delete a generated dataset and its disk file |
| `POST` | `/api/ingest` | Ingest CSV file, load default benchmark, or generate fresh dataset |
| `GET` | `/api/sessions` | Audit trail of historical analysis sessions |
| `GET` | `/api/reports/dossier` | Structured 12-section JSON forensic investigation dossier |
| `GET` | `/api/reports/pdf` | Generate and download publication-grade ReportLab vector PDF |
| `GET` | `/api/ml/models` | Machine learning model registry metadata and signatures |

---

## 10. Data Integrity & Ethical Disclaimer

1. **Synthetic Investigation Data**: The included Bitcoin transaction datasets and network observation records are synthetically generated for research, testing, demonstration, and forensic tooling evaluation.
2. **Investigative Prioritization**: Risk scores and anomaly confidence ratings are algorithmic prioritization signals designed to assist human analysts. They do not constitute conclusive proof of illicit activity or legal evidence without independent verification.
3. **Offline Privacy**: TRACE-X operates completely offline without transmitting transaction queries or IP metadata to third-party tracking APIs.
