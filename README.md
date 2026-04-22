# EDR — Early Ransomware Detection System

> A production-grade Behavioural Endpoint Detection & Response (EDR) system
> built in Python. Suitable for internship portfolios, placements, and
> real-world deployment.

---

## Architecture

```
edr_system/
│
├── core/
│   ├── security_event.py     # Unified event data model (all detections)
│   └── logger.py             # Centralised logging config
│
├── features/
│   └── feature_extractor.py  # Per-IP traffic stats from live packets
│
├── detection/
│   ├── detector.py           # Rule-based + IOC network analysis
│   └── correlator.py         # Multi-signal correlation + incident grouping
│
├── ml/
│   └── anomaly_model.py      # Isolation Forest anomaly detection
│
├── monitoring/
│   ├── file_monitor.py       # Watchdog file system monitor
│   └── process_monitor.py    # psutil process behaviour monitor
│
├── threat_intel/
│   └── ioc_checker.py        # IP threat intelligence / IOC lookup
│
├── response/
│   └── response_engine.py    # Simulated block_ip / kill_process / quarantine
│
├── dashboard/
│   └── dash_ui.py            # Dash SOC dashboard (auto-refreshes every 5s)
│
├── capture/
│   └── capture_packets.py    # Live packet capture — main pipeline loop
│
├── run_project.py            # Master launcher
├── requirements.txt
└── README.md
```

---

## Detection Pipeline

```
Live Packet
    │
    ▼
Feature Extractor  ─── per-IP stats (rate, size, protocols)
    │
    ▼
Rule Engine  ───────── high rate / large packets / suspicious proto
    │
    ├──► IOC Checker ─ match against known-bad IPs → score boost
    │
    ├──► ML Model ──── Isolation Forest anomaly score
    │
    ├──► File Monitor ─ mass changes / ransomware extensions
    │
    └──► Proc Monitor ─ vssadmin / bcdedit / CPU burst
           │
           ▼
       Correlator  ──── weighted multi-signal score → severity
           │
           ▼
      Response Engine ── block_ip / kill_process / quarantine_file
           │
           ▼
      SOC Dashboard  ──── live Dash UI at http://127.0.0.1:8050
```

---

## Detection Features

| Layer | Rule | MITRE |
|-------|------|-------|
| Network | High packet rate (>20/s) | T1046 |
| Network | Large avg packet size (>1000B) | T1041 |
| Network | TLS/SSL/QUIC traffic | T1071.001 |
| Network | IOC threat intel match | T1071 |
| File | Mass file modifications (≥20/min) | T1486 |
| File | Ransomware extensions (.locked, .enc…) | T1486 |
| Process | Ransomware CLI (vssadmin, bcdedit…) | T1059 |
| Process | Script host in TEMP/AppData | T1059 |
| Process | Process spawn burst (>6 in 5s) | T1059 |
| Process | Abnormal CPU usage (>40%) | T1486 |

---

## Correlation Severity Rules

| Signals triggered | Severity |
|---|---|
| 3 (network + file + process) | **CRITICAL** |
| 2 any combination | **HIGH** |
| 1 | **MEDIUM** |
| 0 | CLEAN |

Weighted scoring: network=3, file=4, process=5

---

## Bonus Features Implemented

- **Host risk scoring** — cumulative risk per IP tracked over time
- **Behaviour stabilisation** — risk score decays after 5 clean cycles
- **Incident grouping** — events within 15 minutes grouped under one `INC-*` ID
- **Risk heatmap** — visual host risk in dashboard
- **Timeline tracking** — incident open time + event count

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure network interface

Edit `capture/capture_packets.py` and set `INTERFACE`:

```python
# Windows example:
INTERFACE = r"\Device\NPF_{YOUR-GUID-HERE}"

# Linux / macOS:
INTERFACE = "eth0"
```

Find your interface name in **Wireshark → Capture → Interfaces**.

### 3. Run dashboard only (no capture required)

```bash
python run_project.py --dashboard
```

Open `http://127.0.0.1:8050`

### 4. Run the full system

```bash
# Windows — run as Administrator (required for packet capture)
python run_project.py

# Linux
sudo python run_project.py
```

### 5. Simulate alerts (test without live traffic)

```bash
python generate_real_alerts.py
```

---

## Log Files

| File | Contents |
|------|----------|
| `logs/system.log` | All structured detection events |
| `logs/file_system.log` | File create/modify/delete events |
| `logs/process_system.log` | Process behaviour alerts |
| `logs/response_actions.log` | All automated response actions |

---

## SecurityEvent Schema

Every detection returns a `SecurityEvent` with:

```python
{
    "timestamp":       "2024-01-01 12:00:00",
    "source":          "network | file | process",
    "event_type":      "network_behavior_anomaly | ...",
    "host":            "192.168.1.5",
    "user":            "SYSTEM",
    "mitre_technique": "T1486",
    "tactic":          "Impact",
    "impact":          8,            # 1–10
    "confidence":      85.0,         # %
    "risk_score":      6.8,          # impact × (confidence/10)
    "severity":        "HIGH",       # LOW | MEDIUM | HIGH | CRITICAL
    "details":         { ... }       # raw evidence dict
}
```

---

## Interview Talking Points

### Why Isolation Forest?
- Unsupervised — no labelled ransomware dataset required
- Learns "normal" baseline from the first 20 packets
- Efficient on high-dimensional feature vectors
- Low false-positive rate at contamination=0.03

### Why multi-signal correlation?
- Ransomware triggers multiple independent signals simultaneously
- Combining network + file + process reduces single-source false positives
- Weighted scoring reflects realistic threat impact (process = highest weight)

### Why behaviour-based detection?
- Signature-based AV misses novel/polymorphic ransomware
- Ransomware behaviour (mass file rename, C2 contact, vssadmin) is invariant
- Detects at pre-encryption stage (network C2) — earlier than file-level tools

### MITRE ATT&CK mapping
- T1486 — Data Encrypted for Impact (ransomware hallmark)
- T1041 — Exfiltration Over C2 Channel
- T1059 — Command and Scripting Interpreter
- T1071 — Application Layer Protocol (C2 communication)

---

## Author

Sanchita Kulkarni  
Email: sanchitakulkarni28@gmail.com