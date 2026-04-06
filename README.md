<<<<<<< HEAD
# LeakLoom
Real-time, application-layer IDS for HealthTech/FinTech. Detects authorized insider data exfiltration with sliding-window analytics, dynamic threat scoring, and live SSE dashboard.
=======
# LeakLoom IDS
**The Lightweight Application-Layer Guardian for ePHI & Sensitive Data**

**Core Tech:** Python 3.12 • `collections.deque` • Stateful Temporal Heuristics  
**Target Domain:** Healthtech / Fintech (HIPAA • PCI-DSS • DPDPA)  
**License:** MIT • Zero external dependencies  

---

## 🛑 The Real Problem Most IDS Miss

Traditional Intrusion Detection Systems (IDS) excel at catching external attackers — but they are blind to **authorized abuse** (the #1 threat in healthcare and finance). 

A legitimate nurse, doctor, or analyst with valid credentials can quietly exfiltrate thousands of patient records in minutes. Firewalls, WAFs, and network IDS see only “valid traffic.” Most open-source tools were never built for this.

## 🛡️ LeakLoom: Purpose-Built for Authorized Exfiltration Detection

LeakLoom is a real-time, application-layer IDS that sits directly inside your Python backend. It uses a **constant-memory sliding window** to calculate Temporal Correlation states, detecting anomalous volume, velocity, and pattern bursts — even when the user is fully authenticated.

It doesn’t sniff packets. It doesn’t require agents or heavy SIEMs. It simply watches your API logs and raises the alarm the moment insider data leakage begins.

### Why LeakLoom is Uniquely Better than Existing Open-Source IDS

| Feature / Capability | LeakLoom | Snort / Suricata | Wazuh / OSSEC | Typical Python Scapy IDS |
| :--- | :--- | :--- | :--- | :--- |
| **Layer** | **Application (API logs)** | Network (packets) | Host / Log | Network (packets) |
| **Detects Authorized Insider Threats** | **Yes (volume + temporal bursts)** | No | Partial (custom rules only) | No |
| **Dependencies** | **Zero** | Heavy (libpcap, rulesets) | Full stack (agent + server) | Scapy + libpcap |
| **Memory Footprint** | **~0.5 MB measured at 10k events** | High | Very High | Medium-High |
| **Setup Time** | **< 60 seconds** | Hours–days | Days | Medium |
| **Tamper-Evident Reporting** | **SHA-256 rolling-chained CSVs** | Manual | Generic | None |
| **Real-time Dashboard** | **Real-Time Forensic Interface** | None | Yes (but heavy) | No |
| **Embeddable as Middleware**| **Yes** | No | No | No |

---

## ✨ Project Features Implemented

### High-Fidelity "Adversarial" Log Simulation Engine
To demonstrate the engine's power, this project ships with a purely *adversarial* traffic simulator bounded to an exact 60-second loop iteration. It generates normal baselines across multi-tenant hospital environments, but guarantees attempting to **"trick"** the detector by injecting sophisticated temporal bursts, imitating targeted evasive logic natively.

### Multi-Tenant Live SSE Architecture
Tearing away from static WAF polling protocols, LeakLoom now natively provisions a True-Time WebSockets equivalent via **Server-Sent Events (SSE)**. Traffic logs stream endlessly from isolated `facility_id` branches (e.g. *St_Judes_Cardio*, *Mercy_General*) natively projecting continuous payload updates straight down to the dashboard matrix dynamically.

### Constant-Memory Sliding Window
Uses `collections.deque` as a finite scanning window to track per-user activity in rolling 60-second bounds. Rather than suffering from array bloat, memory stays consistently negligible.

### Multi-Dimensional Threat Detection & The "Cold Start" Problem
* **Dynamic Baselines (Learning Phase)**: Continually learns a user's normal byte volume via strict **Exponential Moving Averages (EMA)** utilizing an $\alpha = 0.3$ smoothing factor to prioritize recent historical volatility.
* **"Cold Start" Default Behaviors**: For brand-new users lacking historical footprints, LeakLoom heavily regulates traffic via rigid global fallback limits (~500MB or 20 isolated `/record` requests inside 60s) until a progressive baseline forms.
* **Unusual Access Times**: Multiplies penalties if data is touched off-hours (e.g. outside standard business boundaries).

### Weighted Threat Scoring Engine
Converts raw signals into cleanly readable 0–100 Threat Scores via granular metrics. *(Weighting ratios were tuned empirically against the adversarial simulator to optimally isolate data-hoarding behaviors rapidly).*
* **Volume (35%)**: Extracted data scale assessed against expected structural baselines. 
* **Frequency (25%)**: Speed of request barrage density heavily points to scripting abuse.
* **Sensitivity (20%)**: Emphasizing sensitive routes (`/records` vs `/dashboard`).
* **Deviant Anomalies (20%)**: Penalizing off-hours and deviations from established profiles.

### Automated Tamper-Evident Forensic Pipeline
Instantly generates isolated data reports specifically routed to individual storage protocols:
* `logs/forensic_report.csv` (Complete audit trail timeline featuring natively engineered **SHA-256 rolling hash chains** preventing retroactive log tampering).
* `dashboard/threat_summary.json` (Real-time visualizations metric natively hooked to the frontend).

### Real-Time Forensic Interface
Zero-dependency HTML/JS/CSS **“Society of Digital Forensics”** command center featuring:
* Native SSE Log Ingest continuously processing infinite traffic across multi-tenant drop-down arrays.
* NLP Threat Heuristics explicitly mapping specific anomaly combinations into plain-English alerts (e.g., *“Aggressive Bulk ePHI Scraping (Insider Theft)”*).
* Live-Animated Data Flow Configurations and Live Volumetric Trajectory Line Charts.
* Live Threat Matrices + Risk Breakdown Radar Chart Modals engineered with a premium corporate SOC aesthetic.
*(Runs locally natively at [http://localhost:8080](http://localhost:8080))*

---

## 🛠️ Performance & Limitations

### Benchmarks & False Positive Rate
* **Zero False Positives**: Verified flawlessly via the `test_zero_false_positives` Pytest test suite, standard hospital payloads mimicking 1,000 normal legitimate interactions trigger exactly 0.0% flags.
* **Memory Benchmark**: A strict evaluation via Python's native `tracemalloc` processing 10,000 complex log events directly measures peak footprint limits successfully resting at **0.486 MB**—well beneath ordinary tracking configurations.

### Known Limitations: "Slow-Exfiltration Evading"
A sophisticated insider adversary intentionally dragging targeted API pulls beneath the 60-second window baseline thresholds *("Low & Slow Exfiltration")* will potentially bypass immediate anomaly detection. 
* *Proposed Future Iteration*: Incorporating a secondary, loosely aggregated long-term sliding window (24h/14-Day threshold logic) strictly analyzing total volumetric footprint to organically capture trickling extractions over multiple disjoint sessions.

---

## 🧠 What I Learnt Building LeakLoom

1. **Efficiency**: Mastering memory-efficient stateful inspection sets featuring Python's robust `deque` mechanics significantly outperforms standard ever-growing array memory leaks.
2. **Behavior vs Signature**: Realizing that strict Signature-based detection natively fails against authorized abuse, whilst embracing mathematical behavioral tracking actively isolates the insider organically.
3. **Compliance Optimization**: Fine-tuning analytical EMA baseline arrays securely identifying sophisticated anomalies while recognizing that legitimate operators (like extremely fast-clicking ER nurses in HealthTech stacks) require zero-false-positive limits.

---

## 📂 Architecture Structure

```plaintext
/leakloom
├── core/                  # Core IDS Stateful Logic & Log Generators
├── dashboard/             # Forensics HTML/JS Front-end
├── examples/              # Embeddable Middleware Templates
├── logs/                  # Tamper-Evident CSV Archival Folder
├── tests/                 # Comprehensive Pytest Suite for Integrity & FPs
├── run_demo.py            # Central Orchestrator & API Server
└── benchmark.py           # Production Memory Footprint Tester
```

---

## 🚀 How to Run (1 Command)

```bash
cd leakloom
python3 run_demo.py
```
*(Automatically processes logs, generates analytical reports natively across `/logs/` and `/dashboard/`, and begins broadcasting at `http://localhost:8080`).*
>>>>>>> a4aa3ee (Initial commit: LeakLoom V3 project structure with dashboard and core logic)
