<div align="center">

# 🛡️ AEGIS

**Unified AI Cyber Defense Platform**

Five cyber security tasks. One codebase. Fully integrated.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Tests](https://img.shields.io/badge/tests-10%20passed-brightgreen?style=flat-square)](#testing)

[Overview](#overview) · [Architecture](#architecture) · [Quickstart](#quickstart) · [Tasks](#tasks) · [API](#api-reference)

</div>

---

## Overview

AEGIS is a modular cyber security platform that consolidates five independent security primitives into a single, cohesive system. Each component is production-shaped: typed, tested, observable, and wired into a shared event bus and ML model registry.

Instead of five disconnected scripts, AEGIS demonstrates how **detection, analysis, and response** interoperate within a real architecture — the kind you would actually deploy to a Security Operations Center.

**What sets it apart:**

- **Event-driven** — every module emits structured events to a shared bus backed by SQLite with async pub/sub fan-out
- **Model registry** — SHA256-pinned artifacts with lazy loading and version tracking
- **Real ML, not toy demos** — trained on 86,000+ emails across 6 independent corpora
- **Zero-knowledge crypto** — the file-sharing server never sees plaintext or keys
- **Live dashboard** — dark-themed, real-time, severity-aware

---

## Architecture

```
                             ┌──────────────────────────────┐
                             │   Streamlit Dashboard        │
                             │   :8501  ·  dark ·  realtime │
                             └──────────────┬───────────────┘
                                            │  REST + WebSocket
                             ┌──────────────▼───────────────┐
                             │   FastAPI Gateway            │
                             │   :8000                      │
                             │   /api/phish                 │
                             │   /api/code/scan             │
                             │   /api/events                │
                             │   /vault/*                   │
                             │   /ws/events                 │
                             └──────────────┬───────────────┘
                                            │
        ┌───────────────┬───────────────────┼───────────────────┬───────────────┐
        │               │                   │                   │               │
  ┌─────▼─────┐  ┌──────▼──────┐  ┌─────────▼────────┐  ┌───────▼──────┐  ┌─────▼─────┐
  │ PacketEye │  │ PhishGuard  │  │  CodeSentinel    │  │  NetRadar    │  │ DropVault │
  │  Task 1   │  │   Task 2    │  │     Task 3       │  │   Task 4     │  │  Task 5   │
  └─────┬─────┘  └──────┬──────┘  └─────────┬────────┘  └───────┬──────┘  └─────┬─────┘
        └───────────────┴───────────────────┼───────────────────┴───────────────┘
                                            │
                             ┌──────────────▼───────────────┐
                             │   Event Bus                  │
                             │   SQLite + async pub/sub     │
                             └──────────────┬───────────────┘
                                            │
                             ┌──────────────▼───────────────┐
                             │   ML Model Registry          │
                             │   SHA256 manifest · lazy     │
                             └──────────────────────────────┘
```

---

## Tasks

| # | Task | Module | Approach |
|:-:|------|--------|----------|
| 1 | **Network Packet Analyzer** | `modules/packet_eye` | Flow reconstruction, beaconing detection, GBM risk scoring |
| 2 | **Phishing Awareness & Detection** | `modules/phish_guard` | 3-head ML ensemble + interactive awareness game |
| 3 | **Secure Code Assessment** | `modules/code_sentinel` | Inter-procedural AST taint analysis + lexical rules |
| 4 | **Network Intrusion Detection** | `modules/net_radar` | Isolation Forest + MITRE ATT&CK stage classifier |
| 5 | **Secure File Sharing** | `modules/drop_vault` | X25519 + AES-GCM zero-knowledge + HMAC one-time tokens |

### Task 2 — PhishGuard

Three independent signal heads, soft-voted into a single verdict:

| Head | Features | Model |
|------|----------|-------|
| **URL** | 22 lexical (entropy, hyphens, TLD, subdomain depth) | Logistic Regression |
| **Text** | Word 1–2 grams hashed to 262,144 buckets | SGD (modified Huber) |
| **Header** | Rules (spoofed sender, urgency, money) | Deterministic |

#### Cross-Corpus Evaluation

Trained on a merged corpus, evaluated on six independent sources:

| Dataset | Rows | Accuracy | Precision | Recall | F1 |
|---------|-----:|---------:|----------:|-------:|---:|
| CEAS 2008 | 39,154 | 0.963 | 0.939 | 0.998 | 0.968 |
| Enron | 29,719 | 0.982 | 0.972 | 0.991 | 0.981 |
| Ling | 2,859 | 0.966 | 0.836 | 0.978 | 0.901 |
| Nazario | 1,559 | 0.972 | 1.000 | 0.972 | 0.986 |
| Nigerian Fraud | 3,331 | 0.998 | 1.000 | 0.998 | 0.999 |
| SpamAssassin | 5,806 | 0.823 | 0.627 | 0.995 | 0.769 |

**Result:** 82–100% accuracy across six independent corpora — the model generalizes.

### Task 3 — CodeSentinel

Catches what regex cannot:

```python
x = input()      # line 1
eval(x)          # line 2 — data flow from source to sink
```

An AST taint tracker follows the user input from **source** (`input()`, `request.args`, `sys.argv`) through assignments, f-strings, subscripts, and function calls to reach dangerous **sinks** (`eval`, `os.system`, `cursor.execute`, `pickle.loads`).

Detected categories:
- Code execution (`eval`, `exec`)
- Command injection (`os.system`, `subprocess.*`)
- SQL injection (`cursor.execute` with concatenation)
- Insecure deserialization (`pickle.loads`, `yaml.load`)
- Weak crypto (MD5, SHA1, ECB mode)
- Hardcoded secrets (API keys, passwords, tokens)

### Task 4 — NetRadar

Two-model NIDS:

- **Isolation Forest** — unsupervised anomaly score in [0, 1] over 29 flow features
- **Gradient Boosting** — multi-class MITRE ATT&CK stage classifier (7 classes)

Ships 4 custom Suricata rules:

```
DNS Tunneling - TXT payload > 200 bytes   (sid:9000001)
SSH Brute Force - 8 attempts in 60s       (sid:9000002)
SYN Port Scan - 25 SYNs in 10s            (sid:9000003)
TLS SNI on suspicious TLD                 (sid:9000004)
```

Auto-block via `iptables` / `pfctl`, alerts via Telegram.

### Task 5 — DropVault

The server **never sees plaintext or the AES key**:

```
Client                          Server
  │                               │
  │ 1. Generate AES-256-GCM key   │
  │ 2. Encrypt file               │
  │ 3. Generate X25519 keypair    │
  │ ──── public key ─────────────►│
  │ 4. Derive shared secret       │
  │ 5. Wrap AES key under shared  │
  │ 6. Send ciphertext + wrapped  │
  │ ─────────────────────────────►│  stores ciphertext only
  │◄───── one-time HMAC token ────│  TTL-bound, single-use
```

Per-user access anomalies detected via **EWMA + z-score** — no global model training required.

---

## Quickstart

### Prerequisites

- Python **3.10+**
- Windows · macOS · Linux
- Optional: `tcpdump`/`tshark` (Task 1), `iptables` (Task 4 auto-block)

### Install

```bash
git clone https://github.com/pradheepa73/CODSOFT_TASKS.git aegis
cd aegis

python -m venv .venv
.\.venv\Scripts\Activate.ps1         # Windows
# source .venv/bin/activate          # macOS / Linux

pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
```

### Prepare data

Place the merged phishing dataset at `data/phishing_email.csv` with columns `text` and `label`.

For multi-source training, place the six sub-corpora in `data/sources/`:
```
CEAS_08.csv · Enron.csv · Ling.csv
Nazario.csv · Nigerian_Fraud.csv · SpamAssasin.csv
```

### Train

```bash
# Single-source
python -m scripts.train_phish

# Multi-source
$env:AEGIS_MULTI_SOURCE = "1"        # Windows
export AEGIS_MULTI_SOURCE=1          # Unix
python -m scripts.train_phish

# Per-source evaluation
python -m scripts.evaluate_sources
```

### Run

Two terminals:

```bash
# Terminal 1 — API
uvicorn aegis.api.main:app --port 8000
```

```bash
# Terminal 2 — Dashboard
streamlit run aegis/dashboard/app.py --server.port 8501
```

Open **http://localhost:8501**.

Optional — seed demo events:
```bash
python -m scripts.seed_demo
```

---

## Testing

```bash
python -m pytest -q
# ..........  [100%]
# 10 passed in 1.54s
```

| Area | Tests |
|------|-------|
| Event bus | Roundtrip, severity filter |
| URL features | Shape, IP detection, TLD flagging |
| Taint analysis | `eval(input())`, hardcoded secret, safe parameterized SQL |
| Vault tokens | Roundtrip, wrong file, expired |

Live API smoke test:
```bash
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
```

---

## API Reference

| Method | Endpoint | Purpose |
|:------:|----------|---------|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/api/events` | Recent events (filterable) |
| `GET` | `/api/stats` | Event counts by severity |
| `POST` | `/api/phish` | Phishing verdict for email |
| `POST` | `/api/code/scan` | Static + taint scan |
| `POST` | `/vault/upload` | Upload encrypted blob |
| `POST` | `/vault/share/{id}` | Create one-time link |
| `GET` | `/vault/download/{id}` | Download via signed token |
| `WS` | `/ws/events` | Live event stream |

### Example

```bash
curl -X POST http://localhost:8000/api/phish \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: verify your account at http://paypa1-verify.tk/login"}'
```

```json
{
  "is_phishing": true,
  "score": 0.9812,
  "breakdown": { "url": 0.9421, "text": 0.9987, "header": 0.3000 },
  "signals": ["Urgency language: urgent, verify"]
}
```

---

## Project Layout

```
aegis/
├── aegis/
│   ├── config.py
│   ├── core/
│   │   ├── events.py             # EventBus + SQLite + pub/sub
│   │   └── ml_registry.py        # SHA256-pinned model loading
│   ├── modules/
│   │   ├── packet_eye/           # Task 1
│   │   ├── phish_guard/          # Task 2
│   │   ├── code_sentinel/        # Task 3
│   │   ├── net_radar/            # Task 4
│   │   └── drop_vault/           # Task 5
│   ├── api/main.py               # FastAPI gateway
│   └── dashboard/                # Streamlit UI
├── scripts/                      # trainers + utilities
├── tests/                        # pytest suite
├── docs/                         # architecture · task mapping
├── models/                       # trained artifacts (gitignored)
├── data/                         # datasets (gitignored)
└── reports/                      # generated reports
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **SQLite for events** | Zero infra, single file, swappable for Postgres |
| **Async pub/sub** | Slow consumers drop events instead of blocking producers |
| **SHA256-pinned models** | Detects stale or tampered artifacts at load time |
| **HashingVectorizer** | O(1) memory, ~15× faster on 80k+ documents |
| **AST taint over regex** | Regex cannot track `x = input(); eval(x)` across lines |
| **X25519 over RSA** | 32-byte keys, constant-time, fast |
| **EWMA + z-score** | Per-user anomaly baseline without global training |
| **5-step dark elevation** | SOC ergonomics; severity colors pop against navy-black |

---

## Acknowledgments

Built for the **CodSoft Cyber Security Internship** (2026).

Datasets:
- [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) — merged corpus of CEAS 2008, Enron, Ling, Nazario, Nigerian Fraud, and SpamAssassin

Inspiration:
- MITRE ATT&CK framework
- OWASP Top 10

---

## 👤 Author

<div align="center">

**Pradheepa M**  
*Cybersecurity Enthusiast*

[![GitHub](https://img.shields.io/badge/GitHub-pradheepa73-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/pradheepa73)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Pradheepa-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/pradheepa-m-051728372)

</div>

---

<div align="center">
<sub>Built with precision. Tested against reality.</sub>
</div>
```
