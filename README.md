<div align="center">

# 🛡️ SENTRI

### `THREAT INTELLIGENCE SYSTEM`

**Detect • Analyze • Understand • Defend**

> A cybersecurity threat-analysis platform built to identify suspicious URLs and scam indicators through explainable, rule-based detection.

**STATUS:** 🟢 ONLINE &nbsp;&nbsp; | &nbsp;&nbsp; **ENGINE:** `RULE-X` &nbsp;&nbsp; | &nbsp;&nbsp; **MODE:** `LOCAL`

---

`Cybersecurity` • `Threat Detection` • `TypeScript` • `React` • `Node.js`

</div>

# ◈ SYSTEM OVERVIEW

The internet is full of links and messages that look legitimate.

Some aren't.

**Sentri** is a cybersecurity portfolio project designed to investigate suspicious digital content and expose the warning signs hidden underneath.

```text
SUSPICIOUS INPUT
       │
       ▼
┌─────────────────────┐
│   SENTRI ANALYZER   │
│      RULE-X         │
└──────────┬──────────┘
           │
           ▼
   THREAT INDICATORS
           │
           ▼
      RISK ENGINE
           │
     ┌─────┼─────┐
     ▼     ▼     ▼
    LOW  MEDIUM  HIGH
     │     │     │
     └─────┼─────┘
           ▼
 SECURITY RECOMMENDATION
```

---

# ◈ CORE MODULES

## 🔗 URL INTELLIGENCE

Sentri inspects URLs for patterns commonly associated with phishing, impersonation, and malicious links.

```text
URL RECEIVED
     │
     ├──► Domain Analysis
     ├──► URL Structure Analysis
     ├──► Keyword Detection
     ├──► Impersonation Detection
     └──► Risk Classification
```

Current checks include:

- URL shorteners
- Suspicious top-level domains
- IP-based URLs
- Excessive subdomains
- Punycode domains
- `@` symbol manipulation
- Nested URLs
- Suspicious paths and query parameters
- Brand impersonation patterns

---

## 💬 MESSAGE INTELLIGENCE

Scams often rely on social engineering rather than technical exploits.

Sentri analyzes suspicious messages for behavioral patterns commonly associated with phishing and fraud.

Examples include:

```text
⚠ URGENCY DETECTED
⚠ ACCOUNT THREAT DETECTED
⚠ SUSPICIOUS REQUEST
⚠ PHISHING LANGUAGE
⚠ SOCIAL ENGINEERING INDICATOR
```

The analyzer can detect patterns involving:

- Artificial urgency
- Account suspension threats
- Pressure to take immediate action
- Suspicious requests
- Phishing terminology
- Scam-related language

---

## 🧠 RULE-X ENGINE

At the center of Sentri is:

```text
╔══════════════════════════════╗
║          RULE-X              ║
║                              ║
║   EXPLAINABLE THREAT ENGINE  ║
║                              ║
║   MODE ............. LOCAL   ║
║   STATUS ........... ONLINE  ║
╚══════════════════════════════╝
```

**RULE-X** is Sentri's rule-based detection engine.

Rather than relying entirely on an external AI model, RULE-X evaluates predefined cybersecurity indicators.

This makes the detection process:

- Explainable
- Predictable
- Fast
- Local
- Easy to expand
- Independent from external AI APIs

Each detected indicator contributes to the final security assessment.

---

# ◈ THREAT CLASSIFICATION

Sentri converts detected indicators into an understandable risk assessment.

| Level | Classification | Meaning |
|:---:|:---|:---|
| 🟢 | **LOW** | Few or no suspicious indicators detected |
| 🟡 | **MEDIUM** | Multiple suspicious characteristics detected |
| 🔴 | **HIGH** | Strong phishing, scam, or malicious indicators detected |

A scan may produce results similar to:

```text
┌──────────────────────────────────────┐
│ SENTRI // THREAT REPORT              │
├──────────────────────────────────────┤
│                                      │
│ RISK SCORE       78 / 100            │
│ THREAT LEVEL     HIGH                │
│ ENGINE           RULE-X              │
│                                      │
│ FLAGS                                │
│                                      │
│ [!] Suspicious domain                │
│ [!] URL shortener detected           │
│ [!] Urgency language                 │
│ [!] Possible brand impersonation     │
│                                      │
├──────────────────────────────────────┤
│ RECOMMENDATION                       │
│                                      │
│ Avoid interacting with this content  │
│ until its legitimacy is verified.    │
└──────────────────────────────────────┘
```

---

# ◈ FEATURES

### 🛡️ Threat Analysis

- Suspicious URL scanning
- Scam message analysis
- Phishing indicator detection
- Explainable threat flags

### 📊 Risk Intelligence

- Numerical risk scoring
- Low / Medium / High classification
- Security recommendations
- Detection summaries

### 🕒 Scan Intelligence

- Recent scan history
- Scan activity tracking
- Security statistics
- History management

### 🖥️ Command Dashboard

- Threat intelligence interface
- System status monitoring
- RULE-X engine status
- Local analysis mode
- Responsive cybersecurity UI

---

# ◈ TECHNOLOGY STACK

```text
┌──────────────────────────────────────┐
│              SENTRI                  │
├──────────────────────────────────────┤
│                                      │
│ FRONTEND                             │
│ ├── React                            │
│ ├── TypeScript                       │
│ ├── Vite                             │
│ └── CSS                              │
│                                      │
│ BACKEND                              │
│ ├── Node.js                          │
│ ├── Express                          │
│ ├── TypeScript                       │
│ └── REST API                         │
│                                      │
│ SECURITY                             │
│ ├── URL Pattern Analysis             │
│ ├── Scam Pattern Detection           │
│ ├── Risk Classification              │
│ └── RULE-X Detection Engine          │
│                                      │
└──────────────────────────────────────┘
```

---

# ◈ PROJECT STRUCTURE

```text
sentri/
│
├── client/
│   │
│   └── src/
│       │
│       ├── components/
│       │   ├── Navbar/
│       │   ├── ScamAnalyzer/
│       │   ├── UrlScanner/
│       │   ├── ScanHistory/
│       │   └── ResultsCard/
│       │
│       ├── services/
│       ├── types/
│       ├── App.tsx
│       └── main.tsx
│
├── server/
│   │
│   └── src/
│       │
│       ├── routes/
│       ├── services/
│       ├── types/
│       └── server.ts
│
└── README.md
```

---

# ◈ INITIALIZE SENTRI

## 01 // Clone

```bash
git clone https://github.com/SeukallesX/sentri.git
cd sentri
```

## 02 // Frontend

```bash
cd client
npm install
npm run dev
```

## 03 // Backend

Open another terminal:

```bash
cd server
npm install
npm run dev
```

Once both systems are running:

```text
SENTRI INITIALIZATION

[✓] Frontend initialized
[✓] Backend initialized
[✓] RULE-X loaded
[✓] Threat engine ready

SYSTEM ONLINE
```

---

# ◈ API

Sentri's frontend communicates with its threat-analysis backend through a REST API.

### Analyze Content

```http
POST /api/analyze
```

Processes suspicious content and returns threat indicators, risk information, and security recommendations.

### Scan Intelligence

```http
/api/scan
```

Handles scan records and statistics.

### System Health

```http
GET /api/health
```

Checks the operational status of the Sentri backend.

---

# ◈ SCREENSHOTS

## 🖥️ Threat Intelligence Dashboard

> `// Screenshot Coming Soon`

## 🔗 URL Intelligence

> `// Screenshot Coming Soon`

## 💬 Message Analysis

> `// Screenshot Coming Soon`

## 🚨 Threat Report

> `// Screenshot Coming Soon`

---

# ◈ DEVELOPMENT ROADMAP

## `PHASE 01 // FOUNDATION`

- [x] Project architecture
- [x] React frontend
- [x] Express backend
- [x] TypeScript integration
- [x] REST API
- [x] Cybersecurity dashboard

## `PHASE 02 // RULE-X`

- [x] URL scanner
- [x] Message analyzer
- [x] Threat indicators
- [x] Risk scoring
- [x] Risk classification
- [x] Security recommendations

## `PHASE 03 // INTELLIGENCE`

- [x] Scan history
- [x] System status
- [ ] Domain reputation analysis
- [ ] Expanded phishing rules
- [ ] Threat categories
- [ ] Advanced impersonation detection
- [ ] Security statistics

## `PHASE 04 // THREAT NETWORK`

- [ ] External threat intelligence APIs
- [ ] Known malicious domain detection
- [ ] Domain reputation services
- [ ] Threat intelligence feeds
- [ ] Cross-source threat verification

## `PHASE 05 // HYBRID INTELLIGENCE`

- [ ] AI-assisted explanations
- [ ] Context-aware scam analysis
- [ ] Advanced pattern recognition
- [ ] Scam classification
- [ ] RULE-X + AI hybrid detection

---

# ◈ PROJECT OBJECTIVE

Sentri was built as more than a frontend demonstration.

The project explores how a complete cybersecurity system can move through the pipeline:

```text
COLLECT
   ↓
ANALYZE
   ↓
DETECT
   ↓
CLASSIFY
   ↓
EXPLAIN
   ↓
RESPOND
```

Through Sentri, the project demonstrates experience with:

- Cybersecurity fundamentals
- Threat analysis
- Phishing detection
- Scam detection
- URL intelligence
- Rule-based security systems
- Risk scoring
- Explainable detection
- React architecture
- TypeScript
- Node.js
- Express
- REST APIs
- Full-stack development
- Security-focused UI/UX
- Git & GitHub

---

# ◈ WHY SENTRI?

Security tools can generate warnings without explaining what caused them.

Sentri explores a different approach:

> **Detection should be understandable.**

The goal is to expose the indicators behind a security assessment so users can better understand what made a URL or message suspicious.

That makes Sentri both a cybersecurity application and an exploration of **explainable threat detection**.

---

# ⚠ SECURITY DISCLAIMER

Sentri is an educational cybersecurity and portfolio project.

It is **not** a replacement for:

- Professional antivirus software
- Enterprise security platforms
- Threat intelligence services
- Security professionals

A `LOW RISK` result does **not** guarantee that content is safe.

Do not submit passwords, authentication tokens, financial information, personally identifiable information, or other confidential data.

---

# 🤝 CONTRIBUTING

Ideas, suggestions, and contributions are welcome.

```bash
# Fork the repository

# Create a branch
git checkout -b feature/new-feature

# Commit your changes
git commit -m "Add new feature"

# Push your branch
git push origin feature/new-feature
```

Then open a pull request.

---

# 📄 LICENSE

This project is licensed under the **MIT License**.

---

<div align="center">

## 👤 DEVELOPER

### **Mariel Bravo**

Computer Science @ California State University, Fullerton

`AI` • `Blockchain` • `Cybersecurity`

---

### 🛡️ SENTRI

**Threats hide in plain sight. Sentri looks closer.**

`SYSTEM STATUS // ONLINE`

</div>

Computer Science @ California State University, Fullerton

Exploring AI • Blockchain • Cybersecurity
