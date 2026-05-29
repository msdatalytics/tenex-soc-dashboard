# TENEX SOC Dashboard 🛡️

A full-stack cybersecurity log analysis application built for the TENEX.AI take-home assessment.

## What it does

Upload ZScaler web proxy logs and get instant AI-powered threat analysis:
- Parses real ZScaler NSS JSON logs into structured data
- Detects anomalies with confidence scores
- Displays results in a SOC-style dashboard with charts and timelines
- Uses Claude AI to generate plain English threat summaries

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16, TypeScript, TailwindCSS, Recharts |
| Backend | Python 3.11, Flask, JWT Authentication |
| Database | PostgreSQL (via Docker) |
| AI Detection | Rule-based anomaly detection engine |
| AI Summary | Claude AI (Anthropic) |
| Deployment | Docker + Docker Compose |

## AI Approach

This application uses TWO layers of AI:

### Layer 1 — Rule-based Anomaly Detection
Deterministic rules trained on known threat patterns — same approach used in real SIEM systems like Google Chronicle. No hallucination risk.

| Rule | Trigger | Severity | Confidence |
|------|---------|----------|------------|
| High Request Volume | 5+ requests from same IP | HIGH | 0.60-0.95 |
| Suspicious Domain | Known malicious TLDs (.ru, .xyz, .tk, .pw, .top) | HIGH | 0.92 |
| Excessive Blocks | 3+ blocked requests from same IP | MEDIUM | 0.55-0.90 |
| Off-Hours Activity | Requests between 10PM-6AM | MEDIUM | 0.75 |

Each anomaly returns:

    {
      "type": "Suspicious Domain Access",
      "severity": "HIGH",
      "confidence": 0.92,
      "reason": "Request to suspicious domain: malware-site.ru",
      "source_ip": "192.168.1.15"
    }

### Layer 2 — Claude AI Threat Summary
After detection, Claude AI reads all findings and generates a plain English SOC analyst-style threat summary. Used in backend/services/ai_summary.py.

Why rule-based over pure LLM? Rule-based detection gives deterministic, explainable results with no hallucination risk — critical for security applications where false negatives have real consequences.

## Log Format Support

### Format 1 — Real ZScaler NSS JSON (Recommended)
Same format used in Google Chronicle SIEM. Each line is one JSON event:

    {"event":{"ClientIP":"192.168.1.15","action":"Blocked","datetime":"2026-05-26 08:13:45","hostname":"malware-site.ru","threatname":"Trojan.GenericKD","threatcategory":"Malware","threatseverity":"Critical","department":"Engineering","devicehostname":"JOHN-LAPTOP","user":"john.doe@company.com"},"sourcetype":"zscalernss-web"}

### Format 2 — Simplified CSV

    2026-05-26 10:32:11,192.168.1.15,john.doe,GET,example.com,ALLOW,200,Chrome

The parser auto-detects which format is uploaded.

## Quick Start

### Prerequisites
- Docker Desktop
- Node.js 18+
- Python 3.11+

### Option 1 — Docker (Recommended)

    git clone https://github.com/msdatalytics/tenex-soc-dashboard.git
    cd tenex-soc-dashboard
    echo "JWT_SECRET_KEY=tenex-secret-key-2026" > backend/.env
    echo "ANTHROPIC_API_KEY=your-key-here" >> backend/.env
    docker-compose up --build

Open browser at http://localhost:3000

### Option 2 — Manual Setup

Start PostgreSQL:

    docker-compose up db -d

Start Backend:

    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python3 app.py

Start Frontend:

    cd frontend
    npm install
    npm run dev

Open http://localhost:3000

## Login Credentials

    Email: analyst@tenex.ai
    Password: password123

## Sample Log Files
- sample_logs/zscaler_sample.json — Real ZScaler NSS JSON format (recommended)
- sample_logs/sample.log — Simplified CSV format

## Project Structure

    tenex-soc-dashboard/
    ├── backend/
    │   ├── app.py                      # Flask entry point
    │   ├── models.py                   # PostgreSQL models (SQLAlchemy)
    │   ├── parsers/
    │   │   └── zscaler_parser.py       # Auto-detecting log parser
    │   ├── services/
    │   │   ├── anomaly_detector.py     # Rule-based threat detection
    │   │   └── ai_summary.py          # Claude AI threat summary
    │   └── routes/
    │       ├── auth.py                 # JWT authentication
    │       ├── upload.py               # File upload (.log .txt .json)
    │       └── analysis.py            # Analysis + DB caching
    ├── frontend/
    │   ├── app/
    │   │   ├── page.tsx                # Login page
    │   │   ├── upload/page.tsx         # Upload page
    │   │   └── dashboard/page.tsx     # SOC dashboard
    │   └── services/api.ts             # API service layer
    ├── sample_logs/
    │   ├── zscaler_sample.json        # Real ZScaler NSS logs
    │   └── sample.log                 # CSV format logs
    ├── docker-compose.yml
    └── README.md

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|---------|------|-------------|
| POST | /api/auth/login | No | Login and get JWT |
| POST | /api/auth/register | No | Register user |
| POST | /api/upload | JWT | Upload log file |
| GET | /api/analyze/:file_id | JWT | Analyze file |

## Dashboard Features
- Claude AI threat summary in plain English
- Summary cards — total logs, unique IPs, blocked, anomalies
- Pie chart — ALLOW vs BLOCK ratio
- Bar chart — Top IPs by request volume
- Line chart — Request timeline
- Anomaly table — severity and confidence scores
- SOC Event Timeline — chronological threat events
- Parsed logs table — suspicious domains highlighted

## Deployment Note
Live deployment was explored via Railway and Vercel. Free tiers do not support full stack PostgreSQL hosting without a credit card. The application runs fully locally using Docker Compose with one command as documented above.

## Environment Variables

    JWT_SECRET_KEY=your-secret-key
    ANTHROPIC_API_KEY=your-anthropic-api-key
    DATABASE_URL=postgresql://tenex:tenex123@localhost:5432/tenex_soc
