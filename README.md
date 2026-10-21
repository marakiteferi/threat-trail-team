# ThreatTrail — SOC Analyst Investigation Platform

ThreatTrail is an interactive cybersecurity training platform designed to simulate Security Operations Center (SOC) investigations for Active Directory attacks. Instead of requiring heavy SIEM infrastructure, ThreatTrail pairs curated Windows Event log datasets (`JSONB`), Sigma detection rules, and Active Directory environment context with a guided forensic Q&A workbench.

---

## Key Features

* **SOC Investigation Workbench**: Searchable, filterable Windows Event log viewer with Formatted & Raw JSON inspection, one-click IOC copying, key evidence pinning, and attack timeline reconstruction.
* **Contextual Threat Intelligence**: Built-in Sigma detection rule viewer, Active Directory user/host/group lookup, and Windows Event ID cheat sheet.
* **Automated Forensic Grading**: Server-side grading with weighted points, performance tiers, and per-question forensic explanations.
* **Admin Scenario Studio**: Role-protected instructor console to create, edit, draft/publish scenarios, and upload `.json`/`.zip` event log bundles.
* **Offline Demo Resilience**: Built-in client fallback dataset ensures live demos work seamlessly even without network connectivity.

---

## Tech Stack

* **Frontend**: React 19, Vite 8, React Router v7, Axios, Lucide Icons
* **Backend**: Python 3.10+, FastAPI, SQLAlchemy, Pydantic
* **Database**: PostgreSQL (with `JSONB` for raw Windows Event payloads)

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph Client ["Frontend (React 19 + Vite)"]
        UI["Dashboard / SOC Workbench / Report"]
        API["Axios Client + Offline Demo Fallback"]
        UI --> API
    end

    subgraph Server ["Backend (FastAPI + SQLAlchemy)"]
        MW["Security Headers + Rate Limiter + CORS"]
        AUTH["JWT Auth & RBAC (Analyst / Admin)"]
        ROUTES["Scenario, Log & Grading Endpoints"]
        MW --> AUTH --> ROUTES
    end

    subgraph DB ["Database (PostgreSQL)"]
        PG[("users | scenarios | alerts\nlogs (JSONB) | questions | results")]
    end

    API -- "REST JSON (Bearer JWT)" --> MW
    ROUTES --> PG
```

---

## Prerequisites

* **Node.js**: v20.19+ or v22.12+
* **Python**: v3.10+
* **PostgreSQL**: v14+ running locally (or SQLite fallback for testing)

---

## Quick Start (Under 5 Minutes)

### 1. Clone & Configure Environment
```bash
cp .env.example .env
# Edit .env with your local PostgreSQL connection string and a fresh JWT_SECRET_KEY
```

### 2. Backend Setup & Database Seed
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python seed.py
uvicorn main:app --host 0.0.0.0 --port 5050 --reload
```

### 3. Frontend Setup & Run
```bash
npm --prefix threattrail-frontend install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `DATABASE_URL` | Yes | `postgresql://postgres:postgres@localhost:5432/threattrail` | SQLAlchemy database connection URL |
| `JWT_SECRET_KEY` | Yes | *(Must be set in `.env`)* | Secret key for signing JWT access tokens (min 32 chars) |
| `JWT_EXPIRE_MINUTES` | No | `120` | Token expiration window in minutes |
| `CORS_ORIGINS` | No | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed frontend origins |
| `VITE_API_URL` | No | `http://localhost:5050/api` | Backend API base URL consumed by Vite frontend |
| `VITE_ENABLE_DEMO_HELPER` | No | `true` | Enables the one-click demo credential banner on login pages |

---

## Running Tests & Linting

```bash
# Run backend unit, smoke, and security tests
pytest

# Run frontend linter and production build check
npm --prefix threattrail-frontend run lint
npm --prefix threattrail-frontend run build
```

---

## Project Structure

```text
threat-trail/
├── threattrail-frontend/       # React 19 + Vite SPA
│   ├── src/
│   │   ├── api.js              # Axios client, auth interceptors & offline fallback
│   │   ├── App.css             # Dark theme & SOC workbench styles
│   │   ├── App.jsx             # Router & auth state layout
│   │   └── pages/              # Dashboard, Investigation, Report, Login, Admin
│   ├── package.json
│   └── vite.config.js
├── seed.py                     # Populates initial AD attack scenarios (e.g. T1110.003)
├── main.py                     # FastAPI entry point & route definitions
├── security_hardening.py       # Env validation, rate limiting, security headers, safe uploads
├── tests/                      # Automated API & security test suite
├── DEMO.md                     # 3-5 minute live demo script & Q&A prep
├── MVP_REPORT.md               # Security audit & hardening report
├── SECURITY.md                 # Vulnerability reporting policy
└── .env.example                # Template environment configuration
```

---

## Known Limitations

* **Static Scenarios Only**: ThreatTrail does not ingest live logs or execute Sigma rules dynamically; all scenarios use pre-curated Windows Event logs.
* **Single-Node Rate Limiting**: Rate limiting is stored in process memory for local/demo simplicity.
* **Normalized Exact-Match Grading**: Answers are graded via case-insensitive normalized string comparison against configured answer keys.

---

## Security Considerations

* **Server-Side Grading**: `correct_answer` values are never transmitted to the client prior to quiz submission.
* **Upload Protection**: Admin log uploads validate archive size, compression ratios, and file paths to prevent Zip-Bomb and Zip-Slip attacks.
* **Security Headers & Rate Limiting**: Responses include `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and brute-force rate limiting on authentication and grading endpoints.
