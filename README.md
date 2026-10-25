# ThreatTrail — SOC Analyst Investigation Platform

**GitHub Repository Link:** [https://github.com/marakiteferi/threat-trail-team](https://github.com/marakiteferi/threat-trail-team)

## 1. Video Presentation
**Watch the 5-Minute Demonstration Here:** 
[Insert Video Link - e.g., YouTube, Google Drive, or Loom URL]



## 2. Team Information
* **Mearg Mehari** — CTC-692-26
* **Sofoniyas Fikadu** — CTC-160-26
* **Kidus Girma** — CTC-3276-26 
* **Jedidiah melkamu** — CTC-4884-26
* **Maraki Teferi** — CTC-6496-26
---

## 3. Project Information

### Purpose
ThreatTrail is an interactive cybersecurity training platform designed to simulate Security Operations Center (SOC) investigations for Active Directory attacks. Instead of requiring heavy SIEM infrastructure, ThreatTrail pairs curated Windows Event log datasets (`JSONB`), Sigma detection rules, and Active Directory environment context with a guided forensic Q&A workbench. It provides junior analysts with a realistic, hands-on environment to hunt for active threats, reconstruct attack timelines, and receive immediate diagnostic feedback on their forensic accuracy without the overhead of deploying full virtual machines.

### Main Features
- **Automated Threat Curation:** The backend ingests raw, industry-standard Windows Event logs (like Mordor datasets), normalizes the telemetry, and automatically generates targeted forensic scenarios mapped to MITRE ATT&CK techniques.
- **SOC Investigation Workbench:** A dynamic frontend interface where analysts can filter raw telemetry, inspect decoded payload fields, and utilize "Click-to-Pivot" workflows to trace lateral movement and privilege escalation.
- **Evidence-Backed Grading:** Trainees must actively pin supporting key-evidence logs to validate their findings. The server tracks all attempts and hint usages to calculate a final score, preventing client-side score manipulation.
- **SOC Realism vs. Guided Mode:** Trainees can toggle between a Guided Mode that highlights suspicious event heuristics for onboarding, and a SOC Realism Mode that removes visual spoilers and forces analysts to sift through benign Active Directory background noise.
- **Incident Containment Playbooks:** Analysts conclude their investigations by selecting appropriate containment actions (e.g., isolating hosts or disabling compromised service accounts) for holistic incident response training.

---

## 4. Tech Stack

- **Frontend**: React 19, Vite 8, React Router v7, Axios, Lucide Icons
- **Backend**: Python 3.10+, FastAPI, SQLAlchemy, Pydantic
- **Database**: PostgreSQL (with `JSONB` for raw Windows Event payloads)

---

## 5. Architecture Overview

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

## 6. Prerequisites

- **Node.js**: v20.19+ or v22.12+
- **Python**: v3.10+
- **PostgreSQL**: v14+ running locally (or SQLite fallback for testing)

---

## 7. Quick Start (Under 5 Minutes)

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

## 8. Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `DATABASE_URL` | Yes | `postgresql://postgres:postgres@localhost:5432/threattrail` | SQLAlchemy database connection URL |
| `JWT_SECRET_KEY` | Yes | *(Must be set in `.env`)* | Secret key for signing JWT access tokens (min 32 chars) |
| `JWT_EXPIRE_MINUTES` | No | `120` | Token expiration window in minutes |
| `CORS_ORIGINS` | No | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed frontend origins |
| `VITE_API_URL` | No | `http://localhost:5050/api` | Backend API base URL consumed by Vite frontend |
| `VITE_ENABLE_DEMO_HELPER` | No | `true` | Enables the one-click demo credential banner on login pages |

---

## 9. Running Tests & Linting

```bash
# Run backend unit, smoke, and security tests
pytest

# Run frontend linter and production build check
npm --prefix threattrail-frontend run lint
npm --prefix threattrail-frontend run build
```

---

## 10. Project Structure

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

## 11. Known Limitations

- **Static Scenarios Only**: ThreatTrail does not ingest live logs or execute Sigma rules dynamically; all scenarios use pre-curated Windows Event logs.
- **Single-Node Rate Limiting**: Rate limiting is stored in process memory for local/demo simplicity.
- **Normalized Exact-Match Grading**: Answers are graded via case-insensitive normalized string comparison against configured answer keys.

---

## 12. Security Considerations

- **Server-Side Grading**: `correct_answer` values are never transmitted to the client prior to quiz submission.
- **Upload Protection**: Admin log uploads validate archive size, compression ratios, and file paths to prevent Zip-Bomb and Zip-Slip attacks.
- **Security Headers & Rate Limiting**: Responses include `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and brute-force rate limiting on authentication and grading endpoints.