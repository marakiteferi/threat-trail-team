# ThreatTrail Backend 🛡️⚙️

The core REST API and investigation engine for **ThreatTrail**, built with FastAPI and SQLAlchemy.

## Quick Start

### 1. Create & Activate Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Environment Variables
Copy `.env.example` to `.env`:
```bash
# Windows
Copy-Item .env.example .env

# Linux/macOS
cp .env.example .env
```
*(Defaults to local SQLite `threattrail.db` with no external database installation required).*

### 4. Database Setup & Seeding
```bash
# Seed default users (admin & analyst) and core scenarios
python seed.py

# (Optional) Ingest the 5 Mordor Active Directory attack archives
python seed_mordor_scenarios.py
```

### 5. Run API Server
```bash
uvicorn main:app --reload --port 5050
```

- API Base: `http://localhost:5050`
- Interactive API Docs (Swagger): [http://localhost:5050/docs](http://localhost:5050/docs)
- Alternative API Docs (ReDoc): [http://localhost:5050/redoc](http://localhost:5050/redoc)

## Default Accounts
- **Admin:** `admin` / `admin123`
- **Analyst:** `analyst` / `analyst123`

For full project documentation, see the root [README.md](../README.md).
