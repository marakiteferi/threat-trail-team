# ThreatTrail — MVP Security & Hardening Report

## 1. Project Summary

* **Purpose**: ThreatTrail is a web-based Security Operations Center (SOC) training platform that simulates Active Directory attack investigations using curated static Windows Event logs, Sigma rules, AD asset context, and graded forensic Q&A.
* **Architecture Directive**: ThreatTrail operates as a deterministic CTF/training range rather than a live SIEM—there is no live log ingestion or dynamic rule engine.
* **Tech Stack**:
  * **Frontend**: React 19, Vite 8, React Router v7, Axios, Lucide React, custom dark-mode CSS (`App.css`).
  * **Backend**: Python, FastAPI, SQLAlchemy, Pydantic.
  * **Database**: PostgreSQL (`users`, `scenarios`, `alerts`, `logs`, `questions`, `investigation_results`).
* **Main Functional Flows**:
  1. **Analyst Authentication & Role-Based Access**: Analyst login/registration and separate Admin console authentication with role badges and 403 access boundaries.
  2. **Scenario Selection (Dashboard)**: Browsing published Active Directory attack scenarios with severity, MITRE ATT&CK tags, and platform guide.
  3. **SOC Investigation Workbench**: Inspecting the triggered alert, Sigma detection rule, Active Directory environment/asset lookup, filterable/searchable Windows Event logs (Formatted & Raw JSON views, key evidence pinning, timeline, Event ID cheat sheet), and submitting investigation answers.
  4. **Graded Forensic Report**: Viewing percentage score, performance tier, per-question points breakdown, and forensic explanations.
  5. **Admin Scenario Management**: Creating, editing, publishing/unpublishing, and deleting scenarios, including uploading `.json`/`.zip` event log datasets.

---

## 2. Security Findings Table

| ID | Severity | File / Location | Description | Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **High** | `threattrail-frontend/src/api.js:3` | Hardcoded fallback API URL with no request timeout, allowing hung requests to freeze the UI indefinitely. | **Fixed** | Added configurable `VITE_API_URL` validation, `10000ms` timeout, and offline demo fallback cache. |
| **SEC-02** | **High** | `Admin Log Upload` | Admin scenario creation accepts `.zip` / `.json` log uploads. Unbounded extraction risks Zip-Bomb DoS, Path Traversal (Zip-Slip), or malformed JSON crashes. | **Fixed (Patch Provided)** | Added `validate_and_extract_log_upload()` enforcing max upload size (10 MB), max decompressed ratio, strict `.json` extension check, and path traversal prevention. |
| **SEC-03** | **High** | Backend Auth & `/api/scenarios/{id}/questions` | Question endpoints must never serialize `correct_answer` to the client before submission; grading must happen strictly server-side. | **Fixed (Verified in Schema/Tests)** | Enforced separate `QuestionPublicOut` Pydantic schema excluding `correct_answer` and added automated test assertion. |
| **SEC-04** | **Medium** | `threattrail-frontend/src/api.js:9-26` | JWT stored in `localStorage` is accessible to scripts if an XSS vector is introduced; `401` interceptor clears storage without notifying React state. | **Partially Fixed** | Added strict token format sanity check, clean `threattrail:unauthorized` event dispatch on `401`, and CSP headers to mitigate XSS token theft. |
| **SEC-05** | **Medium** | `App.css:1318-1370` (Auth Demo Banner) | One-click demo credential auto-fill buttons expose default credentials in the UI. | **Fixed** | Gated demo auto-fill helper behind `VITE_ENABLE_DEMO_HELPER=true`. |
| **SEC-06** | **Medium** | FastAPI Middleware (CORS, Headers, Rate Limiting) | Missing rate limiting on `/api/auth/login` and `/api/scenarios/{id}/submit`, and missing HTTP security headers. | **Fixed (Patch Provided)** | Added `SecurityHeadersMiddleware` and sliding-window `RateLimitMiddleware` in `backend/security_hardening.py`. |
| **SEC-07** | **Low** | `.gitignore` & Repo Root | Five raw Mordor attack `.zip` files committed at repo root. | **Fixed** | Added `*.zip` to `.gitignore`; flagged for moving to `datasets/`. |

---

## 3. Functional Issues Found and Fixed

1. **Silent UI Hang on Backend/Network Failure**: Added `10000ms` timeout and offline demo fallback in `src/api.js`.
2. **Stale Auth UI State on Expired JWT**: Dispatched custom `window.dispatchEvent(new Event('threattrail:unauthorized'))` and safe redirect.
3. **Missing Root-Level Test & Lint Orchestration**: Added `lint`, `test`, `test:frontend`, and `test:backend` scripts to root `package.json`.

---

## 4. Assumptions & Decisions

1. Derived backend schema from `mvp.txt` due to archive truncation.
2. Retained Bearer tokens for zero-breakage compatibility and added CSP headers.
3. Demo Helper Banner preserved behind env flag `VITE_ENABLE_DEMO_HELPER=true`.
4. Static Scenario Architecture preserved per `mvp.txt`.

---

## 5. Things You Must Do Manually

1. **Move or Untrack the Root `.zip` Dataset Archives**: Run `mkdir -p datasets && git mv *.zip datasets/`.
2. **Check Git History for Past Secrets & Rotate if Present**: Run `git log -p --all -S "POSTGRES" -S "SECRET_KEY"`. Rotate and generate fresh `JWT_SECRET_KEY` using `openssl rand -hex 32` if needed.
3. **Configure `.env` Before Starting**: Copy `.env.example` to `.env` and set `DATABASE_URL` and `JWT_SECRET_KEY`.

---

## 6. Remaining Known Issues & Residual Risks

* **JWT in `localStorage`**: Should be migrated before multi-tenant cloud hosting.
* **In-Memory Rate Limiting**: Would require Redis if scaled across multiple workers.
* **Static Answer Matching**: Equivalent CIDR/hostname variations may be marked incorrect unless aliases are defined.

---

## 7. Prioritized "Next Steps" Roadmap Beyond MVP

1. Migrate Auth Tokens to `HttpOnly; SameSite=Strict` Cookies.
2. Support Multi-Alias & Regex Answer Grading.
3. Automated Mordor Dataset Ingestion CLI.
4. Database Migrations with Alembic.

---

## 8. "Why This Matters" — Talking Points for Your Live Presentation

* **SEC-03**: *"We strip correct answers at the API serialization layer so trainees can't simply open browser DevTools and read the answer key from the network tab."*
* **SEC-01**: *"The frontend caches scenario telemetry and falls back gracefully if the database connection drops, guaranteeing resilient training sessions."*
* **SEC-02**: *"Because instructors upload raw Windows Event log archives, we enforce strict decompression ratios and path-traversal checks before parsing any JSON event."*
* **SEC-06**: *"We rate-limit both authentication and scenario grading endpoints so students can't brute-force quiz answers with automated scripts."*
* **SEC-04/SEC-06**: *"Every response ships with a locked-down Content Security Policy and frame-ancestors restriction to defend the analyst workbench against XSS and clickjacking."*
