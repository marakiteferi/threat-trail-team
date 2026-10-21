# ThreatTrail — Live Demo Kit (3–5 Minute Script)

## Pre-Demo Checklist (2 Minutes Before Going Live)
1. Ensure PostgreSQL is running and seeded (`python seed.py`).
2. Start backend (`uvicorn main:app --port 5050`) and frontend (`npm run dev`).
3. Open `http://localhost:5173` in a clean browser tab (zoom set to `110%` for projector readability).
4. Verify the green **LIVE** indicator pulse in the top header.

---

## 3–5 Minute Step-by-Step Demo Script

### Minute 0:00 – 0:45 | The Problem & Dashboard Overview
1. **Land on the Dashboard (`/`)**: Point out the Hero banner, active scenario count, and the **Platform Guide**.
2. **Click "How ThreatTrail Works"** toggle (`.db-guide-toggle-btn`) briefly to show the 3-step CTF workflow and Windows Event ID quick reference (`4625` Failed Logon, `4624` Successful Logon).
3. **Say out loud**: *"Junior SOC analysts often jump straight into complex SIEMs without understanding raw Windows Active Directory telemetry. ThreatTrail is a deterministic SOC training range where analysts investigate real attack traces—like Password Spraying, DCSync, and PsExec LSA dumps—and get instant forensic feedback."*

### Minute 0:45 – 1:30 | Authentication & Role Separation
1. Click a locked scenario card (`db-start-btn-locked`) to trigger the redirect to `/login`.
2. On the **Login** page, click the **Auto-fill Demo Analyst** button (`.demo-fill-btn`) and sign in.
3. Point out the **Analyst Role Badge** in the top-right header.

### Minute 1:30 – 3:30 | Core Investigation Workbench (Password Spraying — `T1110.003`)
1. From the Dashboard, click **Start Investigation** on **Password Spraying** (`MITRE T1110.003`).
2. **Top Alert Banner & Sigma Rule**:
   * Highlight the **High Severity: Possible Password Spraying** banner.
   * Click **View Sigma Rule** (`.inv-sigma-btn`) to show the detection logic that triggered the alert, then collapse it.
3. **Active Directory Environment Context**:
   * Click the **Active Directory Environment & Asset Lookup** bar (`.inv-ad-toggle-bar`) to inspect domain users, groups, and lockout policy.
4. **Smart Filtering & Log Inspection**:
   * In the **Windows Event Logs** panel, point out the 15 `Event 4625` (Failed Logon) rows in red followed by 1 `Event 4624` (Successful Logon) row in green.
   * Click the **Event ID `4625`** filter chip, then click **`4624`** (or toggle **Key Evidence**).
   * Click the `4624` log row to expand the **Log Inspector**. Switch between the **Formatted** tab and **Raw JSON** tab, and click the **Copy** chip next to the attacker Source IP.
   * Click the **Pin** icon (`.inv-pin-btn`) on the `4624` event to mark it as key evidence.

### Minute 3:30 – 4:30 | Submitting Findings & Forensic Report
1. In the right-hand **Investigation Q&A Panel**, enter the sample answers below:
   * **Q1 (What is the source IP?)**: `192.168.1.200` (or the IP copied from the `4624` log inspector)
   * **Q2 (Which account was successfully compromised?)**: `jdoe` (or the target username shown on the `4624` row)
   * **Q3 (What is the MITRE technique ID?)**: `T1110.003`
2. Observe the progress bar reach **100%** and click **Submit Investigation**.
3. **Report View (`/report`)**:
   * Highlight the animated SVG score ring, performance tier badge, per-question point pills, and the **Forensic Explanation Box** under each question.

---

## Reliable Sample Inputs

| Field / Context | Sample Input | Expected Behavior |
| :--- | :--- | :--- |
| **Log Search Bar** | `4624` | Filters table immediately to the successful logon event. |
| **Log Search Bar** | `4625` | Filters table to the 15 failed password spray attempts. |
| **Question 1 (Source IP)** | Copy directly from `Source IP` code pill in Log Inspector | Exact match; whitespace is trimmed automatically. |
| **Question 2 (Compromised Account)** | Copy `TargetUserName` from the `4624` event row | Case-insensitive match. |
| **Question 3 (MITRE Technique ID)** | `T1110.003` | Matches Password Spraying sub-technique. |

---

## Offline / Network Failure Fallback Plan

If PostgreSQL or the FastAPI process crashes during the live demo:
1. **Automatic Frontend Fallback**: The hardened `src/api.js` interceptor catches `ECONNABORTED` / network errors and automatically serves the built-in **Password Spraying (`T1110.003`)** scenario, alert, 16 Windows Event logs (`15x 4625` + `1x 4624`), and local grading fallback.
2. **Manual Toggle**: Set `localStorage.setItem('threattrail_offline_demo', 'true')` in the browser console and refresh—the entire click-path from Dashboard -> Investigation -> Graded Report works 100% offline.

---

## 10 Likely Audience Questions & Short Answers

1. **Q: Is ThreatTrail ingesting live Windows Event logs from a Domain Controller?**
   * **A:** No—by design, ThreatTrail is a deterministic training range, not a live SIEM. Using curated static Mordor/AD JSON logs ensures every student investigates the exact same forensic artifacts with zero infrastructure overhead.
2. **Q: Where do the attack logs come from?**
   * **A:** They are curated from real Active Directory attack recordings (such as OTRF Security Datasets / Mordor) covering techniques like Password Spraying (`T1110.003`), DCSync (`DsGetNCChanges`), Mimikatz `logonpasswords`, and PsExec LSA secrets dumps.
3. **Q: Can students cheat by inspecting the API network responses in browser DevTools?**
   * **A:** No. The `/api/scenarios/{id}/questions` endpoint strips `correct_answer` before sending questions to the browser, and all grading happens server-side on `POST /api/scenarios/{id}/submit`.
4. **Q: How do instructors add new attack scenarios?**
   * **A:** Through the built-in Admin Console, where instructors can define scenario metadata, Sigma rules, questions with point weights, and upload JSON/ZIP event logs, then save as Draft or Publish live.
5. **Q: Why include Active Directory asset context and Sigma rules alongside the logs?**
   * **A:** Real SOC analysts don't investigate logs in a vacuum—they need to know why the alert fired (the Sigma rule) and which accounts or hosts are privileged (AD Asset Lookup).
6. **Q: What are the current limitations of this MVP?**
   * **A:** Grading currently relies on normalized exact-match strings rather than fuzzy/regex expressions, authentication uses `localStorage` Bearer tokens rather than `HttpOnly` cookies, and rate limiting is in-memory per process.
7. **Q: What would you build next if given another month?**
   * **A:** First, multi-alias/regex grading and hints with point deductions; second, `HttpOnly` cookie sessions with Alembic migrations; third, multi-stage kill-chain scenarios linking initial access to lateral movement and domain dominance.
8. **Q: How does the platform handle large log files or malicious uploads in the Admin panel?**
   * **A:** Uploads are restricted to authenticated admins and validated for file size, compression ratio (to block Zip-Bombs), path traversal, and strict JSON schema compliance before database insertion.
9. **Q: Why use PostgreSQL instead of Elasticsearch/OpenSearch?**
   * **A:** Since each training scenario uses 15 to 100 curated high-signal events rather than millions of raw logs, PostgreSQL with `JSONB` (`raw_event_data`) gives us relational integrity for grading and users plus flexible JSON storage in a single lightweight datastore.
10. **Q: Can this be used for university cybersecurity labs or SOC hiring assessments?**
    * **A:** Yes—because each scenario is self-contained and produces a deterministic score breakdown, instructors can use it for graded lab assignments or technical screening.

---

## Claims You Should NOT Make During the Presentation

* **Do NOT claim**: *"This is a live SIEM or EDR replacement."* (State clearly that it is a static, scenario-based SOC training simulator.)
* **Do NOT claim**: *"It is production-hardened for untrusted public multi-tenant deployment."* (State that it is a hardened MVP built for local/classroom lab environments.)
* **Do NOT claim**: *"It dynamically evaluates Sigma rules against uploaded logs."* (Sigma rules are displayed as educational reference context for the triggered alert.)
