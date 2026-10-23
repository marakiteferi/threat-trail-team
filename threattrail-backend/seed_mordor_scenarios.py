#!/usr/bin/env python3
"""
seed_mordor_scenarios.py
Smart Signal-Preserving Ingestion for all 5 Mordor / OTRF Active Directory ZIP archives!
Instead of blindly slicing `lines[:120]` (which can miss the actual attack events if they
occur later in the recording), this script scans the ENTIRE archive, extracts all high-signal
security/attack events, and samples surrounding background logs up to `target_count` (350 logs)
sorted chronologically.
"""

import json
import zipfile
from pathlib import Path
from datetime import datetime
from database import SessionLocal
from models import Scenario, Alert, Log, Question, SeverityLevel
from main import extract_field_from_message

ROOT = Path(__file__).resolve().parent

# High-value Windows Security, System, PowerShell, and Sysmon Event IDs for sampling
PRIORITY_EVENT_IDS = {
    4624, 4625, 4648, 4662, 4672, 4688, 4697, 4698, 4768, 4769, 5140, 5145, 7045,
    4103, 4104, 1, 3, 7, 8, 10, 11, 13, 17, 18, 22
}


# ── Scenario-Specific Sigma-Aligned Key Evidence Predicates ─────────────────────

def is_key_evidence_dcsync(data: dict, event_id: int) -> bool:
    """Event 4662 with critical DS-Replication GUIDs."""
    if event_id == 4662:
        props = str(data.get("Properties") or data.get("Message") or "").lower()
        guids = [
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
        ]
        return any(g in props for g in guids)
    return False


def is_key_evidence_mimikatz(data: dict, event_id: int) -> bool:
    """Sysmon Event 10 accessing LSASS with suspicious GrantedAccess or Event 4104 sekurlsa scriptblock."""
    if event_id == 10:
        target = str(data.get("TargetImage") or data.get("Message") or "").lower()
        if "lsass.exe" in target:
            ga = str(data.get("GrantedAccess") or "").lower()
            return ga in ("0x1010", "0x1410", "0x1438") or "powershell" in str(data.get("SourceImage") or "").lower()
        return False
    if event_id == 4104:
        s = str(data.get("ScriptBlockText") or data.get("Message") or "").lower()
        return any(k in s for k in ["sekurlsa", "invoke-mimikatz", "mimikatz"])
    return False


def is_key_evidence_psexec(data: dict, event_id: int) -> bool:
    """Service 7045/4697 PSEXESVC, process 1 execution of PsExec/secrets, or Event 13 LSA secrets."""
    if event_id in (7045, 4697):
        return "psexesvc" in str(data.get("ServiceName") or data.get("Message") or "").lower()
    if event_id == 1:
        cmd = str(data.get("CommandLine") or data.get("Image") or "").lower()
        return "psexesvc" in cmd or ("secrets" in cmd and "reg" in cmd)
    if event_id == 13:
        target = str(data.get("TargetObject") or "").lower()
        return "policy\\secrets" in target or ("psexesvc" in target and "imagepath" in target)
    return False


def is_key_evidence_dcom(data: dict, event_id: int) -> bool:
    """Explorer spawning PowerShell or DCOM ShellWindows CLSID reference."""
    if event_id in (1, 4688):
        parent = str(data.get("ParentImage") or data.get("ParentProcessName") or "").lower()
        img = str(data.get("Image") or data.get("NewProcessName") or "").lower()
        if "explorer.exe" in parent and "powershell.exe" in img:
            return True
    s = str(data).lower()
    return "9ba05972-f6a8-11cf-a442-00a0c90a8f39" in s or "shellwindows" in s


def is_key_evidence_psh_download(data: dict, event_id: int) -> bool:
    """PowerShell staging / netsh firewall punch / Python HTTP server execution."""
    if event_id in (1, 4688):
        cmd = str(data.get("CommandLine") or "").lower()
        img = str(data.get("Image") or data.get("NewProcessName") or "").lower()
        if "http.server" in cmd or ("netsh" in img and "python" in cmd):
            return True
        if any(k in cmd for k in ["invoke-webrequest", "downloadstring", "net.webclient"]):
            return True
    if event_id == 4104:
        s = str(data.get("ScriptBlockText") or data.get("Message") or "").lower()
        return any(k in s for k in ["invoke-webrequest", "downloadstring", "net.webclient", "http.server"])
    if event_id == 22:
        img = str(data.get("Image") or "").lower()
        return "python" in img
    return False


MORDOR_SCENARIOS = [
    {
        "zip_name": "covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "name": "Active Directory DCSync Attack (Covenant C2)",
        "mitre_technique": "T1003.006",
        "target_count": 350,
        "key_predicate": is_key_evidence_dcsync,
        "description": (
            "An attacker with Domain Admin-equivalent privileges used Covenant C2 to perform a "
            "DCSync attack via the MS-DRSR Directory Replication Service (DsGetNCChanges) protocol "
            "to replicate password hashes from the Domain Controller. Investigate Event ID 4662 and "
            "network logon events to identify the compromised account and replication abuse."
        ),
        "alert_title": "Critical: Directory Replication Service (DCSync) Abuse Detected (Event 4662)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": """title: Mimikatz / Covenant DCSync Replication (Event 4662)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006""",
        "ad_context": {
            "domain": "shire.com",
            "attack_type": "DCSync (MS-DRSR DsGetNCChanges)",
            "critical_guids": {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
            },
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for DCSync?",
                "correct_answer": "T1003.006",
                "acceptable_answers": ["T1003"],
                "explanation": "DCSync is categorized under OS Credential Dumping: DCSync (T1003.006).",
                "points": 15,
            },
            {
                "question_text": "Which Windows Security Event ID logs directory service object access used to detect DCSync?",
                "correct_answer": "4662",
                "acceptable_answers": ["4662"],
                "explanation": "Event ID 4662 ('An operation was performed on an object') logs AD replication rights checks.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "empire_mimikatz_logonpasswords.zip",
        "name": "Empire Mimikatz LSASS Credential Dumping",
        "mitre_technique": "T1003.001",
        "target_count": 350,
        "key_predicate": is_key_evidence_mimikatz,
        "description": (
            "A threat actor operating PowerShell Empire executed Mimikatz (sekurlsa::logonpasswords) "
            "on an Active Directory workstation to dump credentials from LSASS process memory. "
            "Analyze the Windows and Sysmon events to trace the credential dump."
        ),
        "alert_title": "Critical: Suspicious Process Access to LSASS Memory (Mimikatz)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": """title: LSASS Memory Dump via Mimikatz (Sysmon Event 10)
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001""",
        "ad_context": {
            "target_process": "C:\\Windows\\System32\\lsass.exe",
            "tool": "PowerShell Empire / Invoke-Mimikatz",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for dumping LSASS memory?",
                "correct_answer": "T1003.001",
                "acceptable_answers": ["T1003"],
                "explanation": "T1003.001 corresponds to OS Credential Dumping: LSASS Memory.",
                "points": 15,
            },
            {
                "question_text": "Which Windows system process is targeted by sekurlsa::logonpasswords?",
                "correct_answer": "lsass.exe",
                "acceptable_answers": ["lsass", "c:\\windows\\system32\\lsass.exe"],
                "explanation": "Local Security Authority Subsystem Service (lsass.exe) stores active logon credentials in memory.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "cmd_psexec_lsa_secrets_dump.zip",
        "name": "PsExec Lateral Movement & LSA Secrets Dump",
        "mitre_technique": "T1003.004",
        "target_count": 300,  # Ingests all 286 events
        "key_predicate": is_key_evidence_psexec,
        "description": (
            "An adversary used Sysinternals PsExec to execute commands as SYSTEM and dump "
            "LSA Secrets from the registry. All 286 events from the incident capture are loaded—"
            "investigate service creation, process execution, and named pipe activity."
        ),
        "alert_title": "High Severity: PsExec Service Installation & LSA Secrets Access",
        "severity": SeverityLevel.HIGH,
        "sigma_rule": """title: PsExec Service Execution (PSEXESVC)
status: stable
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1569.002""",
        "ad_context": {
            "service_binary": "PSEXESVC.exe",
            "technique": "PsExec SYSTEM escalation + LSA Secrets Dump",
        },
        "questions": [
            {
                "question_text": "What is the default service name installed by Sysinternals PsExec on the target host?",
                "correct_answer": "PSEXESVC",
                "acceptable_answers": ["psexesvc.exe"],
                "explanation": "PsExec drops and registers the PSEXESVC service binary on the remote Windows host.",
                "points": 20,
            },
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for LSA Secrets credential dumping?",
                "correct_answer": "T1003.004",
                "acceptable_answers": ["T1003", "T1569.002"],
                "explanation": "T1003.004 is OS Credential Dumping: LSA Secrets.",
                "points": 15,
            },
        ],
    },
    {
        "zip_name": "empire_dcom_shellwindows_stager.zip",
        "name": "Empire Lateral Movement via DCOM ShellWindows",
        "mitre_technique": "T1021.003",
        "target_count": 350,
        "key_predicate": is_key_evidence_dcom,
        "description": (
            "An attacker abused Distributed Component Object Model (DCOM) ShellWindows CLSID "
            "(9BA05972-F6A8-11CF-A442-00A0C90A8F39) via explorer.exe to execute a PowerShell Empire "
            "stager laterally across the domain. Investigate the curated logs from the 32,706-event capture."
        ),
        "alert_title": "High Severity: Remote DCOM ShellWindows Spawning PowerShell Stager",
        "severity": SeverityLevel.HIGH,
        "sigma_rule": """title: DCOM ShellWindows Lateral Movement (Explorer Spawning PowerShell)
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\explorer.exe'
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.003""",
        "ad_context": {
            "dcom_clsid": "9BA05972-F6A8-11CF-A442-00A0C90A8F39 (ShellWindows)",
            "parent_process": "explorer.exe",
            "child_process": "powershell.exe",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for Component Object Model (DCOM) lateral movement?",
                "correct_answer": "T1021.003",
                "acceptable_answers": ["T1021"],
                "explanation": "T1021.003 is Remote Services: Distributed Component Object Model.",
                "points": 20,
            },
            {
                "question_text": "Which Windows shell process acts as the parent process when ShellWindows DCOM is abused?",
                "correct_answer": "explorer.exe",
                "acceptable_answers": ["explorer", "c:\\windows\\explorer.exe"],
                "explanation": "Abusing the ShellWindows COM object causes the remote host's explorer.exe process to spawn the attacker's payload.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "psh_python_webserver.zip",
        "name": "PowerShell Web Download & Staging (Invoke-WebRequest)",
        "mitre_technique": "T1059.001",
        "target_count": 350,
        "key_predicate": is_key_evidence_psh_download,
        "description": (
            "A user workstation executed PowerShell to download a payload hosted on an adversary's "
            "Python SimpleHTTPServer. Investigate PowerShell ScriptBlock logging (Event 4104) and "
            "Sysmon network connection events (Event 3) to uncover the staging activity."
        ),
        "alert_title": "Medium Severity: Suspicious PowerShell Web Download From Non-Standard Port",
        "severity": SeverityLevel.MEDIUM,
        "sigma_rule": """title: PowerShell DownloadString / Invoke-WebRequest Execution
status: stable
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-WebRequest'
      - 'DownloadString'
      - 'Net.WebClient'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001""",
        "ad_context": {
            "staging_protocol": "HTTP (Python SimpleHTTPServer)",
            "key_telemetry": "PowerShell Event ID 4104 (ScriptBlock Logging) & Sysmon Event ID 3",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for PowerShell execution?",
                "correct_answer": "T1059.001",
                "acceptable_answers": ["T1059", "T1105"],
                "explanation": "T1059.001 is Command and Scripting Interpreter: PowerShell.",
                "points": 15,
            },
            {
                "question_text": "Which Windows PowerShell Event ID records full ScriptBlock text content?",
                "correct_answer": "4104",
                "acceptable_answers": ["4104"],
                "explanation": "Event ID 4104 (Execute a Remote Command) records the de-obfuscated PowerShell ScriptBlock text.",
                "points": 20,
            },
        ],
    },
]


def parse_single_record(data: dict, scenario_id: int, key_predicate=None) -> Log:
    ts_str = (
        data.get("@timestamp")
        or data.get("TimeCreated")
        or data.get("EventTime")
        or data.get("UtcTime")
    )
    try:
        clean_ts = str(ts_str).replace("Z", "+00:00")
        ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
    except Exception:
        ts = datetime.now()

    ev_raw = data.get("EventID") or data.get("event_id") or 0
    if isinstance(ev_raw, dict):
        ev_raw = ev_raw.get("$numberInt") or 0
    try:
        event_id = int(ev_raw)
    except Exception:
        event_id = 0

    msg = data.get("Message") or ""
    _IP_PLACEHOLDERS = {"-", "", "::1", "127.0.0.1", "0.0.0.0", "::"}

    def _clean_ip(val):
        if not val or str(val).strip() in _IP_PLACEHOLDERS:
            return None
        v = str(val).strip()
        if v.lower().startswith("fe80"):  # IPv6 link-local
            return None
        return v

    source_ip = (
        _clean_ip(data.get("IpAddress"))
        or _clean_ip(data.get("SourceAddress"))
        or _clean_ip(data.get("SourceIp"))
        # NOTE: DestinationIp intentionally excluded — it is not the source
        or _clean_ip(extract_field_from_message(msg, r"Source Network Address:\s*([^\r\n\t]+)"))
    )
    username = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
        or data.get("User")
        or extract_field_from_message(msg, r"Account Name:\s*([^\r\n\t]+)")
    )
    target_host = (
        data.get("Hostname")
        or data.get("Computer")
        or data.get("host")
    )

    is_key = bool(key_predicate(data, event_id)) if key_predicate else False

    return Log(
        scenario_id=scenario_id,
        event_id=event_id,
        timestamp=ts,
        source_ip=source_ip,
        username=username,
        target_host=target_host,
        is_key_evidence=is_key,
        raw_event_data=data,
    )


def smart_sample_mordor_zip(zip_path: Path, scenario_id: int, target_count: int, key_predicate=None):
    """
    Scans the entire ZIP archive so high-signal events later in the file are never lost!
    Guarantees key evidence events are preserved, prioritizes security events, and samples
    surrounding background events up to target_count sorted chronologically.
    """
    all_raw = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".json") or info.filename.endswith(".jsonl"):
                with zf.open(info) as f:
                    for raw_line in f:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            if isinstance(item, dict):
                                all_raw.append(item)
                        except Exception:
                            continue
                if all_raw:
                    break

    total_in_zip = len(all_raw)
    if total_in_zip <= target_count:
        selected_raw = all_raw
    else:
        key_records = []
        priority_records = []
        background_records = []
        for idx, d in enumerate(all_raw):
            ev = d.get("EventID") or d.get("event_id") or 0
            if isinstance(ev, dict):
                ev = ev.get("$numberInt") or 0
            try:
                ev = int(ev)
            except Exception:
                ev = 0

            # Separate key attack evidence from general priority records
            if key_predicate and key_predicate(d, ev):
                key_records.append((idx, d))
            elif ev in PRIORITY_EVENT_IDS:
                priority_records.append((idx, d))
            else:
                background_records.append((idx, d))

        # 100% of key evidence events are ALWAYS retained
        max_priority = max(0, int(target_count * 0.75) - len(key_records))
        if len(priority_records) > max_priority and max_priority > 0:
            step = max(1, len(priority_records) // max_priority)
            chosen_priority = priority_records[::step][:max_priority]
        else:
            chosen_priority = priority_records[:max_priority]

        remaining_slots = max(0, target_count - len(key_records) - len(chosen_priority))
        if remaining_slots > 0 and background_records:
            step_bg = max(1, len(background_records) // remaining_slots)
            chosen_bg = background_records[::step_bg][:remaining_slots]
        else:
            chosen_bg = []

        combined = sorted(key_records + chosen_priority + chosen_bg, key=lambda x: x[0])
        selected_raw = [x[1] for x in combined]

    entries = [parse_single_record(d, scenario_id, key_predicate) for d in selected_raw]
    entries.sort(key=lambda x: x.timestamp)
    return entries, total_in_zip


def build_dynamic_mordor_questions(item: dict, logs: list[Log]) -> list[dict]:
    """
    Extracts actual forensic values from the ingested Mordor key evidence logs
    so every scenario asks 4 real log-investigation questions instead of static trivia.
    """
    key_logs = [l for l in logs if l.is_key_evidence] or logs
    mitre = item["mitre_technique"]

    # Helper to collect non-empty values from key logs
    def collect_vals(*keys):
        vals = []
        for l in key_logs:
            raw = l.raw_event_data or {}
            for k in keys:
                v = raw.get(k)
                if v and str(v).strip() not in ("-", "", "None"):
                    vals.append(str(v).strip())
        return vals

    hosts = [l.target_host for l in key_logs if l.target_host and l.target_host != "-"]
    primary_host = hosts[0] if hosts else "MORDORDC.theshire.local"
    short_host = primary_host.split(".")[0]

    # 1. DCSync (T1003.006)
    if mitre == "T1003.006":
        actors = [
            u for u in collect_vals("SubjectUserName", "TargetUserName")
            if not u.endswith("$") and u.upper() not in ("SYSTEM", "ANONYMOUS LOGON")
        ]
        attacker_user = actors[0] if actors else "pgustavo"
        return [
            {
                "question_text": "[Phase 1: Alert Triage] Which Windows Security Event ID records the directory replication access check triggered by the DCSync attack?",
                "correct_answer": "4662",
                "acceptable_answers": ["4662"],
                "explanation": "Event ID 4662 ('An operation was performed on an object') logs Active Directory replication permission checks against the domain naming context.",
                "points": 15,
            },
            {
                "question_text": "[Phase 2: Attribution] Pivot on Event 4662 containing the DS-Replication-Get-Changes-All GUID (1131f6ad...). Which non-machine domain user account (SubjectUserName) executed the DCSync attack?",
                "correct_answer": attacker_user,
                "acceptable_answers": list({attacker_user.lower(), f"theshire\\{attacker_user.lower()}", f"shire\\{attacker_user.lower()}"}),
                "explanation": f"While Domain Controller machine accounts (ending in '$') legitimately replicate AD changes, user account '{attacker_user}' requested replication GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.",
                "points": 25,
            },
            {
                "question_text": "[Phase 3: Scope] What is the hostname of the Domain Controller targeted by the replication request?",
                "correct_answer": primary_host,
                "acceptable_answers": [primary_host.lower(), short_host.lower()],
                "explanation": f"The Event 4662 replication operation was logged on Domain Controller '{primary_host}'.",
                "points": 20,
            },
            {
                "question_text": "[Phase 4: Telemetry Analysis] What hex Access Mask value is recorded in the malicious Event 4662 replication logs?",
                "correct_answer": "0x100",
                "acceptable_answers": ["0x100", "100", "control access"],
                "explanation": "In Active Directory Event 4662, Access Mask 0x100 corresponds to ADS_RIGHT_DS_CONTROL_ACCESS, which is required for Extended Rights like DS-Replication-Get-Changes-All.",
                "points": 20,
            },
        ]

    # 2. Empire Mimikatz LSASS Dump (T1003.001)
    if mitre == "T1003.001":
        ev10_logs = [
            l for l in key_logs
            if l.event_id == 10 and str(l.raw_event_data.get("GrantedAccess", "")).lower() in ("0x1010", "0x1410", "0x1438")
        ] or [l for l in key_logs if l.event_id == 10 and "powershell" in str(l.raw_event_data.get("SourceImage", "")).lower()] or [l for l in key_logs if l.event_id == 10]
        src_images = [
            str(l.raw_event_data.get("SourceImage", "")).strip()
            for l in ev10_logs if l.raw_event_data.get("SourceImage")
        ]
        caller_proc = src_images[0].split("\\")[-1] if src_images else "powershell.exe"
        access_masks = [
            str(l.raw_event_data.get("GrantedAccess", "")).strip()
            for l in ev10_logs if l.raw_event_data.get("GrantedAccess")
        ]
        primary_mask = access_masks[0] if access_masks else "0x1010"
        return [
            {
                "question_text": "[Phase 1: Alert Triage] Which Windows system process is targeted in memory by Mimikatz sekurlsa::logonpasswords?",
                "correct_answer": "lsass.exe",
                "acceptable_answers": ["lsass.exe", "lsass", "c:\\windows\\system32\\lsass.exe"],
                "explanation": "Sysmon Event ID 10 shows TargetImage C:\\windows\\system32\\lsass.exe being opened for memory reading.",
                "points": 15,
            },
            {
                "question_text": "[Phase 2: Process Attribution] Inspect Sysmon Event ID 10 targeting lsass.exe. Which executable (SourceImage) opened the suspicious handle to lsass.exe?",
                "correct_answer": caller_proc,
                "acceptable_answers": [caller_proc.lower()] + ([src_images[0].lower()] if src_images else []),
                "explanation": f"PowerShell Empire ran Invoke-Mimikatz in memory inside '{caller_proc}', which is recorded as the SourceImage in Sysmon Event 10.",
                "points": 25,
            },
            {
                "question_text": "[Phase 3: Memory Forensics] What hex GrantedAccess code was requested on lsass.exe in the Sysmon Event 10 log?",
                "correct_answer": primary_mask,
                "acceptable_answers": list({m.lower() for m in access_masks} | {"0x1010", "0x1410", "0x1438"}),
                "explanation": f"Mimikatz requests PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION ({primary_mask}) to read credential material from LSASS memory.",
                "points": 20,
            },
            {
                "question_text": "[Phase 4: Endpoint Scope] On which workstation hostname did this credential dumping attack occur?",
                "correct_answer": primary_host,
                "acceptable_answers": [primary_host.lower(), short_host.lower()],
                "explanation": f"The host telemetry shows the compromise occurred on '{primary_host}'.",
                "points": 20,
            },
        ]

    # 3. PsExec & LSA Secrets Dump (T1003.004)
    if mitre == "T1003.004":
        reg_logs = [l for l in key_logs if l.event_id in (12, 13)]
        reg_targets = [str(l.raw_event_data.get("TargetObject", "")) for l in reg_logs if l.raw_event_data.get("TargetObject")]
        return [
            {
                "question_text": "[Phase 1: Lateral Movement] Which Windows service name is installed on the target host (Event ID 7045 / 4697) during the PsExec execution?",
                "correct_answer": "PSEXESVC",
                "acceptable_answers": ["psexesvc", "psexesvc.exe", "c:\\windows\\psexesvc.exe"],
                "explanation": "Sysinternals PsExec drops and registers the PSEXESVC service binary (Event ID 7045 / 4697) to execute commands as SYSTEM.",
                "points": 15,
            },
            {
                "question_text": "[Phase 2: Execution Context] Under which built-in high-privilege Windows account does PSEXESVC execute its spawned child commands?",
                "correct_answer": "SYSTEM",
                "acceptable_answers": ["system", "nt authority\\system", "localsystem"],
                "explanation": "PsExec runs the service as NT AUTHORITY\\SYSTEM, allowing it to read restricted HKLM\\SECURITY\\Policy\\Secrets registry keys.",
                "points": 20,
            },
            {
                "question_text": "[Phase 3: Registry Forensics] Inspect Sysmon Registry events (Event ID 12/13). Which HKLM SECURITY registry subkey tree is accessed to dump LSA Secrets?",
                "correct_answer": "Policy\\Secrets",
                "acceptable_answers": ["policy\\secrets", "hklm\\security\\policy\\secrets", "security\\policy\\secrets"] + [r.lower() for r in reg_targets[:3]],
                "explanation": "LSA Secrets are stored in the registry under HKLM\\SECURITY\\Policy\\Secrets.",
                "points": 25,
            },
            {
                "question_text": "[Phase 4: Endpoint Scope] What is the hostname of the target machine where PSEXESVC was installed?",
                "correct_answer": primary_host,
                "acceptable_answers": [primary_host.lower(), short_host.lower()],
                "explanation": f"The service installation and LSA secret dump occurred on host '{primary_host}'.",
                "points": 20,
            },
        ]

    # 4. Empire DCOM ShellWindows Lateral Movement (T1021.003)
    if mitre == "T1021.003":
        return [
            {
                "question_text": "[Phase 1: Process Lineage] When ShellWindows DCOM is abused for lateral movement, which Windows shell process acts as the ParentImage that spawns powershell.exe?",
                "correct_answer": "explorer.exe",
                "acceptable_answers": ["explorer.exe", "explorer", "c:\\windows\\explorer.exe"],
                "explanation": "The ShellWindows COM class (9BA05972-F6A8-11CF-A442-00A0C90A8F39) is hosted inside explorer.exe, causing explorer.exe to spawn the attacker's child command.",
                "points": 20,
            },
            {
                "question_text": "[Phase 2: Payload Triage] Which child executable is spawned by explorer.exe to run the Empire stager (Sysmon Event 1 / Security 4688)?",
                "correct_answer": "powershell.exe",
                "acceptable_answers": ["powershell.exe", "powershell", "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"],
                "explanation": "Explorer.exe spawns powershell.exe with an encoded (-enc / -e) Empire stager command line.",
                "points": 20,
            },
            {
                "question_text": "[Phase 3: Endpoint Scope] What is the hostname of the workstation targeted by the DCOM ShellWindows lateral movement?",
                "correct_answer": primary_host,
                "acceptable_answers": [primary_host.lower(), short_host.lower()],
                "explanation": f"The remote DCOM execution occurred on '{primary_host}'.",
                "points": 20,
            },
            {
                "question_text": "[Phase 4: MITRE Mapping] What is the MITRE ATT&CK sub-technique ID for Distributed Component Object Model lateral movement?",
                "correct_answer": "T1021.003",
                "acceptable_answers": ["t1021.003", "t1021"],
                "explanation": "T1021.003 is Remote Services: Distributed Component Object Model.",
                "points": 15,
            },
        ]

    # 5. PowerShell Web Download & Python Staging (T1059.001)
    return [
        {
            "question_text": "[Phase 1: Telemetry Triage] Which Windows PowerShell Event ID records the full ScriptBlock text showing the web download command?",
            "correct_answer": "4104",
            "acceptable_answers": ["4104"],
            "explanation": "PowerShell Operational Event ID 4104 records the full ScriptBlock text of executed commands.",
            "points": 15,
        },
        {
            "question_text": "[Phase 2: Command Analysis] Inspect the process creation and firewall logs. Which TCP port was opened and used by the Python http.server to stage the file?",
            "correct_answer": "8000",
            "acceptable_answers": ["8000", "tcp/8000"],
            "explanation": "The logs show python -m http.server 8000 and a netsh firewall rule opening port 8000.",
            "points": 25,
        },
        {
            "question_text": "[Phase 3: Endpoint Scope] On which host (Computer / Hostname) was the PowerShell download executed?",
            "correct_answer": primary_host,
            "acceptable_answers": [primary_host.lower(), short_host.lower()],
            "explanation": f"The staging and PowerShell execution took place on '{primary_host}'.",
            "points": 20,
        },
        {
            "question_text": "[Phase 4: MITRE Mapping] What is the MITRE ATT&CK sub-technique ID for PowerShell command execution?",
            "correct_answer": "T1059.001",
            "acceptable_answers": ["t1059.001", "t1059"],
            "explanation": "T1059.001 is Command and Scripting Interpreter: PowerShell.",
            "points": 15,
        },
    ]


def main():
    db = SessionLocal()
    try:
        for item in MORDOR_SCENARIOS:
            zpath = ROOT / item["zip_name"] if (ROOT / item["zip_name"]).exists() else ROOT.parent / item["zip_name"]
            if not zpath.exists():
                print(f"[SKIP] {item['zip_name']} not found in root.")
                continue

            existing = db.query(Scenario).filter(Scenario.name == item["name"]).first()
            if existing:
                sc = existing
                sc.ad_context = item["ad_context"]
                db.query(Log).filter(Log.scenario_id == sc.id).delete()
                db.query(Question).filter(Question.scenario_id == sc.id).delete()
                logs, total_raw = smart_sample_mordor_zip(
                    zpath, sc.id, item["target_count"], item.get("key_predicate")
                )
                db.add_all(logs)
                for q in build_dynamic_mordor_questions(item, logs):
                    db.add(Question(scenario_id=sc.id, **q))
                db.commit()
                print(f"[REFRESHED] '{item['name']}': {len(logs)} logs & 4 forensic questions updated.")
                continue

            sc = Scenario(
                name=item["name"],
                description=item["description"],
                mitre_technique=item["mitre_technique"],
                status="Published",
                ad_context=item["ad_context"],
            )
            db.add(sc)
            db.flush()

            db.add(
                Alert(
                    scenario_id=sc.id,
                    title=item["alert_title"],
                    severity=item["severity"],
                    sigma_rule=item["sigma_rule"],
                )
            )

            logs, total_raw = smart_sample_mordor_zip(
                zpath, sc.id, item["target_count"], item.get("key_predicate")
            )
            db.add_all(logs)

            for q in build_dynamic_mordor_questions(item, logs):
                db.add(Question(scenario_id=sc.id, **q))

            db.commit()
            print(f"[+] Imported '{item['name']}': Smart-sampled {len(logs)} / {total_raw} events & 4 forensic questions!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
