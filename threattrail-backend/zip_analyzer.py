import io
import re
import json
import zipfile
from datetime import datetime
from collections import Counter, defaultdict
from typing import Any, Optional

MAX_ZIP_BYTES = 200 * 1024 * 1024          # 200 MB compressed limit
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024 # 250 MB uncompressed limit

PRIORITY_EVENT_IDS = {
    4624, 4625, 4648, 4662, 4672, 4688, 4697, 4698, 4768, 4769, 5140, 5145, 7045,
    4103, 4104, 1, 3, 7, 8, 10, 11, 12, 13, 17, 18, 22
}

BENIGN_SYSTEM_PROCESSES = {
    "svchost.exe", "msmpeng.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "smss.exe", "wmiprvse.exe", "taskhostw.exe"
}

PLACEHOLDER_IPS = {"-", "", "::1", "127.0.0.1", "0.0.0.0", "localhost", "none"}

DCSYNC_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
)


def extract_field_from_message(msg: str, pattern: str) -> Optional[str]:
    if not msg:
        return None
    matches = re.findall(pattern, msg, re.IGNORECASE)
    valid = [m.strip() for m in matches if m and m.strip() not in ("-", "")]
    return valid[-1] if valid else None


def clean_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    return None if s in ("", "-", "None", "null") else s


def clean_ip(val: Any) -> Optional[str]:
    s = clean_str(val)
    if not s or s.lower() in PLACEHOLDER_IPS or s.lower().startswith("fe80:"):
        return None
    return s


def normalize_event(data: dict) -> dict:
    """Normalizes raw Windows Security / System / PowerShell / Sysmon JSON into a consistent dict."""
    ts_str = (
        data.get("@timestamp")
        or data.get("TimeCreated")
        or data.get("EventTime")
        or data.get("UtcTime")
    )
    ts = None
    if ts_str:
        try:
            clean_ts = str(ts_str).replace("Z", "+00:00")
            if "T" in clean_ts:
                ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
            else:
                ts = datetime.strptime(clean_ts[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = None
    if ts is None:
        ts = datetime.now()

    ev_raw = data.get("EventID") or data.get("event_id") or 0
    if isinstance(ev_raw, dict):
        ev_raw = ev_raw.get("$numberInt") or 0
    try:
        event_id = int(ev_raw)
    except Exception:
        event_id = 0

    msg = data.get("Message") or ""

    source_ip = (
        clean_ip(data.get("IpAddress"))
        or clean_ip(data.get("SourceAddress"))
        or clean_ip(data.get("SourceIp"))
        or clean_ip(data.get("SourceNetworkAddress"))
        or clean_ip(extract_field_from_message(msg, r"Source Network Address:\s*([^\r\n\t]+)"))
        or clean_ip(extract_field_from_message(msg, r"Client Address:\s*([^\r\n\t]+)"))
    )

    dest_ip = clean_ip(data.get("DestinationIp")) or clean_ip(data.get("DestAddress"))
    dest_port = clean_str(data.get("DestinationPort")) or clean_str(data.get("DestPort"))

    subject_user = (
        clean_str(data.get("SubjectUserName"))
        or extract_field_from_message(msg, r"Subject:[\s\S]*?Account Name:\s*([^\r\n\t]+)")
    )
    target_user = (
        clean_str(data.get("TargetUserName"))
        or clean_str(data.get("AccountName"))
        or clean_str(data.get("TargetUser"))
        or extract_field_from_message(msg, r"New Logon:[\s\S]*?Account Name:\s*([^\r\n\t]+)")
        or extract_field_from_message(msg, r"Account For Which Logon Failed:[\s\S]*?Account Name:\s*([^\r\n\t]+)")
    )
    username = target_user or subject_user or clean_str(data.get("User"))

    domain = (
        clean_str(data.get("TargetDomainName"))
        or clean_str(data.get("SubjectDomainName"))
        or clean_str(data.get("AccountDomain"))
        or clean_str(data.get("Domain"))
        or extract_field_from_message(msg, r"Account Domain:\s*([^\r\n\t]+)")
    )

    target_host = (
        clean_str(data.get("Hostname"))
        or clean_str(data.get("Computer"))
        or clean_str(data.get("host"))
        or clean_str(data.get("WorkstationName"))
        or extract_field_from_message(msg, r"Workstation Name:\s*([^\r\n\t]+)")
    )

    image = (
        clean_str(data.get("Image"))
        or clean_str(data.get("NewProcessName"))
        or clean_str(data.get("SourceImage"))
        or clean_str(data.get("ProcessName"))
    )
    parent_image = clean_str(data.get("ParentImage")) or clean_str(data.get("ParentProcessName"))
    target_image = clean_str(data.get("TargetImage"))
    command_line = (
        clean_str(data.get("CommandLine"))
        or clean_str(data.get("ProcessCommandLine"))
        or extract_field_from_message(msg, r"Process Command Line:\s*([^\r\n]+)")
    )
    service_name = clean_str(data.get("ServiceName")) or extract_field_from_message(msg, r"Service Name:\s*([^\r\n\t]+)")
    ticket_enc = clean_str(data.get("TicketEncryptionType")) or extract_field_from_message(msg, r"Ticket Encryption Type:\s*(0x[0-9a-fA-F]+|[0-9]+)")
    properties = clean_str(data.get("Properties")) or extract_field_from_message(msg, r"Properties:\s*([^\r\n]+)")
    access_mask = clean_str(data.get("AccessMask")) or extract_field_from_message(msg, r"Access Mask:\s*(0x[0-9a-fA-F]+)")
    granted_access = clean_str(data.get("GrantedAccess"))
    target_object = clean_str(data.get("TargetObject"))
    script_block = clean_str(data.get("ScriptBlockText")) or clean_str(data.get("Payload"))

    return {
        "event_id": event_id,
        "timestamp": ts,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "subject_user": subject_user,
        "target_user": target_user,
        "username": username,
        "domain": domain,
        "target_host": target_host,
        "image": image,
        "parent_image": parent_image,
        "target_image": target_image,
        "command_line": command_line,
        "service_name": service_name,
        "ticket_enc": ticket_enc,
        "properties": properties,
        "access_mask": access_mask,
        "granted_access": granted_access,
        "target_object": target_object,
        "script_block": script_block,
        "message": msg,
        "raw": data,
    }


def stream_and_normalize_zip(content: bytes) -> tuple[list[dict], list[str]]:
    """
    Stage 1 & 2: Validates ZIP archive size/compression bounds and streams all JSON/JSONL records.
    """
    if len(content) > MAX_ZIP_BYTES:
        raise ValueError("ZIP file exceeds the 200 MB maximum upload limit.")

    events: list[dict] = []
    files_processed: list[str] = []
    total_uncompressed = 0

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not (info.filename.endswith(".json") or info.filename.endswith(".jsonl")):
                continue

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Uncompressed log data exceeds 250 MB safety limit.")

            files_processed.append(info.filename)
            with zf.open(info) as f:
                first_chunk = f.read(2048).decode("utf-8", errors="replace").lstrip()
                f.seek(0)

                if first_chunk.startswith("["):
                    raw_text = f.read().decode("utf-8", errors="replace").strip()
                    try:
                        arr = json.loads(raw_text)
                        if isinstance(arr, list):
                            for item in arr:
                                if isinstance(item, dict):
                                    events.append(normalize_event(item))
                    except Exception:
                        pass
                else:
                    for raw_line in f:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            if isinstance(item, dict):
                                events.append(normalize_event(item))
                        except Exception:
                            continue

    events.sort(key=lambda x: x["timestamp"])
    return events, files_processed


def extract_observed_ad_context(events: list[dict]) -> dict[str, Any]:
    """
    Stage 4: Extracts strictly observed facts from the logs and separates inferred roles.
    Never fabricates domain controllers or privileges that aren't backed by log telemetry.
    """
    domains = Counter()
    hosts = Counter()
    human_users = Counter()
    machine_accounts = Counter()
    services_spns = Counter()
    event_counts = Counter()
    dc_candidate_hosts = set()

    for ev in events:
        eid = ev["event_id"]
        event_counts[str(eid)] += 1

        if ev["domain"] and ev["domain"].upper() not in ("NT AUTHORITY", "WORKGROUP", "WINDOWSMANAGER", "FONT DRIVER HOST"):
            domains[ev["domain"]] += 1

        if ev["target_host"]:
            hosts[ev["target_host"]] += 1
            if eid in (4662, 4768, 4769):
                dc_candidate_hosts.add(ev["target_host"])

        for u in (ev["subject_user"], ev["target_user"], ev["username"]):
            if not u:
                continue
            u_clean = u.split("\\")[-1]
            if u_clean.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-"):
                continue
            if u_clean.endswith("$"):
                machine_accounts[u_clean] += 1
            else:
                human_users[u_clean] += 1

        if ev["service_name"] and not ev["service_name"].endswith("$") and ev["service_name"].lower() != "krbtgt":
            services_spns[ev["service_name"]] += 1

    timestamps = [ev["timestamp"] for ev in events if ev["timestamp"]]
    time_window = {
        "first_event_utc": timestamps[0].isoformat() if timestamps else None,
        "last_event_utc": timestamps[-1].isoformat() if timestamps else None,
        "total_events_analyzed": len(events),
    }

    return {
        "schema_note": "Extracted automatically from log telemetry. Distinguishes directly observed entities from inferred roles.",
        "telemetry_summary": time_window,
        "observed_domains": [d for d, _ in domains.most_common(5)],
        "observed_hosts": [{"hostname": h, "event_count": c} for h, c in hosts.most_common(10)],
        "observed_user_accounts": [{"username": u, "occurrences": c} for u, c in human_users.most_common(12)],
        "observed_machine_accounts": [m for m, _ in machine_accounts.most_common(8)],
        "observed_services_and_spns": [{"service": s, "occurrences": c} for s, c in services_spns.most_common(8)],
        "inferred_roles": {
            "potential_domain_controllers": sorted(dc_candidate_hosts),
            "inference_basis": "Hosts logging Active Directory Kerberos (4768/4769) or Directory Replication (4662) events" if dc_candidate_hosts else "No AD DC-specific events (4662/4768/4769) observed",
        },
        "top_event_ids": dict(event_counts.most_common(10)),
    }


def _short_proc(path_str: Optional[str]) -> Optional[str]:
    if not path_str:
        return None
    return path_str.replace("/", "\\").split("\\")[-1]


def evaluate_detection_rules(events: list[dict]) -> dict[str, Any]:
    """
    Stage 3: Deterministic multi-event detection & correlation engine with benign exclusions,
    confidence levels, and evidence-backed question generation.
    """
    candidates = []

    # ── RULE 1: DCSync Directory Replication (T1003.006) ─────────────────────
    dcsync_hits = []
    for idx, ev in enumerate(events):
        if ev["event_id"] == 4662:
            hay = f"{ev['properties'] or ''} {ev['message'] or ''}".lower()
            if any(g in hay for g in DCSYNC_GUIDS):
                actor = ev["subject_user"] or ev["username"] or ""
                # Filter out normal Domain Controller machine account replication ($ suffix)
                if not actor.endswith("$"):
                    dcsync_hits.append((idx, ev))

    if dcsync_hits:
        sample_ev = dcsync_hits[0][1]
        actor = sample_ev["subject_user"] or sample_ev["username"]
        host = sample_ev["target_host"]
        mask = sample_ev["access_mask"]
        questions = [
            {
                "question_text": "[Phase 1: Alert Triage] Which Windows Security Event ID records the directory service object access associated with DCSync replication checks?",
                "correct_answer": "4662",
                "acceptable_answers": ["4662"],
                "explanation": f"Observed {len(dcsync_hits)} Event ID 4662 records referencing MS-DRSR replication GUIDs.",
                "points": 15,
            }
        ]
        if actor:
            questions.append({
                "question_text": "[Phase 2: Attribution] Inspect Event 4662 containing replication GUID 1131f6aa.../1131f6ad... Which non-machine user account (SubjectUserName) initiated the replication request?",
                "correct_answer": actor.split("\\")[-1],
                "acceptable_answers": list({actor.lower(), actor.split("\\")[-1].lower()}),
                "explanation": f"Unlike routine Domain Controller machine accounts (ending in '$'), user account '{actor}' requested directory replication privileges.",
                "points": 25,
            })
        if host:
            questions.append({
                "question_text": "[Phase 3: Scope] Which host recorded the Event 4662 directory replication activity?",
                "correct_answer": host,
                "acceptable_answers": list({host.lower(), host.split(".")[0].lower()}),
                "explanation": f"The directory service access events were logged by host '{host}'.",
                "points": 20,
            })
        if mask:
            questions.append({
                "question_text": "[Phase 4: Telemetry Verification] What hex Access Mask value was recorded in the suspicious Event 4662 logs?",
                "correct_answer": mask,
                "acceptable_answers": [mask.lower(), mask.replace("0x", "").lower()],
                "explanation": f"Access Mask '{mask}' (Control Access) is required to exercise extended AD replication rights.",
                "points": 20,
            })

        candidates.append({
            "score": 95,
            "confidence": "High Confidence (Correlated AD Replication GUIDs + Non-Machine Account)",
            "name": "Active Directory DCSync Replication Abuse",
            "mitre_technique": "T1003.006",
            "severity": "Critical",
            "alert_title": "Critical: Non-DC Account Requesting Directory Replication Changes (Event 4662)",
            "description": (
                f"Telemetry analysis across {len(events)} events identified {len(dcsync_hits)} Event ID 4662 records "
                "where a non-machine account requested MS-DRSR Directory Replication Service extended rights "
                "(DS-Replication-Get-Changes). Investigate the replication events, verify whether the initiating account "
                "is authorized, and determine the scope of domain exposure."
            ),
            "sigma_rule": """title: Directory Replication Service (DCSync) Access by Non-Machine Account
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
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006""",
            "key_indices": {i for i, _ in dcsync_hits},
            "evidence_summary": [
                f"{len(dcsync_hits)} Event 4662 log(s) matched DS-Replication GUIDs from non-machine actor '{actor or 'unknown'}'",
                f"Target host: {host or 'unknown'} | AccessMask: {mask or 'N/A'}",
            ],
            "caveats": [
                "Verify that the initiating account is not a legitimate Azure AD Connect (MSOL_) or authorized backup replication service account."
            ],
            "questions": questions,
        })

    # ── RULE 2: LSASS Memory Access / Credential Dumping (T1003.001) ─────────
    lsass_hits = []
    ps_mimikatz_hits = []
    for idx, ev in enumerate(events):
        if ev["event_id"] == 10 and ev["target_image"] and ev["target_image"].lower().endswith("\\lsass.exe"):
            caller = (_short_proc(ev["image"]) or "").lower()
            ga = (ev["granted_access"] or "").lower()
            if caller not in BENIGN_SYSTEM_PROCESSES and any(m in ga for m in ("0x1010", "0x1410", "0x1438", "0x1fffff")):
                lsass_hits.append((idx, ev))
        elif ev["event_id"] in (4103, 4104):
            hay = f"{ev['script_block'] or ''} {ev['message'] or ''}".lower()
            if any(k in hay for k in ("sekurlsa", "logonpasswords", "invoke-mimikatz", "lsadump")):
                ps_mimikatz_hits.append((idx, ev))

    if lsass_hits or ps_mimikatz_hits:
        all_hits = lsass_hits + ps_mimikatz_hits
        sample_ev = (lsass_hits[0][1] if lsass_hits else ps_mimikatz_hits[0][1])
        caller_proc = _short_proc(sample_ev["image"])
        ga_mask = sample_ev["granted_access"]
        host = sample_ev["target_host"]
        is_both = bool(lsass_hits and ps_mimikatz_hits)

        questions = [
            {
                "question_text": "[Phase 1: Target Identification] Which Windows subsystem process was targeted for memory access in Sysmon Event ID 10?",
                "correct_answer": "lsass.exe",
                "acceptable_answers": ["lsass.exe", "lsass", "c:\\windows\\system32\\lsass.exe"],
                "explanation": "Sysmon Event ID 10 records a process handle opened against C:\\Windows\\System32\\lsass.exe.",
                "points": 15,
            }
        ]
        if caller_proc:
            questions.append({
                "question_text": "[Phase 2: Process Attribution] Which non-standard executable (SourceImage) accessed lsass.exe memory?",
                "correct_answer": caller_proc,
                "acceptable_answers": list({caller_proc.lower(), (sample_ev["image"] or caller_proc).lower()}),
                "explanation": f"Sysmon Event 10 identifies '{sample_ev['image']}' as the SourceImage opening lsass.exe.",
                "points": 25,
            })
        if ga_mask:
            questions.append({
                "question_text": "[Phase 3: Access Rights] What hex GrantedAccess value was requested on the lsass.exe process handle?",
                "correct_answer": ga_mask,
                "acceptable_answers": [ga_mask.lower()],
                "explanation": f"GrantedAccess '{ga_mask}' includes PROCESS_VM_READ permissions required to read credential material from memory.",
                "points": 20,
            })
        if host:
            questions.append({
                "question_text": "[Phase 4: Endpoint Scope] On which workstation/host did this LSASS memory access occur?",
                "correct_answer": host,
                "acceptable_answers": list({host.lower(), host.split(".")[0].lower()}),
                "explanation": f"The activity was recorded on host '{host}'.",
                "points": 20,
            })

        candidates.append({
            "score": 92 if is_both else 84,
            "confidence": "High Confidence (Sysmon Event 10 + PowerShell Telemetry)" if is_both else "Medium-High Confidence (Sysmon Event 10 Non-System Caller)",
            "name": "Suspicious LSASS Process Memory Access (Credential Dumping)",
            "mitre_technique": "T1003.001",
            "severity": "Critical",
            "alert_title": "Critical: Non-System Process Accessing LSASS.exe Memory (Sysmon Event 10)",
            "description": (
                f"Analysis of {len(events)} events detected {len(lsass_hits)} Sysmon Event ID 10 process access record(s) "
                f"targeting lsass.exe from '{caller_proc or 'a non-system process'}' with memory-read access flags. "
                "Investigate the calling process, granted access mask, and surrounding PowerShell or DLL telemetry."
            ),
            "sigma_rule": """title: Suspicious Process Access to LSASS Memory (Sysmon Event 10)
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
            "key_indices": {i for i, _ in all_hits},
            "evidence_summary": [
                f"{len(lsass_hits)} Sysmon Event 10 handle(s) to lsass.exe by '{caller_proc or 'unknown'}' (GrantedAccess: {ga_mask or 'N/A'})",
                f"{len(ps_mimikatz_hits)} PowerShell ScriptBlock/Module event(s) matching credential dumping keywords",
            ],
            "caveats": [
                "Legitimate EDR/antivirus agents may open handles to lsass.exe; always verify the SourceImage path and CallTrace."
            ],
            "questions": questions,
        })

    # ── RULE 3: Kerberoasting RC4 Service Ticket Requests (T1558.003) ────────
    kerb_hits = []
    for idx, ev in enumerate(events):
        if ev["event_id"] == 4769:
            enc = (ev["ticket_enc"] or "").lower()
            svc = ev["service_name"] or ""
            if enc in ("0x17", "23") and svc and not svc.endswith("$") and svc.lower() != "krbtgt":
                kerb_hits.append((idx, ev))

    if kerb_hits:
        sample_ev = kerb_hits[0][1]
        actor = sample_ev["target_user"] or sample_ev["username"]
        svc = sample_ev["service_name"]
        src_ip = sample_ev["source_ip"]
        questions = []
        if actor:
            questions.append({
                "question_text": "[Phase 1: Attribution] Which domain user account requested the RC4-encrypted (0x17) Kerberos service ticket in Event ID 4769?",
                "correct_answer": actor.split("@")[0].split("\\")[-1],
                "acceptable_answers": list({actor.lower(), actor.split("@")[0].lower(), actor.split("\\")[-1].lower()}),
                "explanation": f"Event ID 4769 records account '{actor}' requesting an RC4-HMAC service ticket.",
                "points": 20,
            })
        if svc:
            questions.append({
                "question_text": "[Phase 2: Target SPN] Which Service Name / account was targeted in the RC4 (0x17) TGS request?",
                "correct_answer": svc,
                "acceptable_answers": [svc.lower()],
                "explanation": f"The Service Name field in the 0x17 Event 4769 log is '{svc}'.",
                "points": 25,
            })
        questions.append({
            "question_text": "[Phase 3: Encryption Indicator] What hex value in TicketEncryptionType identifies legacy RC4-HMAC encryption?",
            "correct_answer": "0x17",
            "acceptable_answers": ["0x17", "17", "23"],
            "explanation": "In Windows Event 4769, 0x17 (decimal 23) indicates RC4-HMAC encryption.",
            "points": 15,
        })
        if src_ip:
            questions.append({
                "question_text": "[Phase 4: Network Pivot] From which Client / Source IP address was the RC4 service ticket requested?",
                "correct_answer": src_ip,
                "acceptable_answers": [src_ip.lower()],
                "explanation": f"The Client Address recorded in the Event 4769 log is '{src_ip}'.",
                "points": 20,
            })

        candidates.append({
            "score": 88,
            "confidence": "High Confidence (Event 4769 RC4 0x17 for Non-Machine SPN)",
            "name": "Potential Kerberoasting — RC4 Service Ticket Request",
            "mitre_technique": "T1558.003",
            "severity": "High",
            "alert_title": "High Severity: Kerberos TGS Ticket Requested with Legacy RC4 Encryption (0x17)",
            "description": (
                f"Detected {len(kerb_hits)} Kerberos Service Ticket (Event ID 4769) request(s) using legacy RC4-HMAC (0x17) "
                f"encryption targeting service '{svc}' from account '{actor or 'unknown'}'. Filter out standard AES256 (0x12) "
                "and machine account ('$') noise to investigate the anomalous request."
            ),
            "sigma_rule": """title: Kerberoasting - RC4 Ticket Encryption Requested (Event 4769)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
tags:
  - attack.credential_access
  - attack.t1558.003""",
            "key_indices": {i for i, _ in kerb_hits},
            "evidence_summary": [
                f"{len(kerb_hits)} Event 4769 log(s) with TicketEncryptionType=0x17 for service '{svc}' by '{actor or 'unknown'}'",
            ],
            "caveats": [
                "RC4 (0x17) requests can occasionally occur if a legacy service account does not support AES; correlate with user behavior and SPN privileges."
            ],
            "questions": questions,
        })

    # ── RULE 4: Service Installation / PsExec & LSA Secrets (T1003.004 / T1569.002)
    svc_hits = []
    lsa_reg_hits = []
    for idx, ev in enumerate(events):
        if ev["event_id"] in (7045, 4697):
            svc_hits.append((idx, ev))
        elif ev["event_id"] in (12, 13) and ev["target_object"] and "policy\\secrets" in ev["target_object"].lower():
            lsa_reg_hits.append((idx, ev))
        elif ev["event_id"] == 1 and "psexec" in f"{ev['image'] or ''} {ev['command_line'] or ''}".lower():
            svc_hits.append((idx, ev))

    if svc_hits or lsa_reg_hits:
        all_hits = svc_hits + lsa_reg_hits
        svc_ev = next((e for _, e in svc_hits if e["service_name"]), svc_hits[0][1] if svc_hits else lsa_reg_hits[0][1])
        svc_name = svc_ev["service_name"] or "PSEXESVC"
        host = svc_ev["target_host"]
        questions = [
            {
                "question_text": "[Phase 1: Service Persistence/Execution] Which service name was registered on the target host (Event ID 7045 / 4697)?",
                "correct_answer": svc_name,
                "acceptable_answers": list({svc_name.lower(), f"{svc_name.lower()}.exe"}),
                "explanation": f"Service installation telemetry recorded ServiceName '{svc_name}'.",
                "points": 20,
            }
        ]
        if lsa_reg_hits:
            questions.append({
                "question_text": "[Phase 2: Registry Forensics] Inspect Sysmon Registry events (Event ID 12/13). Which HKLM SECURITY registry subkey path was accessed to read LSA Secrets?",
                "correct_answer": "Policy\\Secrets",
                "acceptable_answers": ["policy\\secrets", "hklm\\security\\policy\\secrets", "security\\policy\\secrets"],
                "explanation": f"Observed {len(lsa_reg_hits)} registry event(s) accessing HKLM\\SECURITY\\Policy\\Secrets.",
                "points": 25,
            })
        if host:
            questions.append({
                "question_text": "[Phase 3: Endpoint Scope] On which target hostname did this service execution occur?",
                "correct_answer": host,
                "acceptable_answers": list({host.lower(), host.split(".")[0].lower()}),
                "explanation": f"The events were recorded on host '{host}'.",
                "points": 20,
            })

        candidates.append({
            "score": 90 if (svc_hits and lsa_reg_hits) else 78,
            "confidence": "High Confidence (Correlated Service Install + LSA Registry Access)" if (svc_hits and lsa_reg_hits) else "Medium Confidence (Service Installation Observed)",
            "name": "PsExec Service Execution & LSA Secrets Access" if lsa_reg_hits else f"Suspicious Service Installation ({svc_name})",
            "mitre_technique": "T1003.004" if lsa_reg_hits else "T1569.002",
            "severity": "High",
            "alert_title": f"High Severity: Remote Service Installation ({svc_name}) & Privileged Execution",
            "description": (
                f"Detected {len(svc_hits)} service installation/execution event(s) ({svc_name}) and "
                f"{len(lsa_reg_hits)} registry access event(s) targeting HKLM\\SECURITY\\Policy\\Secrets. "
                "Investigate the installed service binary, execution account, and registry artifacts."
            ),
            "sigma_rule": f"""title: Suspicious Service Installation ({svc_name})
status: stable
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName: '{svc_name}'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1569.002""",
            "key_indices": {i for i, _ in all_hits},
            "evidence_summary": [
                f"{len(svc_hits)} service/process event(s) referencing '{svc_name}'",
                f"{len(lsa_reg_hits)} Sysmon registry event(s) accessing Policy\\Secrets",
            ],
            "caveats": [
                "Administrators occasionally use PsExec for remote maintenance; correlate with registry access and child process commands."
            ],
            "questions": questions,
        })

    # ── RULE 5: DCOM / Shell Process Spawning PowerShell (T1021.003) ─────────
    dcom_hits = []
    for idx, ev in enumerate(events):
        if ev["event_id"] in (1, 4688):
            parent = (_short_proc(ev["parent_image"]) or "").lower()
            child = (_short_proc(ev["image"]) or "").lower()
            if parent in ("explorer.exe", "mmc.exe") and child in ("powershell.exe", "pwsh.exe", "cmd.exe"):
                dcom_hits.append((idx, ev))
        elif "9ba05972-f6a8-11cf-a442-00a0c90a8f39" in f"{ev['command_line'] or ''} {ev['script_block'] or ''} {ev['message'] or ''}".lower():
            dcom_hits.append((idx, ev))

    if dcom_hits:
        sample_ev = dcom_hits[0][1]
        parent_proc = _short_proc(sample_ev["parent_image"]) or "explorer.exe"
        child_proc = _short_proc(sample_ev["image"]) or "powershell.exe"
        host = sample_ev["target_host"]
        questions = [
            {
                "question_text": "[Phase 1: Process Lineage] Which parent process spawned the suspicious command interpreter during the lateral movement?",
                "correct_answer": parent_proc,
                "acceptable_answers": list({parent_proc.lower(), (sample_ev["parent_image"] or parent_proc).lower()}),
                "explanation": f"Process creation telemetry shows ParentImage '{sample_ev['parent_image'] or parent_proc}'.",
                "points": 20,
            },
            {
                "question_text": "[Phase 2: Payload Execution] Which child executable was spawned by the parent shell process?",
                "correct_answer": child_proc,
                "acceptable_answers": list({child_proc.lower(), (sample_ev["image"] or child_proc).lower()}),
                "explanation": f"The spawned child process Image is '{sample_ev['image'] or child_proc}'.",
                "points": 20,
            },
        ]
        if host:
            questions.append({
                "question_text": "[Phase 3: Endpoint Scope] On which target host was the process spawned?",
                "correct_answer": host,
                "acceptable_answers": list({host.lower(), host.split(".")[0].lower()}),
                "explanation": f"The process creation event was recorded on '{host}'.",
                "points": 20,
            })

        candidates.append({
            "score": 82,
            "confidence": "Medium-High Confidence (Shell Parent Spawning Command Interpreter / DCOM Chain)",
            "name": "Lateral Movement via DCOM ShellWindows / Explorer Process Chain",
            "mitre_technique": "T1021.003",
            "severity": "High",
            "alert_title": f"High Severity: {parent_proc} Spawning {child_proc} (Potential DCOM Lateral Movement)",
            "description": (
                f"Identified {len(dcom_hits)} process/script event(s) where '{parent_proc}' spawned '{child_proc}' "
                "or invoked the ShellWindows DCOM CLSID. Correlate the process creation command line with preceding "
                "network logon (Event 4624 Type 3) and PowerShell ScriptBlock (Event 4104) logs."
            ),
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
            "key_indices": {i for i, _ in dcom_hits},
            "evidence_summary": [
                f"{len(dcom_hits)} event(s) showing {parent_proc} -> {child_proc} execution chain on '{host or 'unknown'}'",
            ],
            "caveats": [
                "A local user launching PowerShell from the Start Menu or Explorer address bar also produces explorer.exe -> powershell.exe; always check CommandLine and network logons (4624 Type 3) to confirm remote DCOM abuse."
            ],
            "questions": questions,
        })

    # ── RULE 6: PowerShell Web Download / Python HTTP Staging (T1059.001) ────
    ps_web_hits = []
    detected_port = None
    for idx, ev in enumerate(events):
        hay = f"{ev['command_line'] or ''} {ev['script_block'] or ''} {ev['message'] or ''}".lower()
        if any(k in hay for k in ("invoke-webrequest", "downloadstring", "http.server", "simplehttpserver", "net.webclient")):
            ps_web_hits.append((idx, ev))
            port_match = re.search(r"(?:http\.server|localport=|:)(\d{4,5})\b", hay)
            if port_match and not detected_port:
                detected_port = port_match.group(1)

    if ps_web_hits:
        sample_ev = ps_web_hits[0][1]
        host = sample_ev["target_host"]
        questions = [
            {
                "question_text": "[Phase 1: Telemetry Source] Which PowerShell Operational Event ID records full ScriptBlock code execution?",
                "correct_answer": "4104",
                "acceptable_answers": ["4104", "4103"],
                "explanation": "Windows PowerShell Event ID 4104 captures the full ScriptBlock content.",
                "points": 15,
            }
        ]
        if detected_port:
            questions.append({
                "question_text": "[Phase 2: Network Staging] Which non-standard TCP port was used to host or download the staged payload?",
                "correct_answer": detected_port,
                "acceptable_answers": [detected_port, f"tcp/{detected_port}"],
                "explanation": f"Command line and script telemetry reference TCP port {detected_port}.",
                "points": 25,
            })
        if host:
            questions.append({
                "question_text": "[Phase 3: Endpoint Scope] On which hostname was the PowerShell download executed?",
                "correct_answer": host,
                "acceptable_answers": list({host.lower(), host.split(".")[0].lower()}),
                "explanation": f"The PowerShell web download occurred on host '{host}'.",
                "points": 20,
            })

        candidates.append({
            "score": 80,
            "confidence": "High Confidence (PowerShell Web Download / Staging Telemetry)",
            "name": "PowerShell Web Download & Payload Staging",
            "mitre_technique": "T1059.001",
            "severity": "Medium",
            "alert_title": "Medium Severity: PowerShell Web Download / HTTP Staging Detected",
            "description": (
                f"Detected {len(ps_web_hits)} event(s) containing PowerShell web download cradle commands or "
                "ad-hoc HTTP staging servers. Inspect PowerShell ScriptBlock logs (Event 4104) and process creation "
                "arguments to identify the staging port and target host."
            ),
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
            "key_indices": {i for i, _ in ps_web_hits},
            "evidence_summary": [
                f"{len(ps_web_hits)} event(s) matched PowerShell web download / HTTP staging patterns",
            ],
            "caveats": [
                "Verify the destination URL/IP in the ScriptBlockText to distinguish internal administrative scripts from unauthorized staging."
            ],
            "questions": questions,
        })

    # ── RULE 7: Password Spraying (T1110.003) vs. Brute Force (T1110.001) ────
    failures_by_ip: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev["event_id"] == 4625 and ev["source_ip"]:
            failures_by_ip[ev["source_ip"]].append((idx, ev))

    for ip, fail_list in failures_by_ip.items():
        if len(fail_list) >= 6:
            distinct_users = {ev["target_user"] or ev["username"] for _, ev in fail_list if (ev["target_user"] or ev["username"])}
            is_spray = len(distinct_users) >= 5
            success_hits = [
                (idx, ev) for idx, ev in enumerate(events)
                if ev["event_id"] == 4624 and ev["source_ip"] == ip
            ]
            compromised_user = success_hits[0][1]["target_user"] or success_hits[0][1]["username"] if success_hits else None

            questions = [
                {
                    "question_text": "[Phase 1: Source Attribution] Which Source IP address generated the burst of failed authentication attempts (Event ID 4625)?",
                    "correct_answer": ip,
                    "acceptable_answers": [ip.lower()],
                    "explanation": f"Source IP {ip} generated {len(fail_list)} failed logon events across {len(distinct_users)} distinct user account(s).",
                    "points": 20,
                }
            ]
            if compromised_user:
                questions.append({
                    "question_text": "[Phase 2: Compromised Account] Which account recorded a successful logon (Event ID 4624) from the attacking IP after the failures?",
                    "correct_answer": compromised_user.split("\\")[-1],
                    "acceptable_answers": list({compromised_user.lower(), compromised_user.split("\\")[-1].lower()}),
                    "explanation": f"Filtering by Source IP {ip} and Event ID 4624 reveals a successful authentication to '{compromised_user}'.",
                    "points": 25,
                })

            candidates.append({
                "score": 89,
                "confidence": f"High Confidence ({len(fail_list)} Failures Across {len(distinct_users)} Distinct Accounts)",
                "name": "Active Directory Password Spraying" if is_spray else "Active Directory Brute Force Authentication",
                "mitre_technique": "T1110.003" if is_spray else "T1110.001",
                "severity": "High",
                "alert_title": f"High Severity: {'Password Spraying' if is_spray else 'Brute Force'} from {ip}",
                "description": (
                    f"Observed {len(fail_list)} failed logon attempts (Event ID 4625) originating from {ip} "
                    f"targeting {len(distinct_users)} distinct account(s)"
                    + (f", followed by a successful logon (Event ID 4624) to '{compromised_user}'." if compromised_user else ".")
                ),
                "sigma_rule": """title: Active Directory Password Spraying Detected
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection | count(TargetUserName) by IpAddress > 5
level: high
tags:
  - attack.credential_access
  - attack.t1110.003""",
                "key_indices": {fail_list[0][0]} | {i for i, _ in success_hits},
                "evidence_summary": [
                    f"{len(fail_list)} Event 4625 failures from {ip} across {len(distinct_users)} distinct user(s)",
                    f"{len(success_hits)} subsequent Event 4624 success(es) from {ip}",
                ],
                "caveats": [
                    "Misconfigured service or scheduled task credentials on a single host typically fail repeatedly on 1 account, whereas spraying targets many distinct accounts."
                ],
                "questions": questions,
            })

    if candidates:
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates[0]

    # ── FALLBACK: General Incident Triage (When No Known Attack Signature Matches)
    ev_counter = Counter(ev["event_id"] for ev in events if ev["event_id"])
    top_ev_id = str(ev_counter.most_common(1)[0][0]) if ev_counter else "4624"
    hosts = [ev["target_host"] for ev in events if ev["target_host"]]
    primary_host = hosts[0] if hosts else None

    fallback_questions = [
        {
            "question_text": "[Phase 1: Telemetry Inventory] Which Windows Event ID occurs most frequently in this log capture?",
            "correct_answer": top_ev_id,
            "acceptable_answers": [top_ev_id],
            "explanation": f"Event ID {top_ev_id} is the highest-volume event in the dataset ({ev_counter.get(int(top_ev_id), 0)} occurrences).",
            "points": 15,
        }
    ]
    if primary_host:
        fallback_questions.append({
            "question_text": "[Phase 2: Endpoint Identification] What is the primary hostname recorded in the event logs?",
            "correct_answer": primary_host,
            "acceptable_answers": list({primary_host.lower(), primary_host.split(".")[0].lower()}),
            "explanation": f"The logs were generated by host '{primary_host}'.",
            "points": 15,
        })

    return {
        "score": 40,
        "confidence": "General Triage (No Pre-Configured Attack Signature Matched)",
        "name": f"Windows Event Log Triage ({primary_host or 'Endpoint Capture'})",
        "mitre_technique": "T1078",
        "severity": "Medium",
        "alert_title": "Medium Severity: Unclassified Windows Telemetry Anomalies for Analyst Review",
        "description": (
            f"Ingested {len(events)} Windows event logs. No deterministic high-confidence attack signature "
            "matched automatically. Review the extracted environment telemetry, customize the investigation "
            "questions below, and verify any suspicious activity before publishing."
        ),
        "sigma_rule": f"""title: Custom Windows Event Triage (Event {top_ev_id})
status: experimental
logsource:
  product: windows
detection:
  selection:
    EventID: {top_ev_id}
  condition: selection
level: medium""",
        "key_indices": set(),
        "evidence_summary": [
            f"Analyzed {len(events)} events across {len(ev_counter)} distinct Event IDs.",
            "No built-in high-confidence attack rule matched; generated baseline triage draft for Admin customization.",
        ],
        "caveats": [
            "Review the logs and customize the questions/answers before publishing this scenario to trainees."
        ],
        "questions": fallback_questions,
    }


def smart_curate_events(events: list[dict], key_indices: set[int], target_count: int = 350) -> list[dict]:
    """
    Guarantees 100% of matched key evidence events are preserved, fills up to 75% with
    high-priority security Event IDs, and samples background noise chronologically.
    """
    total = len(events)
    for idx, ev in enumerate(events):
        ev["is_key_evidence"] = (idx in key_indices)

    if total <= target_count:
        return events

    key_records = [(idx, ev) for idx, ev in enumerate(events) if idx in key_indices]
    priority_records = [
        (idx, ev) for idx, ev in enumerate(events)
        if idx not in key_indices and ev["event_id"] in PRIORITY_EVENT_IDS
    ]
    bg_records = [
        (idx, ev) for idx, ev in enumerate(events)
        if idx not in key_indices and ev["event_id"] not in PRIORITY_EVENT_IDS
    ]

    remaining_after_keys = max(0, target_count - len(key_records))
    max_priority = int(remaining_after_keys * 0.75)

    if len(priority_records) > max_priority and max_priority > 0:
        step = max(1, len(priority_records) // max_priority)
        chosen_priority = priority_records[::step][:max_priority]
    else:
        chosen_priority = priority_records[:max_priority]

    remaining_bg = max(0, target_count - len(key_records) - len(chosen_priority))
    if remaining_bg > 0 and bg_records:
        step_bg = max(1, len(bg_records) // remaining_bg)
        chosen_bg = bg_records[::step_bg][:remaining_bg]
    else:
        chosen_bg = []

    combined = sorted(key_records + chosen_priority + chosen_bg, key=lambda x: x[0])
    return [x[1] for x in combined]


def analyze_zip_archive(content: bytes, target_sample_count: int = 350) -> dict[str, Any]:
    """Full pipeline entrypoint: intake -> normalize all -> detect & correlate -> extract AD -> draft."""
    events, files_processed = stream_and_normalize_zip(content)
    if not events:
        raise ValueError("No valid JSON or JSONL Windows event records were found inside the ZIP archive.")

    detection = evaluate_detection_rules(events)
    ad_context = extract_observed_ad_context(events)

    key_evs = [events[i] for i in sorted(detection["key_indices"])] if detection["key_indices"] else events[:5]
    inferred_host = next((e["target_host"] for e in key_evs if e.get("target_host")), "")
    inferred_user = next(
        (
            (e["target_user"] or e["subject_user"] or e["username"]).split("\\")[-1].split("@")[0]
            for e in key_evs
            if (e.get("target_user") or e.get("subject_user") or e.get("username"))
            and not str(e.get("target_user") or e.get("subject_user") or e.get("username")).endswith("$")
            and str(e.get("target_user") or e.get("subject_user") or e.get("username")).upper() not in ("SYSTEM", "ANONYMOUS LOGON")
        ),
        "",
    )
    ad_context["containment_targets"] = {
        "isolate_host": inferred_host,
        "disable_user": inferred_user,
    }

    # Ensure every auto-generated question has both a Free Starter Hint and a Paid Forensic Hint
    for q in detection["questions"]:
        q.setdefault(
            "free_hint",
            "Filter by the Event ID in the Sigma Rule and expand the suspicious event in the Log Inspector.",
        )
        q.setdefault(
            "hint",
            q.get("explanation") or f"Inspect the key evidence event fields for '{q['correct_answer']}'.",
        )

    curated = smart_curate_events(events, detection["key_indices"], target_sample_count)

    return {
        "files_processed": files_processed,
        "total_events_in_archive": len(events),
        "curated_events_count": len(curated),
        "key_evidence_count": len(detection["key_indices"]),
        "confidence": detection["confidence"],
        "evidence_summary": detection["evidence_summary"],
        "caveats": detection["caveats"],
        "draft": {
            "name": detection["name"],
            "description": detection["description"],
            "mitre_technique": detection["mitre_technique"],
            "status": "Draft",
            "alert_title": detection["alert_title"],
            "alert_severity": detection["severity"],
            "sigma_rule": detection["sigma_rule"],
            "ad_context": ad_context,
            "questions": detection["questions"],
        },
        "curated_events": curated,
    }
