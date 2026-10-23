import os as _os, sys as _sys
"""
Seed script — populates ThreatTrail with 2 realistic, noisy Active Directory scenarios:
  1. Active Directory Password Spraying (MITRE T1110.003) — ~110 events
  2. Kerberoasting Service Account Abuse (MITRE T1558.003) — ~95 events
"""

from datetime import datetime, timedelta
import random
import bcrypt
from database import engine, SessionLocal, Base
from models import User, Scenario, Alert, Log, Question, SeverityLevel

random.seed(42)

(_os.getenv("FORCE_RESET_DB") == "1" or "--reset" in _sys.argv) and Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
print("[+] Tables recreated.")

db = SessionLocal()

try:
    admin_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
    analyst_hash = bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode("utf-8")

    db.add(User(username="admin", password_hash=admin_hash, role="admin"))
    db.add(User(username="analyst", password_hash=analyst_hash, role="user"))
    db.flush()

    normal_users = ["alice.tesfaye", "bob.miller", "claire.chen", "david.kim", "elena.rossi", "frank.wright", "grace.lin"]
    normal_ips = ["10.0.1.14", "10.0.1.22", "10.0.1.35", "10.0.1.48", "10.0.2.19", "10.0.2.61"]
    workstations = ["WS-FIN-01", "WS-HR-04", "WS-DEV-02", "WS-MKT-07", "WS-OPS-03"]

    # =========================================================================
    # SCENARIO 1: PASSWORD SPRAYING (MITRE T1110.003) — ~110 Logs
    # =========================================================================
    sc1_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "high_value_accounts": [
            {"username": "svc_backup", "groups": ["Backup Operators", "Domain Users"], "note": "Legacy backup service account; excluded from MFA"},
            {"username": "adm_kaleb", "groups": ["Domain Admins"], "note": "Tier-0 Administrator"}
        ],
        "lockout_policy": "5 failed attempts within 30 minutes locks account for 15 minutes",
    }

    sc1 = Scenario(
        name="Active Directory Password Spraying",
        description=(
            "A threat actor is attempting to authenticate across multiple Active Directory user accounts "
            "using a single commonly-used password ('Spring2024!') amidst normal corporate domain traffic. "
            "Filter through the background domain authentication noise, inspect the Sigma rule, and identify "
            "the attacker's IP and compromised service account."
        ),
        mitre_technique="T1110.003",
        status="Published",
        ad_context=sc1_ad_context,
    )
    db.add(sc1)
    db.flush()

    sc1_sigma = """title: Active Directory Password Spraying Detected
id: 6d2c8e1a-9f4b-4b11-8c33-1a2b3c4d5e6f
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
    SubStatus: '0xC000006A'
  timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
level: high
tags:
  - attack.credential_access
  - attack.t1110.003"""

    db.add(Alert(
        scenario_id=sc1.id,
        title="High Severity: Password Spraying — Multiple Distinct Accounts Failed From Single IP",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc1_sigma,
    ))

    ATTACKER_IP = "10.0.5.22"
    TARGET_HOST = "DC01.corp.local"
    COMPROMISED_USER = "svc_backup"
    base_time = datetime(2025, 3, 15, 2, 10, 0)

    sc1_logs = []

    # Generate 90 benign background domain events (4624, 4768, 4672, and 2 benign user typo 4625s)
    for idx in range(90):
        ts = base_time + timedelta(seconds=idx * 5 + random.randint(0, 2))
        u = random.choice(normal_users)
        ip = random.choice(normal_ips)
        ws = random.choice(workstations)
        ev_choice = random.choices([4624, 4768, 4672, 4625], weights=[60, 25, 12, 3])[0]

        if ev_choice == 4624:
            msg = (
                f"An account was successfully logged on.\r\n\r\n"
                f"Subject:\r\n\tAccount Name:\t-\r\n\r\n"
                f"Logon Information:\r\n\tLogon Type:\t3\r\n"
                f"New Logon:\r\n\tAccount Name:\t{u}\r\n\tAccount Domain:\tCORP\r\n"
                f"Network Information:\r\n\tWorkstation Name:\t{ws}\r\n\tSource Network Address:\t{ip}\r\n"
                f"Authentication Information:\r\n\tAuthentication Package:\tKerberos\r\n"
            )
        elif ev_choice == 4768:
            msg = (
                f"A Kerberos authentication ticket (TGT) was requested.\r\n\r\n"
                f"Account Information:\r\n\tAccount Name:\t{u}\r\n\tSupplied Realm Name:\tCORP.LOCAL\r\n"
                f"Network Information:\r\n\tClient Address:\t{ip}\r\n"
                f"Additional Information:\r\n\tTicket Encryption Type:\t0x12\r\n"
            )
        elif ev_choice == 4672:
            msg = (
                f"Special privileges assigned to new logon.\r\n\r\n"
                f"Subject:\r\n\tAccount Name:\t{u}\r\n\tAccount Domain:\tCORP\r\n"
                f"Privileges:\tSeSecurityPrivilege\r\n"
            )
        else:
            msg = (
                f"An account failed to log on.\r\n\r\n"
                f"Logon Information:\r\n\tLogon Type:\t2\r\n"
                f"Account For Which Logon Failed:\r\n\tAccount Name:\t{u}\r\n\tAccount Domain:\tCORP\r\n"
                f"Failure Information:\r\n\tStatus:\t0xC000006D\r\n\tSub Status:\t0xC000006A\r\n"
                f"Network Information:\r\n\tWorkstation Name:\t{ws}\r\n\tSource Network Address:\t{ip}\r\n"
            )

        sc1_logs.append(Log(
            scenario_id=sc1.id,
            event_id=ev_choice,
            timestamp=ts,
            source_ip=ip,
            username=u,
            target_host=TARGET_HOST,
            is_key_evidence=False,
            raw_event_data={
                "EventID": ev_choice,
                "TimeCreated": ts.isoformat(),
                "Hostname": TARGET_HOST,
                "Channel": "Security",
                "TargetUserName": u,
                "IpAddress": ip,
                "WorkstationName": ws,
                "Message": msg,
            },
        ))

    # Inject the 15 Password Spraying failed logons (4625) + 1 successful logon (4624) + 1 privilege escalation (4672)
    spray_start = base_time + timedelta(minutes=3, seconds=10)
    spray_targets = [
        "jsmith", "agarcia", "mwilliams", "kjohnson", "lbrown",
        "dlee", "rmartin", "pthompson", "cwilson", "nanderson",
        "btaylor", "hmoore", "fwhite", "eharris", "jclark",
    ]

    for i, target_user in enumerate(spray_targets):
        ts = spray_start + timedelta(seconds=i * 3)
        sc1_logs.append(Log(
            scenario_id=sc1.id,
            event_id=4625,
            timestamp=ts,
            source_ip=ATTACKER_IP,
            username=target_user,
            target_host=TARGET_HOST,
            is_key_evidence=(i == 0),
            raw_event_data={
                "EventID": 4625,
                "SourceName": "Microsoft-Windows-Security-Auditing",
                "TimeCreated": ts.isoformat(),
                "Hostname": TARGET_HOST,
                "Channel": "Security",
                "Keywords": "Audit Failure",
                "LogonType": 3,
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "TargetUserName": target_user,
                "IpAddress": ATTACKER_IP,
                "Message": (
                    f"An account failed to log on.\r\n\r\n"
                    f"Subject:\r\n\tSecurity ID:\tS-1-0-0\r\n\tAccount Name:\t-\r\n\r\n"
                    f"Logon Information:\r\n\tLogon Type:\t3\r\n"
                    f"Account For Which Logon Failed:\r\n\tAccount Name:\t{target_user}\r\n\tAccount Domain:\tCORP\r\n"
                    f"Failure Information:\r\n\tFailure Reason:\tUnknown user name or bad password.\r\n"
                    f"\tStatus:\t0xC000006D\r\n\tSub Status:\t0xC000006A\r\n\r\n"
                    f"Network Information:\r\n\tWorkstation Name:\tATTACKER-WS\r\n"
                    f"\tSource Network Address:\t{ATTACKER_IP}\r\n\tSource Port:\t{49152 + i}\r\n"
                    f"Authentication Information:\r\n\tAuthentication Package:\tNTLM\r\n"
                ),
            },
        ))

    success_ts = spray_start + timedelta(seconds=len(spray_targets) * 3 + 4)
    sc1_logs.append(Log(
        scenario_id=sc1.id,
        event_id=4624,
        timestamp=success_ts,
        source_ip=ATTACKER_IP,
        username=COMPROMISED_USER,
        target_host=TARGET_HOST,
        is_key_evidence=True,
        raw_event_data={
            "EventID": 4624,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": success_ts.isoformat(),
            "Hostname": TARGET_HOST,
            "Channel": "Security",
            "Keywords": "Audit Success",
            "LogonType": 3,
            "TargetUserName": COMPROMISED_USER,
            "IpAddress": ATTACKER_IP,
            "Message": (
                f"An account was successfully logged on.\r\n\r\n"
                f"Subject:\r\n\tSecurity ID:\tS-1-0-0\r\n\tAccount Name:\t-\r\n\r\n"
                f"Logon Information:\r\n\tLogon Type:\t3\r\n"
                f"New Logon:\r\n\tAccount Name:\t{COMPROMISED_USER}\r\n\tAccount Domain:\tCORP\r\n"
                f"Network Information:\r\n\tWorkstation Name:\tATTACKER-WS\r\n"
                f"\tSource Network Address:\t{ATTACKER_IP}\r\n\tSource Port:\t{49152 + 16}\r\n"
                f"Authentication Information:\r\n\tAuthentication Package:\tNTLM\r\n"
            ),
        },
    ))

    sc1_logs.sort(key=lambda x: x.timestamp)
    db.add_all(sc1_logs)

    db.add_all([
        Question(
            scenario_id=sc1.id,
            question_text="What is the source IP address performing the password spray?",
            correct_answer="10.0.5.22",
            acceptable_answers=["10.0.5.22"],
            explanation="While several internal IPs generate normal Kerberos logons, 10.0.5.22 generated 15 sequential NTLM Event 4625 failures followed by a 4624 success.",
            points=10,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="Which account was successfully compromised at the end of the spray?",
            correct_answer="svc_backup",
            acceptable_answers=["corp\\svc_backup", "svc_backup@corp.local"],
            explanation="Filtering by Source IP 10.0.5.22 and Event ID 4624 reveals a successful logon to 'svc_backup'.",
            points=25,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="What is the MITRE ATT&CK sub-technique ID for Password Spraying?",
            correct_answer="T1110.003",
            acceptable_answers=["T1110"],
            explanation="T1110.003 is Brute Force: Password Spraying.",
            points=15,
        ),
    ])

    # =========================================================================
    # SCENARIO 2: KERBEROASTING (MITRE T1558.003) — ~95 Logs
    # =========================================================================
    sc2_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "service_accounts_with_spn": [
            {"username": "svc_mssql", "spn": "MSSQLSvc/SQL01.corp.local:1433", "encryption": "RC4-HMAC (0x17)", "member_of": ["Domain Admins"]},
            {"username": "svc_iis", "spn": "HTTP/WEB01.corp.local", "encryption": "AES256 (0x12)", "member_of": ["Domain Users"]},
            {"username": "svc_exchange", "spn": "exchangeMDB/EX01.corp.local", "encryption": "AES256 (0x12)", "member_of": ["Domain Users"]}
        ],
    }

    sc2 = Scenario(
        name="Kerberoasting Service Account Abuse",
        description=(
            "An attacker with a foothold on a domain workstation enumerated SPNs and requested a "
            "Kerberos TGS service ticket (Event ID 4769) downgraded to legacy RC4 encryption (0x17) "
            "to crack the service account password offline. Filter through normal Kerberos domain "
            "traffic to isolate the RC4 downgrade request."
        ),
        mitre_technique="T1558.003",
        status="Published",
        ad_context=sc2_ad_context,
    )
    db.add(sc2)
    db.flush()

    sc2_sigma = """title: Kerberoasting - RC4 Ticket Encryption Requested (Event 4769)
id: 8f1e2a3b-4c5d-4e6f-9a8b-7c6d5e4f3a2b
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
tags:
  - attack.credential_access
  - attack.t1558.003"""

    db.add(Alert(
        scenario_id=sc2.id,
        title="High Severity: Kerberos TGS Request Using Legacy RC4 Encryption (0x17)",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc2_sigma,
    ))

    kb_base = datetime(2025, 3, 16, 14, 15, 0)
    sc2_logs = []
    services = ["DC01$", "SQL01$", "WEB01$", "EX01$", "svc_iis", "svc_exchange", "krbtgt"]

    # 92 legitimate Kerberos & Logon events (all using 0x12 AES256 or machine '$' accounts)
    for idx in range(92):
        ts = kb_base + timedelta(seconds=idx * 6 + random.randint(0, 3))
        u = f"{random.choice(normal_users)}@CORP.LOCAL"
        ip = random.choice(normal_ips)
        svc = random.choice(services)
        ev_id = random.choices([4769, 4768, 4624], weights=[55, 25, 20])[0]

        if ev_id == 4769:
            msg = (
                f"A Kerberos service ticket was requested.\r\n\r\n"
                f"Account Information:\r\n\tAccount Name:\t{u}\r\n\tAccount Domain:\tCORP.LOCAL\r\n"
                f"Service Information:\r\n\tService Name:\t{svc}\r\n"
                f"Network Information:\r\n\tClient Address:\t{ip}\r\n"
                f"Additional Information:\r\n\tTicket Options:\t0x40810010\r\n"
                f"\tTicket Encryption Type:\t0x12\r\n"
            )
        elif ev_id == 4768:
            msg = (
                f"A Kerberos authentication ticket (TGT) was requested.\r\n\r\n"
                f"Account Information:\r\n\tAccount Name:\t{u}\r\n"
                f"Service Information:\r\n\tService Name:\tkrbtgt\r\n"
                f"Network Information:\r\n\tClient Address:\t{ip}\r\n"
                f"Additional Information:\r\n\tTicket Encryption Type:\t0x12\r\n"
            )
        else:
            msg = (
                f"An account was successfully logged on.\r\n\r\n"
                f"New Logon:\r\n\tAccount Name:\t{u}\r\n\tAccount Domain:\tCORP.LOCAL\r\n"
                f"Network Information:\r\n\tSource Network Address:\t{ip}\r\n"
            )

        sc2_logs.append(Log(
            scenario_id=sc2.id,
            event_id=ev_id,
            timestamp=ts,
            source_ip=ip,
            username=u,
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={
                "EventID": ev_id,
                "TimeCreated": ts.isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": u,
                "ServiceName": svc if ev_id != 4624 else "-",
                "TicketEncryptionType": "0x12" if ev_id in (4768, 4769) else "-",
                "IpAddress": ip,
                "Message": msg,
            },
        ))

    # Inject attacker foothold logon (4624) + PowerShell SPN enumeration (4688) + Malicious RC4 TGS (4769)
    atk_ts = kb_base + timedelta(minutes=4, seconds=18)
    sc2_logs.extend([
        Log(
            scenario_id=sc2.id,
            event_id=4624,
            timestamp=atk_ts,
            source_ip="10.0.2.88",
            username="jdoe@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={
                "EventID": 4624,
                "TimeCreated": atk_ts.isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "jdoe@CORP.LOCAL",
                "LogonType": 3,
                "IpAddress": "10.0.2.88",
                "Message": "An account was successfully logged on.\r\nNew Logon:\r\n\tAccount Name:\tjdoe@CORP.LOCAL\r\nNetwork Information:\r\n\tSource Network Address:\t10.0.2.88",
            },
        ),
        Log(
            scenario_id=sc2.id,
            event_id=4769,
            timestamp=atk_ts + timedelta(seconds=5),
            source_ip="10.0.2.88",
            username="jdoe@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=True,
            raw_event_data={
                "EventID": 4769,
                "TimeCreated": (atk_ts + timedelta(seconds=5)).isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "jdoe@CORP.LOCAL",
                "ServiceName": "svc_mssql",
                "SPN": "MSSQLSvc/SQL01.corp.local:1433",
                "TicketEncryptionType": "0x17",
                "TicketOptions": "0x40810000",
                "IpAddress": "10.0.2.88",
                "Message": (
                    "A Kerberos service ticket was requested.\r\n\r\n"
                    "Account Information:\r\n\tAccount Name:\tjdoe@CORP.LOCAL\r\n"
                    "\tAccount Domain:\tCORP.LOCAL\r\n"
                    "Service Information:\r\n\tService Name:\tsvc_mssql\r\n"
                    "\tService ID:\tS-1-5-21-3623811015-3361044348-30300820-1104\r\n"
                    "Network Information:\r\n\tClient Address:\t10.0.2.88\r\n"
                    "Additional Information:\r\n\tTicket Options:\t0x40810000\r\n"
                    "\tTicket Encryption Type:\t0x17\r\n"
                ),
            },
        ),
    ])

    sc2_logs.sort(key=lambda x: x.timestamp)
    db.add_all(sc2_logs)

    db.add_all([
        Question(
            scenario_id=sc2.id,
            question_text="Which domain user account requested the suspicious RC4 Kerberos service ticket?",
            correct_answer="jdoe",
            acceptable_answers=["jdoe@corp.local", "corp\\jdoe"],
            explanation="Filtering Event 4769 for TicketEncryptionType '0x17' isolates a single request from jdoe@CORP.LOCAL (10.0.2.88) amidst 90+ normal AES256 (0x12) events.",
            points=15,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="Which service account (Service Name) was targeted for offline cracking?",
            correct_answer="svc_mssql",
            acceptable_answers=["mssqlsvc/sql01.corp.local:1433"],
            explanation="The Service Name in the 0x17 RC4 Event 4769 is 'svc_mssql' (a member of Domain Admins).",
            points=20,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="What hex code in TicketEncryptionType indicates RC4-HMAC downgrade?",
            correct_answer="0x17",
            acceptable_answers=["17"],
            explanation="In Windows Kerberos Event 4769, 0x17 corresponds to RC4-HMAC, whereas 0x12 is AES256.",
            points=15,
        ),
    ])

    db.commit()
    print(f"[OK] Seeded Scenario 1 ({len(sc1_logs)} logs) & Scenario 2 ({len(sc2_logs)} logs)!")

except Exception as e:
    db.rollback()
    print(f"[FAIL] Seed failed: {e}")
    raise
finally:
    db.close()
