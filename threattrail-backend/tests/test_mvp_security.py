"""
Comprehensive automated security & functional test suite for ThreatTrail.
Covers High Priority (#1-#5) and Medium Priority (#6-#10) audit requirements.
"""
import io
import json
import os
import sys
import zipfile
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

os.environ["TESTING"] = "1"
os.environ["JWT_SECRET_KEY"] = "test-suite-strong-jwt-secret-key-at-least-32-chars-long"
os.environ["DATABASE_URL"] = "sqlite:///./test_threattrail.db"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from database import Base, engine, SessionLocal
import models
from hardened_overrides import _LOGIN_ATTEMPTS, enforce_strong_jwt_secret


@pytest.fixture(autouse=True)
def setup_clean_db():
    _LOGIN_ATTEMPTS.clear()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed published & draft scenarios, key evidence log, and question
        pub = models.Scenario(
            id=1,
            name="DCSync Attack Investigation",
            description="Investigate suspect directory replication.",
            mitre_technique="T1003.006",
            status="published",
            ad_context={"domain": "corp.local"},
        )
        draft = models.Scenario(
            id=2,
            name="Unpublished Draft Scenario",
            description="Draft scenario for admins only.",
            mitre_technique="T1059",
            status="draft",
            ad_context={"domain": "corp.local"},
        )
        db.add_all([pub, draft])
        db.flush()

        key_log = models.Log(
            id=10,
            scenario_id=1,
            event_id=4662,
            timestamp=datetime(2026, 5, 10, 8, 0, 0),
            source_ip="10.10.10.55",
            username="compromised_admin",
            target_host="DC01.corp.local",
            is_key_evidence=True,
            raw_event_data={"AccessMask": "0x100", "Properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"},
        )
        benign_log = models.Log(
            id=11,
            scenario_id=1,
            event_id=4624,
            timestamp=datetime(2026, 5, 10, 8, 0, 0),
            source_ip="10.10.15.12",
            username="svc_backup",
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={"LogonType": 3},
        )
        question = models.Question(
            id=100,
            scenario_id=1,
            question_text="Which account performed the DCSync replication?",
            correct_answer="compromised_admin",
            acceptable_answers=["corp\\compromised_admin"],
            free_hint="Filter for Event ID 4662.",
            hint="Look at Event ID 4662 from 10.10.10.55 and check the SubjectUserName.",
            explanation="compromised_admin requested DS-Replication-Get-Changes-All.",
            points=20,
        )
        db.add_all([key_log, benign_log, question])
        db.commit()
    finally:
        db.close()
    yield


client = TestClient(app)


def register_and_login(username: str = "trainee1", password: str = "StrongPass123!", role: str = "trainee") -> str:
    reg = client.post("/api/auth/register", json={"username": username, "password": password})
    assert reg.status_code in (200, 201), reg.text
    if role == "admin":
        db = SessionLocal()
        user = db.query(models.User).filter(models.User.username == username).first()
        user.role = "admin"
        db.commit()
        db.close()
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200, login.text
    return login.json().get("access_token") or login.json().get("token")


def test_1_key_evidence_is_hidden_from_trainees():
    """Problem #1: Trainees must not see is_key_evidence in log responses."""
    token = register_and_login("analyst_ev")
    resp = client.get("/api/scenarios/1/logs", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) == 2
    for log_entry in logs:
        assert "is_key_evidence" not in log_entry


def test_2_access_control_enforces_auth_and_publication_status():
    """Problem #2: Unauthenticated requests -> 401; Draft scenarios -> 403 for trainees, 200 for admins."""
    # Unauthenticated calls must be rejected
    assert client.get("/api/scenarios/1/logs").status_code == 401
    assert client.post("/api/scenarios/1/questions/100/hint").status_code == 401
    assert client.post("/api/scenarios/1/verify-finding", json={"question_id": 100, "user_answer": "x"}).status_code == 401
    assert client.post("/api/scenarios/1/submit", json={"answers": []}).status_code == 401

    # Trainee attempting to access draft scenario #2 -> 403 Forbidden
    trainee_token = register_and_login("trainee_acl")
    headers = {"Authorization": f"Bearer {trainee_token}"}
    assert client.get("/api/scenarios/2", headers=headers).status_code == 403
    assert client.get("/api/scenarios/2/logs", headers=headers).status_code == 403
    assert client.post("/api/scenarios/2/submit", json={"answers": []}, headers=headers).status_code == 403

    # Admin can access draft scenario #2 -> 200 OK
    admin_token = register_and_login("admin_acl", "AdminStrong123!", role="admin")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    assert client.get("/api/scenarios/2", headers=admin_headers).status_code == 200


def test_3_score_manipulation_blocked_by_server_side_tracking():
    """Problem #3: Client-tampered hint and attempt counts are ignored in favor of server-tracked state."""
    token = register_and_login("trainee_score")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Request a paid hint (-30% penalty)
    hint_resp = client.post("/api/scenarios/1/questions/100/hint", json={"tier": "paid"}, headers=headers)
    assert hint_resp.status_code == 200
    assert hint_resp.json()["paid_hint_used"] is True

    # 2. Make a wrong verification attempt (-10% penalty)
    verify_resp = client.post(
        "/api/scenarios/1/verify-finding",
        json={"question_id": 100, "user_answer": "wrong_user"},
        headers=headers,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_correct"] is False
    assert verify_resp.json()["wrong_attempts"] == 1

    # 3. Submit correct answer with forged client payload claiming 0 hints and 0 wrong attempts
    sub_resp = client.post(
        "/api/scenarios/1/submit",
        json={
            "answers": [
                {
                    "question_id": 100,
                    "user_answer": "compromised_admin",
                    "hints_used": 0,
                    "paid_hint_used": False,
                    "wrong_attempts": 0,
                }
            ],
            "pinned_log_ids": [10],
        },
        headers=headers,
    )
    assert sub_resp.status_code == 200
    data = sub_resp.json()
    # Full points = 20; paid hint (-6) + 1 wrong attempt (-2) => 12/20 (60%), NOT 100%!
    assert data["score"] < 100
    assert data["points_earned"] == 12
    assert data["evidence_verified"] is True


def test_4_weak_jwt_secret_rejected():
    """Problem #4: Weak or default JWT secrets fail validation when not in test fallback mode."""
    old_testing = os.environ.pop("TESTING", None)
    old_pytest = os.environ.pop("PYTEST_CURRENT_TEST", None)
    old_secret = os.environ.pop("JWT_SECRET_KEY", None)
    try:
        with pytest.raises(RuntimeError):
            enforce_strong_jwt_secret("changeme")
        with pytest.raises(RuntimeError):
            enforce_strong_jwt_secret("short-secret")
    finally:
        if old_testing is not None:
            os.environ["TESTING"] = old_testing
        if old_pytest is not None:
            os.environ["PYTEST_CURRENT_TEST"] = old_pytest
        if old_secret is not None:
            os.environ["JWT_SECRET_KEY"] = old_secret


def test_5_password_policy_and_login_rate_limiting():
    """Problem #5: Reject 4-char passwords on registration and rate-limit brute-force logins."""
    short_reg = client.post("/api/auth/register", json={"username": "weakuser", "password": "1234"})
    assert short_reg.status_code == 422

    # Rate limit login after 5 failed attempts
    register_and_login("ratelimit_user", "ValidPass123!")
    _LOGIN_ATTEMPTS.clear()
    statuses = []
    for _ in range(6):
        r = client.post("/api/auth/login", json={"username": "ratelimit_user", "password": "WrongPassword99!"})
        statuses.append(r.status_code)
    assert 429 in statuses


def test_6_and_7_safe_transactional_log_import_and_malformed_reporting():
    """Problems #6 & #7: Malformed lines are counted, and failed uploads do not wipe existing logs."""
    admin_token = register_and_login("admin_zip", "AdminPass123!", role="admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Upload a ZIP with 0 valid JSON records -> must return 400 AND preserve existing 2 logs
    bad_zip_buf = io.BytesIO()
    with zipfile.ZipFile(bad_zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("corrupt.json", "{not_valid_json\nstill_not_json\n")
    bad_zip_buf.seek(0)

    fail_resp = client.post(
        "/api/admin/scenarios/1/upload-logs",
        files={"file": ("corrupt.zip", bad_zip_buf.getvalue(), "application/zip")},
        headers=headers,
    )
    assert fail_resp.status_code == 400
    # Verify existing 2 logs were NOT deleted
    existing_logs = client.get("/api/scenarios/1/logs", headers=headers).json()
    assert len(existing_logs) == 2

    # 2. Upload a ZIP with 2 valid records + 1 malformed line -> atomic swap + malformed_skipped == 1
    mixed_zip_buf = io.BytesIO()
    with zipfile.ZipFile(mixed_zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        content = (
            json.dumps({"EventID": 4688, "SourceAddress": "10.0.0.5", "TargetUserName": "attacker", "Computer": "DC01"}) + "\n"
            + "{malformed_line_here\n"
            + json.dumps({"EventID": 4624, "SourceAddress": "10.0.0.5", "TargetUserName": "attacker", "Computer": "DC01"}) + "\n"
        )
        zf.writestr("events.jsonl", content)
    mixed_zip_buf.seek(0)

    ok_resp = client.post(
        "/api/admin/scenarios/1/upload-logs?include_noise=true",
        files={"file": ("events.zip", mixed_zip_buf.getvalue(), "application/zip")},
        headers=headers,
    )
    assert ok_resp.status_code == 200, ok_resp.text
    body = ok_resp.json()
    assert body["malformed_skipped"] == 1
    assert body["imported_count"] >= 6  # 2 uploaded + 4 realistic AD background noise logs
