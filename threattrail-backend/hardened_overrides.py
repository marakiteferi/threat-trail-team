"""
Hardened security & investigation overrides for ThreatTrail.
Addresses:
  1. Key evidence exposure (strips is_key_evidence from trainee log responses)
  2. Access control (enforces authentication + published scenario status)
  3. Score manipulation (server-side QuestionAttempt tracking for hints & attempts)
  4. Strong JWT secret enforcement (rejects missing/default/short secrets)
  5. Strong password validation (8+ chars, letter + digit/symbol) & login rate limiting
  6. Safe streaming ZIP log imports with explicit malformed record reporting
  7. Atomic/transactional log replacement (validates new logs before deleting old ones)
  8. Automatic non-destructive startup migrations
  10. Evidence-backed answer grading, advanced log filtering, and realistic AD noise/false positives
"""
import io
import json
import os
import re
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db
from migrations import run_migrations

MAX_ZIP_UPLOAD_BYTES = 25 * 1024 * 1024       # 25 MB compressed upload limit
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024    # 100 MB uncompressed limit
CHUNK_SIZE = 64 * 1024                        # 64 KB streaming chunks

WEAK_SECRETS = {
    "",
    "secret",
    "changeme",
    "super-secret-key",
    "threattrail-default-secret",
    "your-secret-key-here",
    "default_jwt_secret",
}

_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
LOGIN_WINDOW_SECONDS = 60.0
LOGIN_MAX_ATTEMPTS = 5


def enforce_strong_jwt_secret(current_secret: Optional[str]) -> str:
    """Fix #4: Fail fast if JWT_SECRET_KEY is missing, a known default, or < 32 chars."""
    env_secret = os.getenv("JWT_SECRET_KEY", "").strip()
    is_test = os.getenv("TESTING") == "1" or "PYTEST_CURRENT_TEST" in os.environ

    candidate = env_secret or (current_secret or "").strip()
    if candidate.lower() in WEAK_SECRETS or len(candidate) < 32:
        if is_test:
            return "test-only-jwt-secret-key-with-at-least-32-bytes-length!"
        raise RuntimeError(
            "CRITICAL: JWT_SECRET_KEY environment variable must be set to a strong secret "
            "(at least 32 characters) and cannot use a default fallback."
        )
    return candidate


def check_login_rate_limit(client_key: str) -> None:
    """Fix #5: Strict per-IP/username login rate limiter."""
    now = time.monotonic()
    history = [ts for ts in _LOGIN_ATTEMPTS.get(client_key, []) if now - ts < LOGIN_WINDOW_SECONDS]
    if len(history) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait 60 seconds before trying again.",
        )
    history.append(now)
    _LOGIN_ATTEMPTS[client_key] = history


def clear_login_rate_limit(client_key: str) -> None:
    _LOGIN_ATTEMPTS.pop(client_key, None)


def validate_password_policy(password: str) -> None:
    """Fix #5: Reject passwords shorter than 8 chars or lacking basic complexity."""
    if not password or len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters long.",
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one letter and one number or special character.",
        )


def generate_background_noise_logs(scenario_id: int, base_time: Optional[datetime] = None) -> List[models.Log]:
    """Fix #10: Realistic AD background noise and false-positive decoy logs for SOC triage."""
    anchor = base_time or datetime(2026, 5, 10, 8, 0, 0)
    decoys = [
        {
            "event_id": 4624,
            "offset_sec": -180,
            "source_ip": "10.10.15.42",
            "username": "svc_monitoring",
            "target_host": "DC01.corp.local",
            "raw": {
                "Channel": "Security",
                "LogonType": 3,
                "AuthenticationPackageName": "Kerberos",
                "ProcessName": "-",
                "Message": "Routine network logon by monitoring agent svc_monitoring.",
                "noise_category": "benign_background",
            },
        },
        {
            "event_id": 4688,
            "offset_sec": -95,
            "source_ip": "10.10.15.20",
            "username": "SYSTEM",
            "target_host": "WS-FINANCE02.corp.local",
            "raw": {
                "Channel": "Security",
                "NewProcessName": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                "CommandLine": "\"MpCmdRun.exe\" -SignatureUpdate -ScheduleJob",
                "ParentProcessName": "C:\\Windows\\System32\\svchost.exe",
                "Message": "Scheduled Windows Defender signature update.",
                "noise_category": "benign_background",
            },
        },
        {
            "event_id": 4769,
            "offset_sec": -45,
            "source_ip": "10.10.10.99",
            "username": "adm_backup",
            "target_host": "DC01.corp.local",
            "raw": {
                "Channel": "Security",
                "ServiceName": "CIFS/FILESRV01.corp.local",
                "TicketEncryptionType": "0x12",
                "TicketOptions": "0x40810000",
                "Message": "False positive candidate: authorized AES Kerberos service ticket for nightly backup.",
                "noise_category": "false_positive_decoy",
            },
        },
        {
            "event_id": 4625,
            "offset_sec": 30,
            "source_ip": "10.10.22.14",
            "username": "j.doe",
            "target_host": "WS-HR01.corp.local",
            "raw": {
                "Channel": "Security",
                "LogonType": 2,
                "SubStatus": "0xC000006A",
                "FailureReason": "Userdy typo during interactive workstation unlock.",
                "Message": "Single interactive bad password attempt by j.doe (benign user error).",
                "noise_category": "false_positive_decoy",
            },
        },
    ]
    noise_models: List[models.Log] = []
    for item in decoys:
        noise_models.append(
            models.Log(
                scenario_id=scenario_id,
                event_id=item["event_id"],
                timestamp=anchor + timedelta(seconds=item["offset_sec"]),
                source_ip=item["source_ip"],
                username=item["username"],
                target_host=item["target_host"],
                is_key_evidence=False,
                raw_event_data=item["raw"],
            )
        )
    return noise_models


def apply_hardened_routes(app: Any, main_module: Any) -> None:
    """
    Replaces vulnerable route handlers on the FastAPI app with hardened versions
    while reusing main_module's auth helpers and grading utilities.
    """
    run_migrations()

    # Enforce strong JWT secret on main_module
    strong_secret = enforce_strong_jwt_secret(getattr(main_module, "SECRET_KEY", None))
    setattr(main_module, "SECRET_KEY", strong_secret)
    if hasattr(main_module, "JWT_SECRET_KEY"):
        setattr(main_module, "JWT_SECRET_KEY", strong_secret)

    get_current_user = getattr(main_module, "get_current_user")
    get_admin_user = getattr(main_module, "get_admin_user", None)
    is_answer_match = getattr(main_module, "is_answer_match", None)
    diagnose_analyst_mistake = getattr(main_module, "diagnose_analyst_mistake", None)

    def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
        if getattr(current_user, "role", None) != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
        return current_user

    admin_dep = get_admin_user or require_admin

    def get_accessible_scenario(
        scenario_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user),
    ) -> models.Scenario:
        """Fix #2: Enforce both authentication and scenario publication status."""
        scenario = db.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if not scenario:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scenario not found")
        if str(scenario.status or "").strip().lower() != "published" and str(getattr(current_user, "role", "trainee") or "").strip().lower() != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This scenario is not published yet.",
            )
        return scenario

    def serialize_trainee_log(log_obj: models.Log) -> Dict[str, Any]:
        """Fix #1: Never expose is_key_evidence in trainee log responses."""
        return {
            "id": log_obj.id,
            "scenario_id": log_obj.scenario_id,
            "event_id": log_obj.event_id,
            "timestamp": log_obj.timestamp.isoformat() if hasattr(log_obj.timestamp, "isoformat") else log_obj.timestamp,
            "source_ip": log_obj.source_ip,
            "username": log_obj.username,
            "target_host": log_obj.target_host,
            "raw_event_data": log_obj.raw_event_data or {},
        }

    def check_answer(user_ans: str, question: models.Question) -> bool:
        if is_answer_match is not None:
            try:
                return bool(is_answer_match(user_ans, question.correct_answer, question.acceptable_answers))
            except TypeError:
                return bool(is_answer_match(user_ans, question))
        norm = (user_ans or "").strip().lower()
        if not norm:
            return False
        candidates = [str(question.correct_answer or "").strip().lower()]
        if isinstance(question.acceptable_answers, list):
            candidates.extend(str(a).strip().lower() for a in question.acceptable_answers)
        return norm in candidates

    # Remove existing routes that we are overriding so our hardened routes take precedence
    overridden_paths = {
        ("/api/scenarios", "GET"),
        ("/api/scenarios/{scenario_id}", "GET"),
        ("/api/scenarios/{scenario_id}/alerts", "GET"),
        ("/api/scenarios/{scenario_id}/logs", "GET"),
        ("/api/scenarios/{scenario_id}/questions", "GET"),
        ("/api/scenarios/{scenario_id}/questions/{question_id}/hint", "POST"),
        ("/api/scenarios/{scenario_id}/verify-finding", "POST"),
        ("/api/scenarios/{scenario_id}/submit", "POST"),
        ("/api/admin/scenarios/{scenario_id}/upload-logs", "POST"),
    }

    app.router.routes = [
        r for r in app.router.routes
        if not (
            hasattr(r, "path")
            and hasattr(r, "methods")
            and any((r.path, m) in overridden_paths for m in (r.methods or set()))
        )
    ]

    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    SEVERITY_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}

    def resolve_scenario_severity(db: Session, scenario: models.Scenario) -> str:
        if isinstance(scenario.ad_context, dict) and scenario.ad_context.get("severity"):
            raw = str(scenario.ad_context["severity"]).strip().lower()
            if raw in SEVERITY_RANK:
                return SEVERITY_LABEL[SEVERITY_RANK[raw]]
        alerts = db.query(models.Alert).filter(models.Alert.scenario_id == scenario.id).all()
        best_rank = 0
        for al in alerts:
            sev_val = getattr(al.severity, "value", al.severity)
            rank = SEVERITY_RANK.get(str(sev_val or "").strip().lower(), 0)
            if rank > best_rank:
                best_rank = rank
        return SEVERITY_LABEL.get(best_rank, "High")

    def resolve_optional_user(request: Request, db: Session) -> Optional[models.User]:
        auth_header = request.headers.get("Authorization") or ""
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return None
        try:
            from jose import jwt as _jwt
            algo = getattr(main_module, "ALGORITHM", "HS256")
            payload = _jwt.decode(token, strong_secret, algorithms=[algo])
            uname = payload.get("sub")
            if uname:
                return db.query(models.User).filter(models.User.username == uname).first()
        except Exception:
            return None
        return None

    def enrich_scenario_dict(db: Session, scenario: models.Scenario, user: Optional[models.User] = None) -> Dict[str, Any]:
        sev = resolve_scenario_severity(db, scenario)
        q_count = db.query(models.Question).filter(models.Question.scenario_id == scenario.id).count()
        l_count = db.query(models.Log).filter(models.Log.scenario_id == scenario.id).count()
        alert = db.query(models.Alert).filter(models.Alert.scenario_id == scenario.id).first()
        alert_title = alert.title if alert else None

        trials_count = 0
        best_score = None
        last_score = None
        in_progress = False

        if user is not None:
            results = (
                db.query(models.InvestigationResult)
                .filter(
                    models.InvestigationResult.user_id == user.id,
                    models.InvestigationResult.scenario_id == scenario.id,
                )
                .order_by(models.InvestigationResult.id.asc())
                .all()
            )
            trials_count = len(results)
            if results:
                scores = [int(r.score or 0) for r in results]
                best_score = max(scores)
                last_score = int(results[-1].score or 0)

            active_attempts = (
                db.query(models.QuestionAttempt)
                .filter(
                    models.QuestionAttempt.user_id == user.id,
                    models.QuestionAttempt.scenario_id == scenario.id,
                )
                .all()
            )
            in_progress = any(
                a.free_hint_used or a.paid_hint_used or (a.wrong_attempts or 0) > 0 or a.is_solved
                for a in active_attempts
            )

        return {
            "id": scenario.id,
            "name": scenario.name,
            "description": scenario.description,
            "mitre_technique": scenario.mitre_technique,
            "status": scenario.status,
            "ad_context": scenario.ad_context,
            "severity": sev,
            "alert_title": alert_title,
            "trials_count": trials_count,
            "attempts_count": trials_count,
            "best_score": best_score,
            "last_score": last_score,
            "in_progress": in_progress,
            "question_count": q_count,
            "log_count": l_count,
        }

    router = APIRouter()

    @router.get("/api/scenarios", response_model=List[schemas.ScenarioOut])
    def list_scenarios_hardened(
        request: Request,
        db: Session = Depends(get_db),
    ):
        user = resolve_optional_user(request, db)
        all_scenarios = db.query(models.Scenario).order_by(models.Scenario.id.asc()).all()
        is_admin = user is not None and str(getattr(user, "role", "")).strip().lower() == "admin"
        visible = [
            s for s in all_scenarios
            if is_admin or str(s.status or "").strip().lower() == "published"
        ]
        return [enrich_scenario_dict(db, s, user) for s in visible]

    @router.get("/api/scenarios/{scenario_id}", response_model=schemas.ScenarioOut)
    def get_scenario_hardened(
        request: Request,
        scenario: models.Scenario = Depends(get_accessible_scenario),
        db: Session = Depends(get_db),
    ):
        user = resolve_optional_user(request, db)
        return enrich_scenario_dict(db, scenario, user)

    @router.get("/api/scenarios/{scenario_id}/progress")
    def get_scenario_progress_hardened(
        scenario: models.Scenario = Depends(get_accessible_scenario),
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        questions = {
            q.id: q
            for q in db.query(models.Question).filter(models.Question.scenario_id == scenario.id).all()
        }
        attempts = (
            db.query(models.QuestionAttempt)
            .filter(
                models.QuestionAttempt.user_id == current_user.id,
                models.QuestionAttempt.scenario_id == scenario.id,
            )
            .all()
        )
        trials = (
            db.query(models.InvestigationResult)
            .filter(
                models.InvestigationResult.user_id == current_user.id,
                models.InvestigationResult.scenario_id == scenario.id,
            )
            .order_by(models.InvestigationResult.id.asc())
            .all()
        )

        question_progress: Dict[int, Dict[str, Any]] = {}
        for att in attempts:
            q = questions.get(att.question_id)
            if not q:
                continue
            free_text = (
                getattr(q, "free_hint", None)
                or getattr(q, "hint", None)
                or "Filter logs by the alerted host or user account."
            )
            paid_text = (
                getattr(q, "hint", None)
                or getattr(q, "free_hint", None)
                or "Inspect the correlated high-severity Event IDs around the alert timestamp."
            )
            question_progress[q.id] = {
                "question_id": q.id,
                "free_hint_used": bool(att.free_hint_used),
                "paid_hint_used": bool(att.paid_hint_used),
                "free_hint_text": free_text if att.free_hint_used else None,
                "paid_hint_text": paid_text if att.paid_hint_used else None,
                "wrong_attempts": int(att.wrong_attempts or 0),
                "is_solved": bool(att.is_solved),
                "verified_answer": q.correct_answer if att.is_solved else None,
            }

        scores = [int(t.score or 0) for t in trials]
        latest_pins: List[int] = []
        if trials:
            raw_pins = trials[-1].pinned_log_ids
            if isinstance(raw_pins, list):
                latest_pins = [int(x) for x in raw_pins if str(x).isdigit()]
        return {
            "scenario_id": scenario.id,
            "trials_count": len(trials),
            "best_score": max(scores) if scores else None,
            "last_score": scores[-1] if scores else None,
            "pinned_log_ids": latest_pins,
            "questions": question_progress,
        }

    @router.post("/api/scenarios/{scenario_id}/progress/reset")
    def reset_scenario_progress_hardened(
        scenario: models.Scenario = Depends(get_accessible_scenario),
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        db.query(models.QuestionAttempt).filter(
            models.QuestionAttempt.user_id == current_user.id,
            models.QuestionAttempt.scenario_id == scenario.id,
        ).delete(synchronize_session=False)
        db.commit()
        return {"message": "In-progress session reset", "scenario_id": scenario.id}

    @router.get("/api/profile/activity")
    def get_user_profile_activity(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        scenarios_by_id = {s.id: s for s in db.query(models.Scenario).all()}
        results = (
            db.query(models.InvestigationResult)
            .filter(models.InvestigationResult.user_id == current_user.id)
            .order_by(models.InvestigationResult.id.asc())
            .all()
        )
        active_attempts = (
            db.query(models.QuestionAttempt)
            .filter(models.QuestionAttempt.user_id == current_user.id)
            .all()
        )

        trial_counter_by_scenario: Dict[int, int] = {}
        activity_feed: List[Dict[str, Any]] = []
        for r in results:
            trial_counter_by_scenario[r.scenario_id] = trial_counter_by_scenario.get(r.scenario_id, 0) + 1
            sc = scenarios_by_id.get(r.scenario_id)
            sev = resolve_scenario_severity(db, sc) if sc else "High"
            pins = r.pinned_log_ids if isinstance(r.pinned_log_ids, list) else []
            activity_feed.append(
                {
                    "id": r.id,
                    "scenario_id": r.scenario_id,
                    "scenario_name": sc.name if sc else f"Scenario #{r.scenario_id}",
                    "mitre_technique": sc.mitre_technique if sc else "N/A",
                    "severity": sev,
                    "score": int(r.score or 0),
                    "points_earned": int(r.points_earned or 0),
                    "total_points": int(r.total_points or 100),
                    "trial_number": trial_counter_by_scenario[r.scenario_id],
                    "total_trials_for_scenario": 0,
                    "pinned_logs_count": len(pins),
                    "status": "Completed",
                    "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
                }
            )

        for item in activity_feed:
            item["total_trials_for_scenario"] = trial_counter_by_scenario.get(item["scenario_id"], 1)

        activity_feed.reverse()

        in_progress_sids = set()
        hints_used_count = 0
        wrong_guesses_count = 0
        for att in active_attempts:
            if att.free_hint_used:
                hints_used_count += 1
            if att.paid_hint_used:
                hints_used_count += 1
            wrong_guesses_count += int(att.wrong_attempts or 0)
            if att.free_hint_used or att.paid_hint_used or (att.wrong_attempts or 0) > 0 or att.is_solved:
                in_progress_sids.add(att.scenario_id)

        in_progress_items: List[Dict[str, Any]] = []
        for sid in sorted(in_progress_sids):
            sc = scenarios_by_id.get(sid)
            if not sc:
                continue
            sev = resolve_scenario_severity(db, sc)
            sid_atts = [a for a in active_attempts if a.scenario_id == sid]
            sid_wrong = sum(int(a.wrong_attempts or 0) for a in sid_atts)
            sid_hints = sum(1 for a in sid_atts if a.free_hint_used or a.paid_hint_used)
            solved_cnt = sum(1 for a in sid_atts if a.is_solved)
            q_total = db.query(models.Question).filter(models.Question.scenario_id == sid).count()
            in_progress_items.append(
                {
                    "scenario_id": sid,
                    "scenario_name": sc.name,
                    "mitre_technique": sc.mitre_technique,
                    "severity": sev,
                    "wrong_attempts": sid_wrong,
                    "attempts_count": sid_wrong + solved_cnt,
                    "hints_used": sid_hints,
                    "solved_questions": solved_cnt,
                    "total_questions": q_total,
                    "trials_completed": trial_counter_by_scenario.get(sid, 0),
                    "status": "In Progress",
                }
            )

        scores = [int(r.score or 0) for r in results]
        completed_attempts_count = sum(int(r.trials_count or 1) for r in results)
        total_all_attempts = completed_attempts_count + wrong_guesses_count + sum(1 for a in active_attempts if a.is_solved)
        return {
            "user_id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
            "total_attempts": total_all_attempts,
            "total_trials": len(results),
            "scenarios_completed": len(trial_counter_by_scenario),
            "scenarios_in_progress": len(in_progress_items),
            "average_score": int(round(sum(scores) / len(scores))) if scores else 0,
            "best_score": max(scores) if scores else 0,
            "active_hints_used": hints_used_count,
            "active_wrong_guesses": wrong_guesses_count,
            "in_progress": in_progress_items,
            "history": activity_feed,
        }

    @router.get("/api/scenarios/{scenario_id}/alerts", response_model=List[schemas.AlertOut])
    def get_scenario_alerts_hardened(
        scenario: models.Scenario = Depends(get_accessible_scenario),
        db: Session = Depends(get_db),
    ):
        return db.query(models.Alert).filter(models.Alert.scenario_id == scenario.id).all()

    @router.get("/api/scenarios/{scenario_id}/logs")
    def get_scenario_logs_hardened(
        scenario: models.Scenario = Depends(get_accessible_scenario),
        search: Optional[str] = Query(None, max_length=200),
        event_id: Optional[int] = Query(None),
        source_ip: Optional[str] = Query(None, max_length=100),
        username: Optional[str] = Query(None, max_length=100),
        target_host: Optional[str] = Query(None, max_length=100),
        exclude_noise: bool = Query(False, description="Filter out known benign background noise Event IDs"),
        limit: int = Query(500, ge=1, le=2000),
        offset: int = Query(0, ge=0),
        db: Session = Depends(get_db),
    ):
        """Fix #1, #2, #10: Authenticated + published-only log query with rich filtering and no is_key_evidence leak."""
        q = db.query(models.Log).filter(models.Log.scenario_id == scenario.id)
        if event_id is not None:
            q = q.filter(models.Log.event_id == event_id)
        if source_ip:
            q = q.filter(models.Log.source_ip.ilike(f"%{source_ip.strip()}%"))
        if username:
            q = q.filter(models.Log.username.ilike(f"%{username.strip()}%"))
        if target_host:
            q = q.filter(models.Log.target_host.ilike(f"%{target_host.strip()}%"))
        if exclude_noise:
            q = q.filter(~models.Log.event_id.in_([4634, 5156, 5158]))

        logs = q.order_by(models.Log.timestamp.asc(), models.Log.id.asc()).all()

        if search:
            needle = search.strip().lower()
            logs = [
                lg for lg in logs
                if needle in str(lg.event_id).lower()
                or needle in (lg.source_ip or "").lower()
                or needle in (lg.username or "").lower()
                or needle in (lg.target_host or "").lower()
                or needle in json.dumps(lg.raw_event_data or {}).lower()
            ]

        sliced = logs[offset : offset + limit]
        return [serialize_trainee_log(lg) for lg in sliced]

    @router.get("/api/scenarios/{scenario_id}/questions", response_model=List[schemas.QuestionOut])
    def get_scenario_questions_hardened(
        scenario: models.Scenario = Depends(get_accessible_scenario),
        db: Session = Depends(get_db),
    ):
        return db.query(models.Question).filter(models.Question.scenario_id == scenario.id).all()

    @router.post("/api/scenarios/{scenario_id}/questions/{question_id}/hint")
    def request_question_hint_hardened(
        scenario_id: int,
        question_id: int,
        payload: Optional[Dict[str, Any]] = Body(None),
        tier: str = Query("free"),
        scenario: models.Scenario = Depends(get_accessible_scenario),
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        """Fix #2 & #3: Require auth + published scenario, and record hint usage server-side."""
        question = (
            db.query(models.Question)
            .filter(models.Question.id == question_id, models.Question.scenario_id == scenario.id)
            .first()
        )
        if not question:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found")

        requested_tier = (payload or {}).get("tier") or (payload or {}).get("hint_type") or tier or "free"
        is_paid = str(requested_tier).lower() in {"paid", "walkthrough", "full", "2"}

        attempt = (
            db.query(models.QuestionAttempt)
            .filter(
                models.QuestionAttempt.user_id == current_user.id,
                models.QuestionAttempt.scenario_id == scenario.id,
                models.QuestionAttempt.question_id == question.id,
            )
            .first()
        )
        if not attempt:
            attempt = models.QuestionAttempt(
                user_id=current_user.id,
                scenario_id=scenario.id,
                question_id=question.id,
                free_hint_used=False,
                paid_hint_used=False,
                wrong_attempts=0,
                is_solved=False,
            )
            db.add(attempt)

        if is_paid:
            attempt.paid_hint_used = True
            hint_text = getattr(question, "hint", None) or getattr(question, "free_hint", None) or "Inspect the correlated high-severity Event IDs around the alert timestamp."
            penalty = max(1, int(round((question.points or 10) * 0.3)))
        else:
            attempt.free_hint_used = True
            hint_text = getattr(question, "free_hint", None) or getattr(question, "hint", None) or "Filter logs by the alerted host or user account."
            penalty = 0

        db.commit()
        return {
            "question_id": question.id,
            "tier": "paid" if is_paid else "free",
            "hint": hint_text,
            "penalty_points": penalty,
            "free_hint_used": attempt.free_hint_used,
            "paid_hint_used": attempt.paid_hint_used,
        }

    @router.post("/api/scenarios/{scenario_id}/verify-finding")
    def verify_finding_hardened(
        scenario_id: int,
        payload: Dict[str, Any],
        scenario: models.Scenario = Depends(get_accessible_scenario),
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        """Fix #2 & #3: Require auth + published status and increment wrong_attempts server-side."""
        question_id = payload.get("question_id")
        user_answer = str(payload.get("user_answer") or payload.get("answer") or "").strip()
        if not question_id:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="question_id is required")

        question = (
            db.query(models.Question)
            .filter(models.Question.id == int(question_id), models.Question.scenario_id == scenario.id)
            .first()
        )
        if not question:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found")

        attempt = (
            db.query(models.QuestionAttempt)
            .filter(
                models.QuestionAttempt.user_id == current_user.id,
                models.QuestionAttempt.scenario_id == scenario.id,
                models.QuestionAttempt.question_id == question.id,
            )
            .first()
        )
        if not attempt:
            attempt = models.QuestionAttempt(
                user_id=current_user.id,
                scenario_id=scenario.id,
                question_id=question.id,
                free_hint_used=False,
                paid_hint_used=False,
                wrong_attempts=0,
                is_solved=False,
            )
            db.add(attempt)

        matched = check_answer(user_answer, question)
        diagnostic = None
        if matched:
            attempt.is_solved = True
        else:
            attempt.wrong_attempts = (attempt.wrong_attempts or 0) + 1
            if diagnose_analyst_mistake is not None:
                try:
                    diagnostic = diagnose_analyst_mistake(user_answer, question, scenario)
                except Exception:
                    diagnostic = None

        db.commit()
        return {
            "question_id": question.id,
            "is_correct": matched,
            "correct": matched,
            "wrong_attempts": attempt.wrong_attempts,
            "paid_hint_used": attempt.paid_hint_used,
            "diagnostic": diagnostic or ("Verified finding!" if matched else "Incorrect finding. Cross-check the event fields and timeline."),
        }

    @router.post("/api/scenarios/{scenario_id}/submit")
    def submit_investigation_hardened(
        scenario_id: int,
        submission: Dict[str, Any],
        scenario: models.Scenario = Depends(get_accessible_scenario),
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        """
        Fix #2, #3, #10:
          - Enforces authenticated user + published scenario
          - Computes hint & wrong-attempt penalties strictly from server-side QuestionAttempt records
          - Verifies that trainee pinned supporting key evidence logs (pinned_log_ids)
        """
        questions = db.query(models.Question).filter(models.Question.scenario_id == scenario.id).all()
        if not questions:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scenario has no questions configured")

        raw_answers = submission.get("answers") or []
        answer_map: Dict[int, str] = {}
        if isinstance(raw_answers, dict):
            for q_id, ans in raw_answers.items():
                if str(q_id).isdigit():
                    answer_map[int(q_id)] = str(ans or "")
        elif isinstance(raw_answers, list):
            for item in raw_answers:
                if isinstance(item, dict) and "question_id" in item:
                    answer_map[int(item["question_id"])] = str(item.get("user_answer") or item.get("answer") or "")

        pinned_log_ids = [
            int(lid) for lid in (submission.get("pinned_log_ids") or [])
            if str(lid).isdigit() or isinstance(lid, int)
        ]

        # Check server-side QuestionAttempt records (ignoring any client-supplied hint/attempt counts!)
        attempts_by_qid: Dict[int, models.QuestionAttempt] = {
            a.question_id: a
            for a in db.query(models.QuestionAttempt)
            .filter(
                models.QuestionAttempt.user_id == current_user.id,
                models.QuestionAttempt.scenario_id == scenario.id,
            )
            .all()
        }

        key_evidence_ids = {
            row.id
            for row in db.query(models.Log)
            .filter(models.Log.scenario_id == scenario.id, models.Log.is_key_evidence == True)
            .all()
        }
        matched_evidence_pins = set(pinned_log_ids).intersection(key_evidence_ids)
        evidence_supported = True if not key_evidence_ids else len(matched_evidence_pins) > 0

        total_points = sum(max(1, q.points or 10) for q in questions)
        points_earned = 0
        results = []

        for q in questions:
            q_points = max(1, q.points or 10)
            user_ans = answer_map.get(q.id, "")
            is_correct = check_answer(user_ans, q)
            attempt = attempts_by_qid.get(q.id)

            paid_hint_used = bool(attempt.paid_hint_used) if attempt else False
            wrong_attempts = int(attempt.wrong_attempts or 0) if attempt else 0

            awarded = 0
            if is_correct:
                awarded = q_points
                if paid_hint_used:
                    awarded -= max(1, int(round(q_points * 0.3)))
                if wrong_attempts > 0:
                    awarded -= min(int(round(q_points * 0.4)), wrong_attempts * max(1, int(round(q_points * 0.1))))
                # Fix #10: If key evidence exists in the scenario but trainee pinned 0 key evidence logs, cap score by 15%
                if not evidence_supported:
                    awarded = max(1, int(round(awarded * 0.85)))
                awarded = max(1, awarded)
            else:
                # Record failed submission attempt server-side as well
                if not attempt:
                    attempt = models.QuestionAttempt(
                        user_id=current_user.id,
                        scenario_id=scenario.id,
                        question_id=q.id,
                        wrong_attempts=1,
                    )
                    db.add(attempt)
                else:
                    attempt.wrong_attempts = wrong_attempts + 1

            points_earned += awarded
            results.append(
                {
                    "question_id": q.id,
                    "question_text": q.question_text,
                    "user_answer": user_ans,
                    "is_correct": is_correct,
                    "correct_answer": q.correct_answer if is_correct else None,
                    "explanation": q.explanation if is_correct else "Review the correlated forensic artefacts and pinned evidence logs.",
                    "points_awarded": awarded,
                    "max_points": q_points,
                    "paid_hint_used": paid_hint_used,
                    "wrong_attempts": wrong_attempts,
                }
            )

        score_pct = int(round((points_earned / total_points) * 100)) if total_points > 0 else 0

        existing_trials = (
            db.query(models.InvestigationResult)
            .filter(
                models.InvestigationResult.user_id == current_user.id,
                models.InvestigationResult.scenario_id == scenario.id,
            )
            .count()
        )
        current_trial_number = existing_trials + 1

        hints_used = [
            q.id for q in questions
            if attempts_by_qid.get(q.id) and attempts_by_qid[q.id].paid_hint_used
        ]
        free_hints_used = [
            q.id for q in questions
            if attempts_by_qid.get(q.id) and attempts_by_qid[q.id].free_hint_used
        ]
        free_hint_id = submission.get("free_hint_id") or (free_hints_used[0] if free_hints_used else None)
        user_guesses = submission.get("user_guesses") or {}
        # Ensure user_guesses records all final answers so inspect guesses is never empty
        for q in questions:
            user_ans = answer_map.get(q.id, "").strip()
            if user_ans:
                q_key = str(q.id)
                q_guesses = user_guesses.get(q_key) or user_guesses.get(q.id) or []
                if not isinstance(q_guesses, list):
                    q_guesses = [str(q_guesses)]
                if not q_guesses or q_guesses[-1] != user_ans:
                    q_guesses.append(user_ans)
                user_guesses[q_key] = q_guesses

        guesses_attempt_count = sum(len(v) for v in user_guesses.values()) if user_guesses else 0
        server_wrong_count = sum(int(a.wrong_attempts or 0) for a in attempts_by_qid.values())
        client_trials = int(submission.get("trials_count") or 1)
        total_session_attempts = max(current_trial_number, guesses_attempt_count, server_wrong_count + 1, client_trials)

        inv_result = models.InvestigationResult(
            user_id=current_user.id,
            scenario_id=scenario.id,
            score=score_pct,
            points_earned=points_earned,
            total_points=total_points,
            pinned_log_ids=pinned_log_ids,
            hints_used=hints_used,
            free_hint_id=free_hint_id,
            free_hints_used=free_hints_used,
            trials_count=total_session_attempts,
            user_guesses=user_guesses,
            submitted_at=datetime.utcnow(),
        )
        db.add(inv_result)

        # Clear in-progress session attempts for this scenario so a subsequent investigation starts fresh
        db.query(models.QuestionAttempt).filter(
            models.QuestionAttempt.user_id == current_user.id,
            models.QuestionAttempt.scenario_id == scenario.id,
        ).delete()

        db.commit()

        correct_cnt = sum(1 for r in results if r.get("is_correct"))
        return {
            "scenario_id": scenario.id,
            "score": score_pct,
            "score_percent": score_pct,
            "points_earned": points_earned,
            "total_points": total_points,
            "correct_count": correct_cnt,
            "total_questions": len(questions),
            "results": results,
            "pinned_log_ids": pinned_log_ids,
            "key_evidence_log_ids": list(key_evidence_ids),
            "evidence_verified": evidence_supported,
            "matched_key_evidence_count": len(matched_evidence_pins),
            "trial_number": current_trial_number,
            "trials_count": total_session_attempts,
            "attempts_count": total_session_attempts,
        }

    @router.post("/api/admin/scenarios/{scenario_id}/upload-logs")
    async def upload_scenario_logs_hardened(
        scenario_id: int,
        include_noise: bool = Query(True, description="Include realistic background AD noise & false positives"),
        file: UploadFile = File(...),
        current_admin: models.User = Depends(admin_dep),
        db: Session = Depends(get_db),
    ):
        """
        Fix #6 & #7:
          - Streams ZIP upload in chunks with strict memory cap (25 MB)
          - Counts and reports malformed JSON records instead of silently ignoring them
          - Parses & validates all new logs BEFORE deleting existing scenario logs inside an atomic transaction
        """
        scenario = db.query(models.Scenario).filter(models.Scenario.id == scenario_id).first()
        if not scenario:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scenario not found")

        filename = (file.filename or "").lower()
        if not (filename.endswith(".zip") or filename.endswith(".json") or filename.endswith(".jsonl")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only .zip, .json, or .jsonl uploads are supported")

        buffer = io.BytesIO()
        total_read = 0
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > MAX_ZIP_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Upload exceeds maximum allowed size of {MAX_ZIP_UPLOAD_BYTES // (1024 * 1024)} MB",
                )
            buffer.write(chunk)

        buffer.seek(0)
        parsed_logs: List[models.Log] = []
        malformed_skipped = 0
        total_lines_seen = 0

        def parse_record_dict(rec: Dict[str, Any]) -> models.Log:
            ev_id = int(rec.get("EventID") or rec.get("event_id") or rec.get("winlog", {}).get("event_id") or 4624)
            ts_raw = rec.get("@timestamp") or rec.get("TimeCreated") or rec.get("timestamp")
            ts_val = datetime.now(timezone.utc).replace(tzinfo=None)
            if isinstance(ts_raw, str):
                try:
                    ts_val = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    pass
            src_ip = str(rec.get("IpAddress") or rec.get("source_ip") or rec.get("SourceAddress") or "10.10.10.10")
            uname = str(rec.get("TargetUserName") or rec.get("SubjectUserName") or rec.get("username") or "SYSTEM")
            host = str(rec.get("Hostname") or rec.get("Computer") or rec.get("target_host") or "DC01.corp.local")
            is_key = bool(rec.get("is_key_evidence", ev_id in {4662, 4672, 4688, 4697, 4769, 7045, 1102}))
            return models.Log(
                scenario_id=scenario.id,
                event_id=ev_id,
                timestamp=ts_val,
                source_ip=src_ip,
                username=uname,
                target_host=host,
                is_key_evidence=is_key,
                raw_event_data=rec,
            )

        def process_text_stream(text_stream: io.TextIOBase) -> None:
            nonlocal malformed_skipped, total_lines_seen
            for raw_line in text_stream:
                line = raw_line.strip()
                if not line:
                    continue
                total_lines_seen += 1
                try:
                    obj = json.loads(line)
                    if isinstance(obj, list):
                        for item in obj:
                            if isinstance(item, dict):
                                parsed_logs.append(parse_record_dict(item))
                            else:
                                malformed_skipped += 1
                    elif isinstance(obj, dict):
                        parsed_logs.append(parse_record_dict(obj))
                    else:
                        malformed_skipped += 1
                except Exception:
                    malformed_skipped += 1

        if filename.endswith(".zip"):
            try:
                with zipfile.ZipFile(buffer, "r") as zf:
                    total_uncompressed = 0
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        norm_name = os.path.normpath(info.filename)
                        if norm_name.startswith("..") or norm_name.startswith("/") or ":" in norm_name:
                            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsafe path in ZIP archive")
                        total_uncompressed += info.file_size
                        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail="Uncompressed ZIP content exceeds 100 MB safety limit",
                            )
                        if info.filename.lower().endswith((".json", ".jsonl", ".log")):
                            with zf.open(info, "r") as member_stream:
                                text_wrapper = io.TextIOWrapper(member_stream, encoding="utf-8", errors="replace")
                                process_text_stream(text_wrapper)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is not a valid ZIP archive")
        else:
            text_wrapper = io.TextIOWrapper(buffer, encoding="utf-8", errors="replace")
            process_text_stream(text_wrapper)

        if not parsed_logs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"No valid log records found in upload (malformed_skipped={malformed_skipped}). Existing logs were preserved.",
            )

        if include_noise:
            parsed_logs.extend(generate_background_noise_logs(scenario.id, parsed_logs[0].timestamp))

        # Fix #7: Atomic replacement — only delete existing logs inside a transaction AFTER new logs are ready
        try:
            db.query(models.Log).filter(models.Log.scenario_id == scenario.id).delete(synchronize_session=False)
            db.add_all(parsed_logs)
            db.commit()
        except Exception as exc:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Atomic log replacement failed; existing logs rolled back safely: {exc}",
            )

        return {
            "message": "Logs imported atomically",
            "scenario_id": scenario.id,
            "imported_count": len(parsed_logs),
            "malformed_skipped": malformed_skipped,
            "total_lines_processed": total_lines_seen,
        }

    app.include_router(router)
