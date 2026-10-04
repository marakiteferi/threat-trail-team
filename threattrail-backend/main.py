from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func, text
import os
import re
import io
import zipfile
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
from jose import jwt, JWTError

from database import engine, get_db, Base
import models
from models import User, Scenario, Alert, Log, Question, InvestigationResult, QuestionAttempt, SeverityLevel
from schemas import (
    ScenarioOut, AlertOut, LogOut, QuestionOut, QuestionAdminOut,
    SubmissionRequest, SubmissionResponse, QuestionResult,
    ScenarioCreate, ScenarioUpdate, StatusUpdate, AlertCreate, QuestionCreate,
    ScenarioAdminOut, ScenarioAdminDetailOut, ScenarioFullCreate, ScenarioFullUpdate,
    UserRegister, UserLogin, UserOut, AuthResponse, UserProfileUpdate, UserProfileOut,
    UserAdminOut, UserAdminCreate, UserAdminUpdateRole, UserAdminResetPassword,
    VerifyFindingRequest, VerifyFindingResponse, HintResponse, ContainmentResult,
    SubmissionAdminOut, LeaderboardUserOut,
)
from zip_analyzer import analyze_zip_archive, extract_field_from_message
from security_hardening import validate_required_env, SecurityHeadersMiddleware, RateLimitMiddleware

# ── Startup Validation ────────────────────────────────────────────────────────
validate_required_env()


# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatTrail API",
    description="Backend for the ThreatTrail SOC investigation training platform",
    version="0.4.0",
)

# ── CORS Configuration ────────────────────────────────────────────────────────
origins_env = os.getenv("CORS_ORIGINS")
if origins_env:
    cors_origins = [o.strip() for o in origins_env.split(",") if o.strip()]
else:
    cors_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Security Headers & Rate Limiting ─────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=15, window_seconds=60)

# ── JWT & Auth Security ───────────────────────────────────────────────────────

_DEFAULT_SECRET = "threattrail-soc-jwt-secret-key-2026"
SECRET_KEY = os.getenv("JWT_SECRET_KEY", _DEFAULT_SECRET)
if SECRET_KEY == _DEFAULT_SECRET:
    import warnings
    warnings.warn(
        "[ThreatTrail] JWT_SECRET_KEY is using the insecure dev default. "
        "Set JWT_SECRET_KEY in your .env file before deploying to production!",
        stacklevel=2,
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

security = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Returns authenticated user if token is valid, else None."""
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        return db.query(User).filter(User.username == username).first()
    except JWTError:
        return None


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required",
        )
    return current_user


@app.on_event("startup")
def on_startup():
    """Create all tables and perform incremental column migrations if needed."""
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            if engine.dialect.name == "sqlite":
                res_u = conn.execute(text("PRAGMA table_info(users);")).fetchall()
                u_cols = [r[1] for r in res_u]
                if "created_at" not in u_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME;"))
                    conn.execute(text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;"))
                if "email" not in u_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(200);"))
                if "avatar_color" not in u_cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN avatar_color VARCHAR(20) DEFAULT '#3b82f6';"))

                res_q = conn.execute(text("PRAGMA table_info(questions);")).fetchall()
                q_cols = [r[1] for r in res_q]
                if "free_hint" not in q_cols:
                    conn.execute(text("ALTER TABLE questions ADD COLUMN free_hint TEXT;"))
                if "hint" not in q_cols:
                    conn.execute(text("ALTER TABLE questions ADD COLUMN hint TEXT;"))

                res_ir = conn.execute(text("PRAGMA table_info(investigation_results);")).fetchall()
                ir_cols = [r[1] for r in res_ir]
                if "hints_used" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN hints_used JSON;"))
                if "free_hint_id" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN free_hint_id INTEGER;"))
                if "free_hints_used" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN free_hints_used JSON;"))
                if "trials_count" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN trials_count INTEGER DEFAULT 1;"))
                if "user_guesses" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN user_guesses JSON;"))
                if "submitted_at" not in ir_cols:
                    conn.execute(text("ALTER TABLE investigation_results ADD COLUMN submitted_at DATETIME;"))
                conn.commit()
            elif engine.dialect.name == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(200);"))
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color VARCHAR(20) DEFAULT '#3b82f6';"))
                conn.execute(text("ALTER TABLE questions ADD COLUMN IF NOT EXISTS free_hint TEXT;"))
                conn.execute(text("ALTER TABLE questions ADD COLUMN IF NOT EXISTS hint TEXT;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS hints_used JSONB;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS free_hint_id INTEGER;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS free_hints_used JSONB;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS trials_count INTEGER DEFAULT 1;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS user_guesses JSONB;"))
                conn.execute(text("ALTER TABLE investigation_results ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;"))
                conn.commit()
    except Exception as e:
        print(f"[!] Schema check warning: {e}")


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=AuthResponse)
def register(body: UserRegister, db: Session = Depends(get_db)):
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, hyphens, and underscores")

    existing = db.query(User).filter(User.username.ilike(username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    pw_hash = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = User(username=username, password_hash=pw_hash, role="user")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Registration successful")


@app.post("/api/auth/login", response_model=AuthResponse)
def login(body: UserLogin, db: Session = Depends(get_db)):
    username = body.username.strip()
    user = db.query(User).filter(User.username.ilike(username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        valid_pw = bcrypt.checkpw(body.password.encode("utf-8"), user.password_hash.encode("utf-8"))
    except Exception:
        valid_pw = False

    if not valid_pw:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Login successful")


@app.post("/api/auth/admin-login", response_model=AuthResponse)
def admin_login(body: UserLogin, db: Session = Depends(get_db)):
    username = body.username.strip()
    user = db.query(User).filter(User.username.ilike(username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    try:
        valid_pw = bcrypt.checkpw(body.password.encode("utf-8"), user.password_hash.encode("utf-8"))
    except Exception:
        valid_pw = False

    if not valid_pw:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access restricted: This account does not possess administrator privileges.",
        )

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Admin authenticated successfully")


@app.get("/api/auth/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.patch("/api/auth/profile", response_model=UserProfileOut)
def update_profile(
    body: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Allow an authenticated user to update their own profile (username, email, password, avatar color)."""
    
    # Update username if provided
    if body.username is not None:
        new_username = body.username.strip()
        if len(new_username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", new_username):
            raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, hyphens, dots, and underscores")
        if new_username.lower() != current_user.username.lower():
            existing = db.query(User).filter(User.username.ilike(new_username)).first()
            if existing:
                raise HTTPException(status_code=400, detail="That username is already taken")
        current_user.username = new_username
    
    # Update email if provided
    if body.email is not None:
        email = body.email.strip()
        if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            raise HTTPException(status_code=400, detail="Invalid email address format")
        current_user.email = email if email else None
    
    # Update password if provided
    if body.new_password is not None:
        if not body.current_password:
            raise HTTPException(status_code=400, detail="Current password is required to set a new password")
        if len(body.new_password) < 4:
            raise HTTPException(status_code=400, detail="New password must be at least 4 characters")
        try:
            valid = bcrypt.checkpw(body.current_password.encode("utf-8"), current_user.password_hash.encode("utf-8"))
        except Exception:
            valid = False
        if not valid:
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        current_user.password_hash = bcrypt.hashpw(body.new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    # Update avatar color if provided
    if body.avatar_color is not None:
        if not re.match(r'^#[0-9A-Fa-f]{6}$', body.avatar_color):
            raise HTTPException(status_code=400, detail="Invalid hex color format (e.g. #3b82f6)")
        current_user.avatar_color = body.avatar_color
    
    db.commit()
    db.refresh(current_user)
    return current_user


@app.get("/api/auth/profile/stats", response_model=dict)
def get_profile_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return current user's investigation stats for their profile page."""
    results = db.query(InvestigationResult).filter(InvestigationResult.user_id == current_user.id).all()
    active_attempts = db.query(models.QuestionAttempt).filter(models.QuestionAttempt.user_id == current_user.id).all()

    total_investigations = len(results)
    total_points = sum(r.points_earned for r in results)
    avg_score = round(sum(r.score for r in results) / total_investigations) if total_investigations else 0
    active_hints = sum(1 for a in active_attempts if a.free_hint_used or a.paid_hint_used)
    hints_used = sum(len(r.hints_used or []) for r in results) + active_hints
    scenarios_completed = len(set(r.scenario_id for r in results))

    completed_attempts = sum(r.trials_count or 1 for r in results)
    active_wrong_attempts = sum(int(a.wrong_attempts or 0) for a in active_attempts)
    active_solved_attempts = sum(1 for a in active_attempts if a.is_solved)
    total_attempts = completed_attempts + active_wrong_attempts + active_solved_attempts
    total_trials = max(total_investigations, completed_attempts)
    
    # Compute rank among non-admin trainees so Profile rank matches Leaderboard rank
    non_admin_users = db.query(User).filter(User.role != "admin").all()
    all_results = db.query(InvestigationResult).all()
    user_results: dict[int, list[InvestigationResult]] = {}
    for r in all_results:
        user_results.setdefault(r.user_id, []).append(r)

    standings = []
    for u in non_admin_users:
        u_res = user_results.get(u.id, [])
        u_pts = sum(r.points_earned for r in u_res)
        u_scs = len(set(r.scenario_id for r in u_res))
        u_avg = round(sum(r.score for r in u_res) / len(u_res)) if u_res else 0
        standings.append({"user_id": u.id, "points": u_pts, "scenarios": u_scs, "avg": u_avg})

    standings.sort(key=lambda x: (x["points"], x["scenarios"], x["avg"]), reverse=True)
    user_rank = None
    for idx, s in enumerate(standings, start=1):
        if s["user_id"] == current_user.id:
            user_rank = idx
            break

    recent = sorted(results, key=lambda r: r.submitted_at or datetime.min, reverse=True)[:5]
    recent_out = []
    for r in recent:
        sc = db.query(Scenario).filter(Scenario.id == r.scenario_id).first()
        recent_out.append({
            "scenario_id": r.scenario_id,
            "scenario_name": sc.name if sc else f"Scenario #{r.scenario_id}",
            "score": r.score,
            "points_earned": r.points_earned,
            "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
        })
    
    return {
        "total_investigations": total_investigations,
        "total_trials": total_trials,
        "total_attempts": total_attempts,
        "total_points": total_points,
        "average_score": avg_score,
        "hints_used": hints_used,
        "scenarios_completed": scenarios_completed,
        "rank": user_rank,
        "recent_activity": recent_out,
    }


# ── Trainee Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/scenarios", response_model=list[ScenarioOut])
def list_scenarios(
    all_status: bool = Query(False, description="Include drafts if true — admin only"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    # Only admins can see Draft scenarios
    if all_status and current_user and current_user.role == "admin":
        return db.query(Scenario).all()
    # Everyone else gets only Published scenarios
    return db.query(Scenario).filter(Scenario.status == "Published").all()


def _check_scenario_access(scenario: Optional[Scenario], current_user: Optional[User]):
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    if scenario.status != "Published" and (not current_user or current_user.role != "admin"):
        raise HTTPException(
            status_code=403,
            detail="Access restricted: This scenario is in Draft status and only accessible to administrators.",
        )


@app.get("/api/scenarios/{scenario_id}", response_model=ScenarioOut)
def get_scenario_info(
    scenario_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Fetch scenario metadata including Active Directory topology context."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    _check_scenario_access(scenario, current_user)
    return scenario


@app.get("/api/scenarios/{scenario_id}/alert", response_model=AlertOut)
def get_scenario_alert(
    scenario_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    _check_scenario_access(scenario, current_user)
    alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found for this scenario")
    return alert


@app.get("/api/scenarios/{scenario_id}/logs", response_model=list[LogOut])
def get_scenario_logs(
    scenario_id: int,
    event_id: Optional[int] = Query(None, description="Filter by Windows Event ID"),
    search: Optional[str] = Query(None, description="Search username, IP, or host"),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    _check_scenario_access(scenario, current_user)

    query = db.query(Log).filter(Log.scenario_id == scenario_id)
    if event_id is not None:
        query = query.filter(Log.event_id == event_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            (Log.username.ilike(term))
            | (Log.source_ip.ilike(term))
            | (Log.target_host.ilike(term))
        )
    logs = query.order_by(Log.timestamp).offset(offset).limit(limit).all()
    if not logs and offset == 0 and event_id is None and not search:
        raise HTTPException(status_code=404, detail="No logs found for this scenario")
    return logs


@app.get("/api/scenarios/{scenario_id}/questions", response_model=list[QuestionOut])
def get_scenario_questions(
    scenario_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    _check_scenario_access(scenario, current_user)
    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found for this scenario")
    return questions


def is_answer_match(user_raw: str, correct_raw: str, aliases: Optional[list[str]] = None) -> bool:
    """
    Smart SOC answer matcher:
    - Case-insensitive, whitespace-trimmed
    - Checks explicit aliases (e.g. ['CORP\\svc_backup', 'svc_backup@corp.local'])
    - Strips AD domain prefix (DOMAIN\\user) ONLY when there is exactly one backslash
      and no drive letter (avoids matching C:\\Windows\\System32\\foo.exe incorrectly).
    """
    u = user_raw.strip().lower()
    c = correct_raw.strip().lower()
    if not u or not c:
        return False
    if u == c:
        return True

    # Strip DOMAIN\user but NEVER file paths like C:\Windows\System32\lsass.exe
    def _strip_domain(s: str) -> str:
        # A Windows file path contains drive letters (C:) or forward slashes
        if ":" in s or "/" in s:
            return s
        parts = s.split("\\")
        # Only strip domain prefix when there is a single backslash and no drive letter
        if len(parts) == 2 and parts[0] and not parts[0].endswith(":"):
            return parts[1].split("@")[0]
        return s.split("@")[0]  # strip UPN suffix (@corp.local) only

    u_stripped = _strip_domain(u)
    c_stripped = _strip_domain(c)
    if u_stripped == c_stripped and len(c_stripped) >= 3:
        return True

    if aliases:
        for alias in aliases:
            if isinstance(alias, str):
                alias_clean = alias.strip().lower()
                if u == alias_clean:
                    return True
                # Also try alias domain-stripping
                if u_stripped == _strip_domain(alias_clean) and len(u_stripped) >= 3:
                    return True
    return False


def diagnose_analyst_mistake(user_raw: str, question: Question, scenario: Scenario) -> Optional[str]:
    """
    Detects common SOC analyst misconceptions and false-positive traps, returning
    actionable coaching feedback instead of a generic 'Incorrect' message.
    """
    u = user_raw.strip()
    u_low = u.lower()
    q_text = (question.question_text or "").lower()
    correct_low = (question.correct_answer or "").strip().lower()

    if not u:
        return None

    # Trap 1: Analyst submits an Active Directory Machine Account (ending in '$') when asked for a user account
    if u.endswith("$") and not correct_low.endswith("$"):
        return (
            f"⚠️ Analyst Trap Detected: '{u}' ends with '$', which indicates an Active Directory "
            "Machine/Computer account (e.g., routine DC or workstation authentication), not a human or service user account. "
            "Exclude accounts ending in '$' and check SubjectUserName / TargetUserName for the compromised user."
        )

    # Trap 2: Analyst confuses AES256 (0x12) with RC4-HMAC (0x17) in Kerberoasting (Event 4769)
    if u_low in ("0x12", "18", "aes256") and correct_low in ("0x17", "23"):
        return (
            "⚠️ Analyst Trap Detected: '0x12' is AES256-CTS-HMAC-SHA1-96, which is normal, secure Kerberos encryption "
            "seen in background domain traffic. Look for the anomalous Event 4769 downgraded to '0x17' (RC4-HMAC)."
        )

    # Trap 3: Analyst enters normal Kerberos service 'krbtgt' or machine SPN when asked for the Kerberoasted service
    if u_low == "krbtgt" and correct_low != "krbtgt":
        return (
            "⚠️ Analyst Trap Detected: 'krbtgt' is the Kerberos Key Distribution Center service used for normal TGT requests (Event 4768). "
            "Filter Event ID 4769 with TicketEncryptionType 0x17 to find the specific application ServiceName targeted."
        )

    # Trap 4: Analyst enters benign system process accessing LSASS (Event 10)
    if u_low in ("svchost.exe", "msmpeng.exe", "csrss.exe", "lsass.exe", "services.exe", "wininit.exe") and "sourceimage" in q_text:
        return (
            f"⚠️ False Positive Trap: '{u}' is a legitimate Windows OS/Defender process that routinely interacts with LSASS. "
            "Inspect Sysmon Event 10 where GrantedAccess is 0x1010/0x1410 and look for the non-standard SourceImage."
        )

    # Trap 5: Analyst confuses SubjectUserName ('-' or 'SYSTEM') with TargetUserName in Logon events (4624/4625)
    if u_low in ("system", "nt authority\\system", "-") and correct_low not in ("system", "nt authority\\system"):
        return (
            f"⚠️ Field Confusion Trap: '{u}' is the local Subject/System context, not the user account being authenticated or compromised. "
            "Expand the Log Inspector and check 'Target / Account User' (or 'Subject User' for 4662 DCSync)."
        )

    # Trap 6: Analyst enters the Target Domain Controller IP (10.0.0.10) instead of the Attacker Source IP
    if u_low == "10.0.0.10" and "source ip" in q_text:
        return (
            "⚠️ Directionality Trap: '10.0.0.10' is the IP address of the Domain Controller (DC01.corp.local), not the attacker's source IP. "
            "Check the 'Source IP' column for the host generating the burst of failed logons."
        )

    return None


def generate_fallback_free_hint(question: Question) -> str:
    """Generates a gentle starter pointer if the admin left free_hint blank."""
    if question.free_hint and question.free_hint.strip():
        return question.free_hint.strip()
    q_low = (question.question_text or "").lower()
    if "event id" in q_low:
        return "Starter Clue: Click 'View Sigma Rule' in the top alert banner or check the 'Event Cheat Sheet' tab to match the activity to its Windows Event ID."
    if "source ip" in q_low or "client" in q_low or "ip address" in q_low:
        return "Starter Clue: Check the 'Suspect IPs' quick-filter bar or expand the relevant authentication/network event in the Log Inspector to check the Source IP field."
    if "account" in q_low or "user" in q_low or "subjectusername" in q_low:
        return "Starter Clue: Expand the matching event row to open the Forensic Triage View, then inspect 'Identity & Session Context' (ignore machine accounts ending in '$')."
    if "host" in q_low or "workstation" in q_low or "computer" in q_low:
        return "Starter Clue: Look at the 'Target Host' column on the suspicious event row or check the 'AD Environment' tab."
    if "mitre" in q_low:
        return "Starter Clue: Check the top SIEM Alert Banner or the tags section at the bottom of the Sigma Detection Rule."
    return "Starter Clue: Filter the logs using the Event IDs mentioned in the Sigma Rule, then expand the suspicious event to inspect its decoded fields."


def generate_fallback_paid_hint(question: Question) -> str:
    """Generates a detailed forensic walkthrough if the admin left paid hint blank."""
    if question.hint and question.hint.strip():
        return question.hint.strip()
    if question.explanation and question.explanation.strip():
        return f"Forensic Walkthrough: {question.explanation.strip()}"
    ans = (question.correct_answer or "").strip()
    masked = ans[:2] + "***" + (ans[-1] if len(ans) > 3 else "")
    return f"Forensic Walkthrough: Search the logs for indicators matching pattern '{masked}' (length: {len(ans)} chars)."


@app.post("/api/scenarios/{scenario_id}/verify-finding", response_model=VerifyFindingResponse)
def verify_finding(
    scenario_id: int,
    body: VerifyFindingRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    question = (
        db.query(Question)
        .filter(Question.id == body.question_id, Question.scenario_id == scenario_id)
        .first()
    )
    if not question:
        raise HTTPException(status_code=404, detail="Question not found in this scenario")

    is_correct = is_answer_match(body.answer, question.correct_answer, question.acceptable_answers)
    if is_correct:
        return VerifyFindingResponse(
            question_id=question.id,
            is_correct=True,
            trap_detected=False,
            message="Verified! Your finding matches the forensic evidence in the logs.",
        )

    trap_msg = diagnose_analyst_mistake(body.answer, question, scenario)
    if trap_msg:
        return VerifyFindingResponse(
            question_id=question.id,
            is_correct=False,
            trap_detected=True,
            message=trap_msg,
            trap_msg=trap_msg,
        )

    return VerifyFindingResponse(
        question_id=question.id,
        is_correct=False,
        trap_detected=False,
        message=f"'{body.answer.strip()}' does not match the expected indicator. Re-check the Log Inspector fields or use a Free Hint.",
    )


@app.post("/api/scenarios/{scenario_id}/questions/{question_id}/hint")
def get_question_hint(
    scenario_id: int,
    question_id: int,
    is_free: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    question = (
        db.query(Question)
        .filter(Question.id == question_id, Question.scenario_id == scenario_id)
        .first()
    )
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    hint_text = generate_fallback_free_hint(question) if is_free else generate_fallback_paid_hint(question)
    return {
        "question_id": question.id,
        "is_free": is_free,
        "penalty": 0 if is_free else 15,
        "hint": hint_text,
    }


@app.post("/api/scenarios/{scenario_id}/submit", response_model=SubmissionResponse)
def submit_answers(
    scenario_id: int,
    body: SubmissionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    q_map = {q.id: q for q in questions}

    # Deduplicate client-supplied answers by question_id to prevent score inflation exploit
    deduped_answers: dict[int, str] = {}
    for ans in body.answers:
        if ans.question_id not in deduped_answers:
            deduped_answers[ans.question_id] = ans.answer

    results: list[QuestionResult] = []
    correct_count = 0
    total_points = sum(q.points or 10 for q in questions)
    points_earned = 0

    # Grade against the canonical DB question list (not the client list) to prevent omissions
    for question in questions:
        user_answer = deduped_answers.get(question.id, "")  # empty string = no answer submitted
        q_pts = question.points or 10
        is_correct = bool(user_answer) and is_answer_match(user_answer, question.correct_answer, question.acceptable_answers)
        if is_correct:
            correct_count += 1
            points_earned += q_pts

        results.append(
            QuestionResult(
                question_id=question.id,
                question_text=question.question_text,
                user_answer=user_answer,
                correct_answer=question.correct_answer,
                explanation=question.explanation,
                is_correct=is_correct,
                points_awarded=q_pts if is_correct else 0,
                points_possible=q_pts,
            )
        )

    hints_used = body.hints_used or []
    free_hints_used = body.free_hints_used or []
    if body.free_hint_id and body.free_hint_id not in free_hints_used:
        free_hints_used.append(body.free_hint_id)

    # Apply paid hint penalty (-15 pts per unique paid hint used)
    unique_paid_hints = set(body.hints_used or [])
    hint_penalty = len(unique_paid_hints) * 15
    adjusted_points_earned = max(0, points_earned - hint_penalty)

    total = len(questions)
    score_percent = round((adjusted_points_earned / total_points) * 100) if total_points > 0 else 0

    # Evaluate Incident Containment Playbook if configured on the scenario
    ad_ctx = scenario.ad_context or {}
    containment_cfg = ad_ctx.get("containment_targets") or {}
    expected_host = (containment_cfg.get("isolate_host") or "").strip()
    expected_user = (containment_cfg.get("disable_user") or "").strip()

    containment_eval = None
    if expected_host or expected_user:
        sel_host = (body.containment_host or "").strip()
        sel_user = (body.containment_user or "").strip()

        host_ok = is_answer_match(sel_host, expected_host, [expected_host.split(".")[0]]) if expected_host else True
        user_ok = is_answer_match(sel_user, expected_user) if expected_user else True

        feedback_parts = []
        if expected_host:
            if host_ok:
                feedback_parts.append(f"✅ Host Isolation Correct: Isolated '{sel_host}'.")
            elif not sel_host:
                feedback_parts.append(f"⚠️ Missed Host Isolation: Expected '{expected_host}' to be isolated.")
            else:
                feedback_parts.append(f"❌ False-Positive Host Isolation: You isolated '{sel_host}' instead of '{expected_host}'.")
        if expected_user:
            if user_ok:
                feedback_parts.append(f"✅ Account Containment Correct: Disabled '{sel_user}'.")
            elif not sel_user:
                feedback_parts.append(f"⚠️ Missed Account Containment: Expected '{expected_user}' to be disabled.")
            elif sel_user.upper() in ("SYSTEM", "LOCAL SYSTEM") or sel_user.endswith("$"):
                feedback_parts.append(f"❌ Critical SOC Mistake: Disabling '{sel_user}' (a built-in OS or machine '$' account) causes severe production outage! Target the compromised user '{expected_user}'.")
            else:
                feedback_parts.append(f"❌ Wrong Account Disabled: You disabled '{sel_user}' instead of '{expected_user}'.")

        containment_eval = ContainmentResult(
            enabled=True,
            expected_host=expected_host or None,
            selected_host=sel_host or None,
            host_correct=host_ok if expected_host else None,
            expected_user=expected_user or None,
            selected_user=sel_user or None,
            user_correct=user_ok if expected_user else None,
            feedback=" ".join(feedback_parts),
        )

    resolved_user_id = current_user.id

    result_record = InvestigationResult(
        user_id=resolved_user_id,
        scenario_id=scenario_id,
        score=score_percent,
        points_earned=adjusted_points_earned,
        total_points=total_points,
        pinned_log_ids=body.pinned_log_ids or [],
        hints_used=hints_used,
        free_hint_id=body.free_hint_id or (free_hints_used[0] if free_hints_used else None),
        free_hints_used=free_hints_used,
        trials_count=body.trials_count or 1,
        user_guesses=body.user_guesses or {},
        submitted_at=datetime.utcnow(),
    )
    db.add(result_record)
    db.commit()

    key_logs = (
        db.query(Log.id)
        .filter(Log.scenario_id == scenario_id, Log.is_key_evidence == True)
        .all()
    )
    key_log_ids = [r[0] for r in key_logs]

    return SubmissionResponse(
        scenario_id=scenario_id,
        total_questions=total,
        correct_count=correct_count,
        total_points=total_points,
        points_earned=adjusted_points_earned,
        score_percent=score_percent,
        pinned_log_ids=body.pinned_log_ids or [],
        key_evidence_log_ids=key_log_ids,
        hints_used=hints_used,
        free_hint_id=body.free_hint_id or (free_hints_used[0] if free_hints_used else None),
        free_hints_used=free_hints_used,
        hint_penalty=hint_penalty,
        trials_count=body.trials_count or 1,
        containment_eval=containment_eval,
        results=results,
    )


# ── Admin Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    total_scenarios = db.query(Scenario).count()
    published_scenarios = db.query(Scenario).filter(Scenario.status == "Published").count()
    draft_scenarios = db.query(Scenario).filter(Scenario.status == "Draft").count()
    total_logs = db.query(Log).count()
    total_submissions = db.query(InvestigationResult).count()
    total_users = db.query(User).count()
    total_admins = db.query(User).filter(User.role == "admin").count()
    total_trainees = db.query(User).filter(User.role == "user").count()

    return {
        "total_scenarios": total_scenarios,
        "published_scenarios": published_scenarios,
        "draft_scenarios": draft_scenarios,
        "total_logs": total_logs,
        "total_submissions": total_submissions,
        "total_users": total_users,
        "total_admins": total_admins,
        "total_trainees": total_trainees,
    }


@app.get("/api/admin/submissions", response_model=list[SubmissionAdminOut])
def get_admin_submissions(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    submissions = (
        db.query(InvestigationResult)
        .order_by(InvestigationResult.id.desc())
        .limit(100)
        .all()
    )
    out = []

    # Include active in-progress analyst sessions so admin inspect guesses monitors ongoing investigations
    active_attempts = db.query(models.QuestionAttempt).all()
    attempts_by_user_scenario: dict[tuple[int, int], list[models.QuestionAttempt]] = {}
    for att in active_attempts:
        attempts_by_user_scenario.setdefault((att.user_id, att.scenario_id), []).append(att)

    for (uid, sid), att_list in attempts_by_user_scenario.items():
        total_wrong = sum(int(a.wrong_attempts or 0) for a in att_list)
        total_solved = sum(1 for a in att_list if a.is_solved)
        hints_paid = [a.question_id for a in att_list if a.paid_hint_used]
        hints_free = [a.question_id for a in att_list if a.free_hint_used]

        if total_wrong == 0 and total_solved == 0 and not hints_paid and not hints_free:
            continue

        u = db.query(User).filter(User.id == uid).first()
        sc = db.query(Scenario).filter(Scenario.id == sid).first()
        if not u or not sc:
            continue

        guesses_map: dict[str, list[str]] = {}
        for a in att_list:
            q_label = str(a.question_id)
            steps = []
            if a.wrong_attempts > 0:
                for w_idx in range(a.wrong_attempts):
                    steps.append(f"Incorrect attempt #{w_idx + 1}")
            if a.is_solved:
                steps.append("Verified correct finding")
            if not steps:
                steps.append("In progress")
            guesses_map[q_label] = steps

        out.append(
            SubmissionAdminOut(
                id=-(sid * 100000 + uid),
                user_id=uid,
                username=u.username,
                user_role=u.role,
                scenario_id=sid,
                scenario_name=sc.name,
                mitre_technique=sc.mitre_technique or "N/A",
                score=0,
                points_earned=0,
                total_points=100,
                hints_used=hints_paid,
                free_hint_id=hints_free[0] if hints_free else None,
                free_hints_used=hints_free,
                hint_penalty=len(hints_paid) * 15,
                trials_count=max(1, total_wrong + total_solved),
                user_guesses=guesses_map,
                status="In Progress",
                submitted_at=None,
            )
        )

    for s in submissions:
        user = s.user
        scenario = s.scenario
        hints = s.hints_used or []
        free_hints = s.free_hints_used or []
        if s.free_hint_id and s.free_hint_id not in free_hints:
            free_hints.append(s.free_hint_id)
        hint_penalty = len(hints) * 15
        out.append(
            SubmissionAdminOut(
                id=s.id,
                user_id=s.user_id,
                username=user.username if user else f"User #{s.user_id}",
                user_role=user.role if user else "user",
                scenario_id=s.scenario_id,
                scenario_name=scenario.name if scenario else f"Scenario #{s.scenario_id}",
                mitre_technique=scenario.mitre_technique if scenario else "N/A",
                score=s.score,
                points_earned=s.points_earned,
                total_points=s.total_points,
                hints_used=hints,
                free_hint_id=s.free_hint_id,
                free_hints_used=free_hints,
                hint_penalty=hint_penalty,
                trials_count=s.trials_count or 1,
                user_guesses=s.user_guesses or {},
                status="Completed",
                submitted_at=s.submitted_at.isoformat() if s.submitted_at else None,
            )
        )
    return out


# ── Admin User Management Endpoints ──────────────────────────────────────────

@app.get("/api/admin/users", response_model=list[UserAdminOut])
def get_admin_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List all registered users, their registration date, submissions, and point totals."""
    users = db.query(User).order_by(User.id.asc()).all()
    results = db.query(InvestigationResult).all()

    user_results: dict[int, list[InvestigationResult]] = {}
    for r in results:
        user_results.setdefault(r.user_id, []).append(r)

    out = []
    for u in users:
        u_res = user_results.get(u.id, [])
        subs_count = len(u_res)
        tot_pts = sum(r.points_earned for r in u_res)
        avg_score = round(sum(r.score for r in u_res) / subs_count) if subs_count else 0
        out.append(
            UserAdminOut(
                id=u.id,
                username=u.username,
                role=u.role,
                created_at=u.created_at,
                submissions_count=subs_count,
                total_points=tot_pts,
                average_score=avg_score,
            )
        )
    return out


@app.post("/api/admin/users", response_model=UserAdminOut)
def admin_create_user(
    body: UserAdminCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin-controlled user creation (add a trainee or another admin)."""
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, hyphens, and underscores")

    existing = db.query(User).filter(User.username.ilike(username)).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{username}' is already registered")

    role = body.role if body.role in ("admin", "user") else "user"
    pw_hash = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    new_user = User(
        username=username,
        password_hash=pw_hash,
        role=role,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserAdminOut(
        id=new_user.id,
        username=new_user.username,
        role=new_user.role,
        created_at=new_user.created_at,
        submissions_count=0,
        total_points=0,
        average_score=0,
    )


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin-controlled user deletion with self-deletion protection and cascade cleanup."""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own active administrator account")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Clean up investigation records first (if cascade isn't fully enforced)
    db.query(InvestigationResult).filter(InvestigationResult.user_id == user_id).delete()
    uname = target_user.username
    db.delete(target_user)
    db.commit()
    return {"status": "success", "message": f"User '{uname}' and associated data deleted successfully"}


@app.patch("/api/admin/users/{user_id}/role")
def admin_update_user_role(
    user_id: int,
    body: UserAdminUpdateRole,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Promote trainee to admin or demote admin to trainee."""
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be either 'admin' or 'user'")
    if user_id == admin.id and body.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot demote your own active administrator account")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    target_user.role = body.role
    db.commit()
    db.refresh(target_user)
    return {"status": "success", "message": f"User '{target_user.username}' role changed to '{target_user.role}'", "role": target_user.role}


@app.patch("/api/admin/users/{user_id}/password")
def admin_reset_user_password(
    user_id: int,
    body: UserAdminResetPassword,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin password reset for any user."""
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    pw_hash = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    target_user.password_hash = pw_hash
    db.commit()
    return {"status": "success", "message": f"Password successfully reset for '{target_user.username}'"}



# ── Leaderboard Endpoint ──────────────────────────────────────────────────────

@app.get("/api/leaderboard", response_model=list[LeaderboardUserOut])
def get_leaderboard(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.role != "admin").all()
    results = db.query(InvestigationResult).all()

    user_results = {}
    for r in results:
        user_results.setdefault(r.user_id, []).append(r)

    leaderboard = []
    for u in users:
        u_res = user_results.get(u.id, [])
        total_points = sum(r.points_earned for r in u_res)
        scenarios_completed = len(set(r.scenario_id for r in u_res))
        avg_score = round(sum(r.score for r in u_res) / len(u_res)) if u_res else 0
        total_trials = sum(r.trials_count or 1 for r in u_res)
        hints_used_count = sum(len(r.hints_used or []) for r in u_res)

        if total_points >= 200:
            status = "Principal SOC Lead"
            badge = "🏆"
        elif total_points >= 120:
            status = "Senior Threat Hunter"
            badge = "🛡️"
        elif total_points >= 50:
            status = "Incident Responder"
            badge = "🔍"
        else:
            status = "Junior Analyst"
            badge = "🔰"

        leaderboard.append({
            "user_id": u.id,
            "username": u.username,
            "role": u.role,
            "total_points": total_points,
            "scenarios_completed": scenarios_completed,
            "average_score": avg_score,
            "total_trials": total_trials,
            "hints_used_count": hints_used_count,
            "status": status,
            "badge": badge,
        })

    leaderboard.sort(key=lambda x: (x["total_points"], x["scenarios_completed"], x["average_score"]), reverse=True)

    ranked_out = []
    for idx, entry in enumerate(leaderboard, start=1):
        entry["rank"] = idx
        ranked_out.append(LeaderboardUserOut(**entry))

    return ranked_out


@app.get("/api/admin/scenarios", response_model=list[ScenarioAdminOut])
def admin_list_scenarios(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenarios = db.query(Scenario).order_by(Scenario.id.desc()).all()

    # Batch counts to avoid N+1 queries
    log_counts = dict(
        db.query(Log.scenario_id, func.count(Log.id)).group_by(Log.scenario_id).all()
    )
    q_counts = dict(
        db.query(Question.scenario_id, func.count(Question.id)).group_by(Question.scenario_id).all()
    )
    alerts_by_sc = {
        a.scenario_id: a for a in db.query(Alert).all()
    }

    results = []
    for sc in scenarios:
        alert = alerts_by_sc.get(sc.id)
        results.append(ScenarioAdminOut(
            id=sc.id,
            name=sc.name,
            description=sc.description,
            mitre_technique=sc.mitre_technique,
            status=sc.status or "Draft",
            ad_context=sc.ad_context,
            alert=AlertOut.model_validate(alert) if alert else None,
            logs_count=log_counts.get(sc.id, 0),
            questions_count=q_counts.get(sc.id, 0),
        ))
    return results


@app.get("/api/admin/scenarios/{scenario_id}", response_model=ScenarioAdminDetailOut)
def admin_get_scenario_detail(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    alert = db.query(Alert).filter(Alert.scenario_id == sc.id).first()
    questions = db.query(Question).filter(Question.scenario_id == sc.id).all()
    log_cnt = db.query(Log).filter(Log.scenario_id == sc.id).count()

    return ScenarioAdminDetailOut(
        id=sc.id,
        name=sc.name,
        description=sc.description,
        mitre_technique=sc.mitre_technique,
        status=sc.status or "Draft",
        ad_context=sc.ad_context,
        alert=AlertOut.model_validate(alert) if alert else None,
        questions=[QuestionAdminOut.model_validate(q) for q in questions],
        logs_count=log_cnt,
    )


@app.post("/api/admin/scenarios", response_model=ScenarioOut)
def create_scenario(body: ScenarioCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = Scenario(**body.model_dump())
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@app.post("/api/admin/scenarios/full", response_model=ScenarioAdminDetailOut)
def create_scenario_full(body: ScenarioFullCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Atomic creation of Scenario + Alert + Questions in a single transaction."""
    try:
        sc = Scenario(
            name=body.name,
            description=body.description,
            mitre_technique=body.mitre_technique,
            status=body.status or "Published",
            ad_context=body.ad_context or {},
        )
        db.add(sc)
        db.flush()

        alert = Alert(
            scenario_id=sc.id,
            title=body.alert_title or f"Detection Alert: {body.name}",
            severity=body.alert_severity or SeverityLevel.HIGH,
            sigma_rule=body.sigma_rule,
        )
        db.add(alert)

        for q in (body.questions or []):
            if q.question_text.strip() and q.correct_answer.strip():
                db.add(Question(
                    scenario_id=sc.id,
                    question_text=q.question_text.strip(),
                    correct_answer=q.correct_answer.strip(),
                    acceptable_answers=q.acceptable_answers or [],
                    free_hint=q.free_hint,
                    hint=q.hint,
                    explanation=q.explanation,
                    points=q.points or 10,
                ))

        db.commit()
        return admin_get_scenario_detail(sc.id, db, admin)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scenario atomically: {str(e)}")


@app.put("/api/admin/scenarios/{scenario_id}", response_model=ScenarioOut)
def update_scenario(scenario_id: int, body: ScenarioUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(sc, field, val)

    db.commit()
    db.refresh(sc)
    return sc


@app.patch("/api/admin/scenarios/{scenario_id}/status", response_model=ScenarioOut)
def update_scenario_status(scenario_id: int, body: StatusUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    sc.status = body.status
    db.commit()
    db.refresh(sc)
    return sc


@app.put("/api/admin/scenarios/{scenario_id}/full", response_model=ScenarioAdminDetailOut)
def full_update_scenario(scenario_id: int, body: ScenarioFullUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if body.name is not None:
        sc.name = body.name
    if body.description is not None:
        sc.description = body.description
    if body.mitre_technique is not None:
        sc.mitre_technique = body.mitre_technique
    if body.status is not None:
        sc.status = body.status
    if body.ad_context is not None:
        sc.ad_context = body.ad_context

    if body.alert_title is not None or body.alert_severity is not None or body.sigma_rule is not None:
        alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
        if not alert:
            alert = Alert(
                scenario_id=scenario_id,
                title=body.alert_title or "Security Alert",
                severity=body.alert_severity or SeverityLevel.HIGH,
                sigma_rule=body.sigma_rule,
            )
            db.add(alert)
        else:
            if body.alert_title:
                alert.title = body.alert_title
            if body.alert_severity:
                alert.severity = body.alert_severity
            if body.sigma_rule is not None:
                alert.sigma_rule = body.sigma_rule

    if body.questions is not None:
        db.query(Question).filter(Question.scenario_id == scenario_id).delete()
        for q in body.questions:
            if q.question_text and q.correct_answer:
                new_q = Question(
                    scenario_id=scenario_id,
                    question_text=q.question_text,
                    correct_answer=q.correct_answer,
                    acceptable_answers=q.acceptable_answers or [],
                    free_hint=q.free_hint,
                    hint=q.hint,
                    explanation=q.explanation,
                    points=q.points if q.points is not None else 10,
                )
                db.add(new_q)

    db.commit()
    return admin_get_scenario_detail(scenario_id, db, admin)


@app.delete("/api/admin/scenarios/{scenario_id}")
def delete_scenario(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    db.query(InvestigationResult).filter(InvestigationResult.scenario_id == scenario_id).delete()
    db.query(Log).filter(Log.scenario_id == scenario_id).delete()
    db.query(Alert).filter(Alert.scenario_id == scenario_id).delete()
    db.query(Question).filter(Question.scenario_id == scenario_id).delete()
    db.query(Scenario).filter(Scenario.id == scenario_id).delete()
    db.commit()

    return {"status": "success", "message": f"Scenario {scenario_id} deleted successfully"}


@app.post("/api/admin/scenarios/{scenario_id}/alert", response_model=AlertOut)
def create_or_update_alert(scenario_id: int, body: AlertCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    db.query(Alert).filter(Alert.scenario_id == scenario_id).delete()

    alert = Alert(scenario_id=scenario_id, **body.model_dump())
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@app.post("/api/admin/scenarios/{scenario_id}/questions", response_model=QuestionAdminOut)
def create_question(scenario_id: int, body: QuestionCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    question = Question(scenario_id=scenario_id, **body.model_dump())
    db.add(question)
    db.commit()
    db.refresh(question)
    return question


@app.post("/api/admin/analyze-zip")
async def analyze_zip_endpoint(
    file: UploadFile = File(...),
    admin: User = Depends(require_admin),
):
    """
    Streams and analyzes 100% of events in an uploaded .zip archive, returning
    confidence-scored findings, observed AD context, and evidence-backed draft questions
    for Admin review before saving.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are supported")

    content = await file.read()
    try:
        report = analyze_zip_archive(content, target_sample_count=350)
        # Exclude raw curated_events array from the lightweight form-preview response
        return {k: v for k, v in report.items() if k != "curated_events"}
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid or corrupted .zip archive")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZIP analysis failed: {str(e)}")


@app.post("/api/admin/scenarios/{scenario_id}/upload-logs")
async def upload_logs(
    scenario_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    content = await file.read()
    try:
        analysis = analyze_zip_archive(content, target_sample_count=350)
        curated_events = analysis["curated_events"]

        log_entries = [
            Log(
                scenario_id=scenario_id,
                event_id=ev["event_id"],
                timestamp=ev["timestamp"],
                source_ip=ev["source_ip"],
                username=ev["username"],
                target_host=ev["target_host"],
                is_key_evidence=bool(ev.get("is_key_evidence", False)),
                raw_event_data=ev["raw"],
            )
            for ev in curated_events
        ]

        # If scenario had no ad_context yet, populate it with observed telemetry
        if not scenario.ad_context:
            scenario.ad_context = analysis["draft"]["ad_context"]

        db.query(Log).filter(Log.scenario_id == scenario_id).delete()
        db.add_all(log_entries)
        db.commit()

        return {
            "status": "success",
            "total_in_archive": analysis["total_events_in_archive"],
            "logs_inserted": len(log_entries),
            "key_evidence_count": analysis["key_evidence_count"],
            "message": (
                f"Analyzed {analysis['total_events_in_archive']} total events and curated "
                f"{len(log_entries)} logs ({analysis['key_evidence_count']} key evidence events preserved)."
            ),
        }
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file format")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Log ingestion error: {str(e)}")


# --- AUTO-APPLIED HARDENED OVERRIDES (Issues #1-#10) ---
import sys as _sys
from fastapi import Request as _Request
from fastapi.responses import JSONResponse as _JSONResponse
from hardened_overrides import (
    apply_hardened_routes as _apply_hardened_routes,
    check_login_rate_limit as _check_login_rate_limit,
    clear_login_rate_limit as _clear_login_rate_limit,
    validate_password_policy as _validate_password_policy,
)

_apply_hardened_routes(app, _sys.modules[__name__])

@app.middleware("http")
async def _auth_hardening_middleware(request: _Request, call_next):
    path = request.url.path
    if request.method == "POST" and path in {"/api/auth/login", "/api/auth/admin-login"}:
        client_ip = request.client.host if request.client else "unknown"
        try:
            _check_login_rate_limit(f"{client_ip}:{path}")
        except Exception as exc:
            status_code = getattr(exc, "status_code", 429)
            detail = getattr(exc, "detail", "Too many login attempts")
            return _JSONResponse(status_code=status_code, content={"detail": detail})
        response = await call_next(request)
        if response.status_code == 200:
            _clear_login_rate_limit(f"{client_ip}:{path}")
        return response
    return await call_next(request)
