from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime


# ── Scenario ──────────────────────────────────────────────────────────────────

class ScenarioOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str = "Draft"
    ad_context: Optional[dict[str, Any]] = None
    severity: Optional[str] = "High"
    alert_title: Optional[str] = None
    trials_count: Optional[int] = 0
    attempts_count: Optional[int] = 0
    best_score: Optional[int] = None
    last_score: Optional[int] = None
    in_progress: Optional[bool] = False
    question_count: Optional[int] = 0
    log_count: Optional[int] = 0

    model_config = {"from_attributes": True}


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    scenario_id: int
    title: str
    severity: str
    sigma_rule: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Log ───────────────────────────────────────────────────────────────────────

class LogOut(BaseModel):
    id: int
    scenario_id: int
    event_id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    target_host: Optional[str] = None
    raw_event_data: dict[str, Any]

    model_config = {"from_attributes": True}



class LogAdminOut(LogOut):
    is_key_evidence: bool = False

# ── Question ──────────────────────────────────────────────────────────────────

class QuestionOut(BaseModel):
    id: int
    scenario_id: int
    question_text: str
    points: int = 10
    has_hint: bool = True
    # correct_answer & acceptable_answers excluded for trainees

    model_config = {"from_attributes": True}


class QuestionAdminOut(BaseModel):
    id: int
    scenario_id: int
    question_text: str
    correct_answer: str
    acceptable_answers: Optional[list[str]] = Field(default_factory=list)
    free_hint: Optional[str] = None
    hint: Optional[str] = None
    explanation: Optional[str] = None
    points: int = 10

    model_config = {"from_attributes": True}


# ── Submission & Hint (request bodies) ────────────────────────────────────────

class AnswerSubmission(BaseModel):
    question_id: int
    answer: str


class VerifyFindingRequest(BaseModel):
    question_id: int
    answer: str


class VerifyFindingResponse(BaseModel):
    question_id: int
    is_correct: bool
    trap_detected: bool = False
    message: str
    trap_msg: Optional[str] = None


class HintResponse(BaseModel):
    question_id: int
    hint: str
    point_deduction: int = 15
    is_free: bool = False


class SubmissionRequest(BaseModel):
    answers: list[AnswerSubmission]
    pinned_log_ids: Optional[list[int]] = Field(default_factory=list)
    hints_used: Optional[list[int]] = Field(default_factory=list)
    free_hint_id: Optional[int] = None
    free_hints_used: Optional[list[int]] = Field(default_factory=list)
    trials_count: Optional[int] = 1
    user_guesses: Optional[dict[str, list[str]]] = Field(default_factory=dict)
    containment_host: Optional[str] = None
    containment_user: Optional[str] = None


class ContainmentResult(BaseModel):
    enabled: bool = False
    expected_host: Optional[str] = None
    selected_host: Optional[str] = None
    host_correct: Optional[bool] = None
    expected_user: Optional[str] = None
    selected_user: Optional[str] = None
    user_correct: Optional[bool] = None
    feedback: Optional[str] = None


# ── Grading result (response) ─────────────────────────────────────────────────

class QuestionResult(BaseModel):
    question_id: int
    question_text: str
    user_answer: str
    correct_answer: str
    explanation: Optional[str] = None
    is_correct: bool
    points_awarded: int = 0
    points_possible: int = 10


class SubmissionResponse(BaseModel):
    scenario_id: int
    total_questions: int
    correct_count: int
    total_points: int = 0
    points_earned: int = 0
    score_percent: int
    score: Optional[int] = None
    pinned_log_ids: list[int] = Field(default_factory=list)
    key_evidence_log_ids: list[int] = Field(default_factory=list)
    hints_used: list[int] = Field(default_factory=list)
    free_hint_id: Optional[int] = None
    free_hints_used: list[int] = Field(default_factory=list)
    hint_penalty: int = 0
    trials_count: int = 1
    containment_eval: Optional[ContainmentResult] = None
    results: list[QuestionResult]


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class ScenarioCreate(BaseModel):
    name: str
    description: str
    mitre_technique: str
    status: Optional[str] = "Published"
    ad_context: Optional[dict[str, Any]] = None


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None
    ad_context: Optional[dict[str, Any]] = None


class StatusUpdate(BaseModel):
    status: str


class AlertCreate(BaseModel):
    title: str
    severity: str
    sigma_rule: Optional[str] = None


class QuestionCreate(BaseModel):
    question_text: str
    correct_answer: str
    acceptable_answers: Optional[list[str]] = Field(default_factory=list)
    free_hint: Optional[str] = None
    hint: Optional[str] = None
    explanation: Optional[str] = None
    points: int = 10


class ScenarioAdminOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str
    ad_context: Optional[dict[str, Any]] = None
    alert: Optional[AlertOut] = None
    logs_count: int = 0
    questions_count: int = 0

    model_config = {"from_attributes": True}


class ScenarioAdminDetailOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str
    ad_context: Optional[dict[str, Any]] = None
    alert: Optional[AlertOut] = None
    questions: list[QuestionAdminOut] = Field(default_factory=list)
    logs_count: int = 0

    model_config = {"from_attributes": True}


class ScenarioFullCreate(BaseModel):
    name: str
    description: str
    mitre_technique: str
    status: Optional[str] = "Published"
    ad_context: Optional[dict[str, Any]] = None
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = "High"
    sigma_rule: Optional[str] = None
    questions: Optional[list[QuestionCreate]] = Field(default_factory=list)


class ScenarioFullUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None
    ad_context: Optional[dict[str, Any]] = None
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = None
    sigma_rule: Optional[str] = None
    questions: Optional[list[QuestionCreate]] = None


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    avatar_color: Optional[str] = '#3b82f6'
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class UserAdminOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: Optional[datetime] = None
    submissions_count: int = 0
    total_points: int = 0
    average_score: int = 0

    model_config = {"from_attributes": True}


class UserAdminCreate(BaseModel):
    username: str
    password: str
    role: str = "user"


class UserAdminUpdateRole(BaseModel):
    role: str


class UserAdminResetPassword(BaseModel):
    password: str


class AuthResponse(BaseModel):
    token: str
    user: UserOut
    message: str = "Success"


class UserProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    avatar_color: Optional[str] = None


class UserProfileOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    avatar_color: Optional[str] = '#3b82f6'
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Activity & Leaderboard Schemas ───────────────────────────────────────────

class SubmissionAdminOut(BaseModel):
    id: int
    user_id: int
    username: str
    user_role: str
    scenario_id: int
    scenario_name: str
    mitre_technique: str
    score: int
    points_earned: int
    total_points: int
    hints_used: list[int] = Field(default_factory=list)
    free_hint_id: Optional[int] = None
    free_hints_used: list[int] = Field(default_factory=list)
    hint_penalty: int = 0
    trials_count: int = 1
    user_guesses: Optional[dict[str, Any]] = Field(default_factory=dict)
    status: str = "Completed"
    submitted_at: Optional[str] = None


class LeaderboardUserOut(BaseModel):
    rank: int
    user_id: int
    username: str
    role: str
    total_points: int
    scenarios_completed: int
    average_score: int
    total_trials: int
    hints_used_count: int
    status: str
    badge: str


# --- HARDENED SCHEMA OVERRIDES ---
import re as _re
from pydantic import field_validator as _field_validator

class HardenedUserRegister(UserRegister):
    @_field_validator("password")
    @classmethod
    def validate_strong_password(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(v) > 128:
            raise ValueError("Password must not exceed 128 characters.")
        if not _re.search(r"[A-Za-z]", v) or not _re.search(r"[0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", v):
            raise ValueError("Password must contain at least one letter and one number or special character.")
        return v

UserRegister = HardenedUserRegister
