from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, DateTime, Boolean, Index, JSON, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
import enum

# Dialect-aware JSON type: uses binary JSONB on PostgreSQL and standard JSON on SQLite
JSONType = JSON().with_variant(JSONB, "postgresql")


class SeverityLevel(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    email = Column(String(200), nullable=True)
    avatar_color = Column(String(20), nullable=True, default='#3b82f6')  # hex color for avatar

    investigation_results = relationship("InvestigationResult", back_populates="user", cascade="all, delete-orphan")



class Scenario(Base):
    __tablename__ = "scenarios"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    mitre_technique = Column(String(100), nullable=False)
    status = Column(String(20), default="Draft", nullable=False)
    ad_context = Column(JSONType, nullable=True, default=dict)

    alerts = relationship("Alert", back_populates="scenario", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="scenario", cascade="all, delete-orphan")
    questions = relationship("Question", back_populates="scenario", cascade="all, delete-orphan")
    investigation_results = relationship("InvestigationResult", back_populates="scenario", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    severity = Column(SAEnum(SeverityLevel), nullable=False)
    sigma_rule = Column(Text, nullable=True)

    scenario = relationship("Scenario", back_populates="alerts")


class Log(Base):
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_scenario_timestamp", "scenario_id", "timestamp"),
        Index("ix_logs_scenario_event_id", "scenario_id", "event_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    event_id = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=True)
    username = Column(String(150), nullable=True)
    target_host = Column(String(200), nullable=True)
    is_key_evidence = Column(Boolean, default=False, nullable=False)
    raw_event_data = Column(JSONType, nullable=False)

    scenario = relationship("Scenario", back_populates="logs")


class Question(Base):
    __tablename__ = "questions"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    question_text = Column(Text, nullable=False)
    correct_answer = Column(String(300), nullable=False)
    acceptable_answers = Column(JSONType, nullable=True, default=list)
    free_hint = Column(Text, nullable=True)
    hint = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    points = Column(Integer, default=10, nullable=False)

    scenario = relationship("Scenario", back_populates="questions")


class InvestigationResult(Base):
    __tablename__ = "investigation_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    points_earned = Column(Integer, default=0, nullable=False)
    total_points = Column(Integer, default=0, nullable=False)
    pinned_log_ids = Column(JSONType, nullable=True, default=list)
    hints_used = Column(JSONType, nullable=True, default=list)
    free_hint_id = Column(Integer, nullable=True)
    free_hints_used = Column(JSONType, nullable=True, default=list)
    trials_count = Column(Integer, default=1, nullable=False)
    user_guesses = Column(JSONType, nullable=True, default=dict)
    submitted_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="investigation_results")
    scenario = relationship("Scenario", back_populates="investigation_results")


class QuestionAttempt(Base):
    __tablename__ = "question_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id", ondelete="CASCADE"), nullable=False, index=True)
    question_id = Column(Integer, ForeignKey("questions.id", ondelete="CASCADE"), nullable=False, index=True)
    free_hint_used = Column(Boolean, default=False, nullable=False)
    paid_hint_used = Column(Boolean, default=False, nullable=False)
    wrong_attempts = Column(Integer, default=0, nullable=False)
    is_solved = Column(Boolean, default=False, nullable=False)
