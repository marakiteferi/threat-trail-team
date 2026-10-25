"""
Automated, idempotent schema migration runner for ThreatTrail.
Consolidates migrate_auth.py and migrate_hints_and_tracking.py safely without dropping tables.
"""
from sqlalchemy import inspect, text
from database import engine
import models


def run_migrations() -> None:
    # Create any missing tables (including question_attempts) non-destructively
    models.Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    column_migrations = {
        "users": [
            ("role", "VARCHAR(50) DEFAULT 'trainee' NOT NULL"),
        ],
        "scenarios": [
            ("status", "VARCHAR(50) DEFAULT 'draft' NOT NULL"),
            ("ad_context", "TEXT"),
        ],
        "questions": [
            ("acceptable_answers", "TEXT"),
            ("free_hint", "TEXT"),
            ("hint", "TEXT"),
            ("explanation", "TEXT"),
            ("points", "INTEGER DEFAULT 10 NOT NULL"),
        ],
        "investigation_results": [
            ("points_earned", "INTEGER DEFAULT 0"),
            ("total_points", "INTEGER DEFAULT 100"),
            ("pinned_log_ids", "TEXT"),
        ],
    }

    with engine.begin() as conn:
        for table_name, columns in column_migrations.items():
            if table_name not in existing_tables:
                continue
            existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
            for col_name, col_def in columns:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}"))


if __name__ == "__main__":
    run_migrations()
    print("[+] Database migrations applied safely.")
