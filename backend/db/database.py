# CSP Guardian v2 – db/database.py
# Database connection & session management

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from .models import Base

# ── Database URL ──────────────────────────────────────────────────────────────
# Default: SQLite (zero-config, file-based)
# Override with DATABASE_URL env var for PostgreSQL/MySQL in production:
#   postgresql://user:pass@localhost/csp_guardian
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./csp_guardian.db"
)

# ── Engine setup ──────────────────────────────────────────────────────────────
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {
        "check_same_thread": False,
    }

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set True to log SQL queries
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Init DB (create tables) ───────────────────────────────────────────────────
def init_db():
    Base.metadata.create_all(bind=engine)


# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()