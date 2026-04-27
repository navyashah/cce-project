from __future__ import annotations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.config import settings

# check_same_thread is SQLite-only — PostgreSQL on Railway doesn't need it
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
