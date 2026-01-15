from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uuid_str() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"


class EvalStatus(str, enum.Enum):
    pass_ = "PASS"
    fail = "FAIL"


class Control(Base):
    """
    Controls are defined as code (YAML) but stored for traceability and drift detection.
    """

    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    control_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    risk: Mapped[str] = mapped_column(Text)
    expected_state: Mapped[dict] = mapped_column(JSON)
    evidence_sources: Mapped[list] = mapped_column(JSON)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    check_frequency: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Evidence(Base):
    """
    Immutable, timestamped evidence snapshots.

    Immutability policy:
    - We never update an Evidence row once written.
    - The API intentionally exposes only create + read.
    - DB-level immutability (e.g., triggers) is a natural next step but out of scope.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("control_id", "source_system", "collected_at", name="uq_evidence_snapshot"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    source_system: Mapped[str] = mapped_column(String(64), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    raw_snapshot: Mapped[dict] = mapped_column(JSON)


class Evaluation(Base):
    """
    Evaluations are the interpreted results of a snapshot.

    Design choice:
    - Evidence is raw and immutable (what we saw).
    - Evaluation is also append-only and immutable (what we concluded at the time).
    """

    __tablename__ = "evaluations"
    __table_args__ = (
        UniqueConstraint("control_id", "evaluated_at", name="uq_evaluation_point_in_time"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence.id"), index=True)

    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[EvalStatus] = mapped_column(Enum(EvalStatus), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    remediation: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    """
    Basic internal alerting: record high-severity control failures.
    """

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    message: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

