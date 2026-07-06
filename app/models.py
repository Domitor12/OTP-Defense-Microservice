"""
SQLAlchemy ORM models for persistent audit and reputation storage.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Integer, Float, Text, Index, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FailedLoginAttempt(Base):
    """
    Records every failed authentication attempt.
    Used for long-term analytics, forensic investigation,
    and as a durable fallback when Redis data expires.
    """
    __tablename__ = "failed_login_attempts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv6-safe
    attempt_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, index=True
    )
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_failed_login_user_time", "user_id", "attempt_time"),
    )


class OTPRequestLog(Base):
    """
    Immutable audit log of every OTP evaluation decision.
    Critical for compliance, incident response, and ML training data.
    """
    __tablename__ = "otp_request_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)   # ALLOW, BLOCK, CHALLENGE
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_otp_log_phone_time", "phone_number", "evaluated_at"),
        Index("ix_otp_log_action", "action"),
    )


class IPReputation(Base):
    """
    Stores known malicious IPs from threat intelligence feeds.
    Acts as the durable backing store for the Redis cache.
    """
    __tablename__ = "ip_reputation"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "botnet", "vishing"
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(255), nullable=False)  # feed name
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_ip_reputation_active", "ip_address", "is_active"),
    )