"""
Core OTP evaluation engine.

Evaluation pipeline (fail-fast, ordered by cost):
  1. IP reputation   (Redis O(1) lookup)
  2. Failed login velocity  (Redis sliding window)
  3. OTP request rate limit (Redis sliding window)
  4. (Extensible) Device / geo anomaly checks

On ALLOW, the OTP request is also recorded so that future
evaluations see an updated count.
"""

import time
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import FailedLoginAttempt, OTPRequestLog
from app.redis_client import (
    check_and_record_rate_limit,
    get_sliding_window_count,
    is_ip_malicious,
)
from app.schemas import OTPAction, OTPEvaluateRequest, OTPEvaluateResponse

logger = structlog.get_logger(__name__)
settings = get_settings()


async def evaluate_otp_request(
    request: OTPEvaluateRequest,
    db: AsyncSession,
) -> OTPEvaluateResponse:
    """
    Runs the full evaluation pipeline and returns a decision.
    Persists an immutable audit log regardless of outcome.
    """
    request_id = uuid.uuid4().hex
    evaluated_at = datetime.now(timezone.utc)
    details: dict = {}

    # ────────────────────────────────────────────────────────────
    # CHECK 1 — IP Reputation (cheapest, fastest fail)
    # ────────────────────────────────────────────────────────────
    try:
        if await is_ip_malicious(request.ip_address):
            reason = "Request originated from a known malicious IP address."
            await _persist_log(db, request, OTPAction.BLOCK, reason, evaluated_at)
            return OTPEvaluateResponse(
                action=OTPAction.BLOCK,
                reason=reason,
                request_id=request_id,
                evaluated_at=evaluated_at,
                details={"check": "ip_reputation", "ip": request.ip_address},
            )
    except Exception as exc:
        # Graceful degradation: if Redis is unreachable, log and continue
        logger.warning("ip_reputation_check_failed", error=str(exc))
        details["ip_reputation_error"] = str(exc)

    # ────────────────────────────────────────────────────────────
    # CHECK 2 — Failed Login Velocity
    # ────────────────────────────────────────────────────────────
    failed_login_key = f"rate:failed_login:{request.user_id}"
    try:
        failed_count = await get_sliding_window_count(
            failed_login_key,
            settings.failed_login_window_seconds,
        )
        details["recent_failed_logins"] = failed_count

        if failed_count >= settings.failed_login_max_attempts:
            reason = (
                f"High velocity of failed login attempts detected "
                f"({failed_count} in {settings.failed_login_window_seconds}s)."
            )
            await _persist_log(db, request, OTPAction.BLOCK, reason, evaluated_at)
            return OTPEvaluateResponse(
                action=OTPAction.BLOCK,
                reason=reason,
                request_id=request_id,
                evaluated_at=evaluated_at,
                details=details,
            )
    except Exception as exc:
        logger.warning("failed_login_velocity_check_failed", error=str(exc))
        # Fallback: query PostgreSQL directly
        failed_count = await _count_failed_logins_db(db, request.user_id)
        details["recent_failed_logins_db_fallback"] = failed_count
        if failed_count >= settings.failed_login_max_attempts:
            reason = (
                f"High velocity of failed login attempts detected (DB fallback: "
                f"{failed_count} in {settings.failed_login_window_seconds}s)."
            )
            await _persist_log(db, request, OTPAction.BLOCK, reason, evaluated_at)
            return OTPEvaluateResponse(
                action=OTPAction.BLOCK, reason=reason,
                request_id=request_id, evaluated_at=evaluated_at, details=details,
            )

    # ────────────────────────────────────────────────────────────
    # CHECK 3 — OTP Request Rate Limit (per phone number)
    # ────────────────────────────────────────────────────────────
    otp_key = f"rate:otp_request:{request.phone_number}"
    try:
        allowed, _ = await check_and_record_rate_limit(
            otp_key,
            settings.otp_request_window_seconds,
            settings.otp_request_max_attempts,
        )
        details["otp_rate_limit_allowed"] = allowed

        if not allowed:
            reason = (
                f"OTP rate limit exceeded for phone number "
                f"(max {settings.otp_request_max_attempts} "
                f"per {settings.otp_request_window_seconds}s). "
                f"Require alternate verification."
            )
            await _persist_log(db, request, OTPAction.CHALLENGE, reason, evaluated_at)
            return OTPEvaluateResponse(
                action=OTPAction.CHALLENGE,
                reason=reason,
                request_id=request_id,
                evaluated_at=evaluated_at,
                details=details,
            )
    except Exception as exc:
        logger.warning("otp_rate_limit_check_failed", error=str(exc))
        details["otp_rate_limit_error"] = str(exc)
        # If Redis is down, we still allow but flag it — don't block legitimate users
        details["degraded_mode"] = True

    # ────────────────────────────────────────────────────────────
    # ALL CHECKS PASSED → ALLOW
    # ────────────────────────────────────────────────────────────
    reason = "Request meets all security baselines."
    await _persist_log(db, request, OTPAction.ALLOW, reason, evaluated_at)

    return OTPEvaluateResponse(
        action=OTPAction.ALLOW,
        reason=reason,
        request_id=request_id,
        evaluated_at=evaluated_at,
        details=details,
    )


# ── Internal helpers ───────────────────────────────────────────────

async def _persist_log(
    db: AsyncSession,
    req: OTPEvaluateRequest,
    action: OTPAction,
    reason: str,
    evaluated_at: datetime,
) -> None:
    """Write an immutable audit record to PostgreSQL."""
    log_entry = OTPRequestLog(
        user_id=req.user_id,
        phone_number=req.phone_number,
        ip_address=req.ip_address,
        action=action.value,
        reason=reason,
        evaluated_at=evaluated_at,
    )
    db.add(log_entry)


async def _count_failed_logins_db(db: AsyncSession, user_id: str) -> int:
    """PostgreSQL fallback for counting recent failed logins."""
    cutoff = datetime.now(timezone.utc).timestamp() - settings.failed_login_window_seconds
    from datetime import datetime as dt, timezone as tz
    cutoff_dt = dt.fromtimestamp(cutoff, tz=tz.utc)

    stmt = (
        select(FailedLoginAttempt)
        .where(
            FailedLoginAttempt.user_id == user_id,
            FailedLoginAttempt.attempt_time >= cutoff_dt,
        )
    )
    result = await db.execute(stmt)
    return len(result.scalars().all())