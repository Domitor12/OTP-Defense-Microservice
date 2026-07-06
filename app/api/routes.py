"""
REST API endpoints for the OTP Defense Microservice.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db_session
from app.dependencies import verify_internal_token
from app.models import FailedLoginAttempt
from app.redis_client import get_redis
from app.schemas import (
    FailedLoginReport,
    HealthResponse,
    OTPEvaluateRequest,
    OTPEvaluateResponse,
)
from app.services.evaluator import evaluate_otp_request

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── OTP Evaluation ─────────────────────────────────────────────────

@router.post(
    "/otp/evaluate",
    response_model=OTPEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate whether an OTP should be sent",
    description=(
        "Run IP reputation, failed-login velocity, and rate-limit checks. "
        "Returns ALLOW, BLOCK, or CHALLENGE."
    ),
)
async def post_evaluate_otp(
    payload: OTPEvaluateRequest,
    db: AsyncSession = Depends(get_db_session),
    _auth: str = Depends(verify_internal_token),
) -> OTPEvaluateResponse:
    logger.info(
        "otp_evaluate_request",
        user_id=payload.user_id,
        ip=payload.ip_address,
        phone=payload.phone_number,
    )
    response = await evaluate_otp_request(payload, db)
    logger.info(
        "otp_evaluate_result",
        action=response.action.value,
        request_id=response.request_id,
    )
    return response


# ── Failed Login Reporting ─────────────────────────────────────────

@router.post(
    "/auth/failed-login",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Report a failed login attempt",
)
async def post_failed_login(
    payload: FailedLoginReport,
    db: AsyncSession = Depends(get_db_session),
    _auth: str = Depends(verify_internal_token),
) -> dict:
    """
    Called by the login system on every failed authentication.
    Records the event in both Redis (for real-time rate limiting)
    and PostgreSQL (for durable audit).
    """
    import time, uuid

    # 1. Update Redis sliding window
    from app.redis_client import get_redis as _get_redis
    try:
        redis = await _get_redis()
        key = f"rate:failed_login:{payload.user_id}"
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex[:8]}"
        from app.config import get_settings
        settings = get_settings()
        await redis.zadd(key, {member: now})
        await redis.expire(key, settings.failed_login_window_seconds)
    except Exception as exc:
        logger.warning("redis_failed_login_record_error", error=str(exc))

    # 2. Persist to PostgreSQL
    attempt = FailedLoginAttempt(
        user_id=payload.user_id,
        ip_address=payload.ip_address,
        metadata_json=str(payload.metadata) if payload.metadata else None,
    )
    db.add(attempt)

    logger.info("failed_login_recorded", user_id=payload.user_id)
    return {"status": "recorded", "user_id": payload.user_id}


# ── Health Check ───────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["ops"],
    include_in_schema=True,
)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> HealthResponse:
    """Liveness + readiness probe for Kubernetes / load balancers."""
    pg_status = "unknown"
    redis_status = "unknown"

    try:
        await db.execute(text("SELECT 1"))
        pg_status = "healthy"
    except Exception:
        pg_status = "unhealthy"

    try:
        redis = await get_redis()
        await redis.ping()
        redis_status = "healthy"
    except Exception:
        redis_status = "unhealthy"

    overall = "healthy" if (pg_status == "healthy" and redis_status == "healthy") else "degraded"

    return HealthResponse(
        status=overall,
        postgres=pg_status,
        redis=redis_status,
    )