"""
FastAPI application factory with lifespan management.
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes import router
from app.config import get_settings
from app.database import async_session_factory, close_db, init_db
from app.redis_client import close_redis, get_redis
from app.services.ip_reputation import load_ip_reputation_into_cache

settings = get_settings()

# ── Structured Logging ─────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if settings.app_env == "production"
            else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        structlog.get_level_from_name(settings.log_level)
    ),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


# ── Lifespan (Startup / Shutdown) ─────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage resources across the application lifecycle."""
    logger.info("starting_otp_defense_service", env=settings.app_env)

    # 1. Initialize database tables (use Alembic in real production)
    await init_db()
    logger.info("database_initialized")

    # 2. Verify Redis connectivity
    try:
        redis = await get_redis()
        await redis.ping()
        logger.info("redis_connected")
    except Exception as exc:
        logger.error("redis_connection_failed", error=str(exc))

    # 3. Seed IP reputation cache from PostgreSQL
    try:
        async with async_session_factory() as db:
            count = await load_ip_reputation_into_cache(db)
            logger.info("ip_reputation_cache_warmed", entries=count)
    except Exception as exc:
        logger.error("ip_reputation_seed_failed", error=str(exc))

    yield  # ── Application is running ──

    # Shutdown
    logger.info("shutting_down_otp_defense_service")
    await close_redis()
    await close_db()


# ── Application Factory ────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="OTP Defense Microservice",
        description=(
            "Evaluates OTP dispatch requests against IP reputation, "
            "failed-login velocity, and rate-limit checks. Returns "
            "ALLOW, BLOCK, or CHALLENGE decisions."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )

    # ── Middleware ──────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request ID middleware for distributed tracing ───────────
    @app.middleware("http")
    async def add_request_id(request, call_next):
        import uuid
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Routes ─────────────────────────────────────────────────
    app.include_router(router, prefix=settings.api_prefix)

    return app


app = create_app()