"""
IP Reputation management: seeding Redis from PostgreSQL,
and adding new entries from threat intel feeds.
"""

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IPReputation
from app.redis_client import seed_malicious_ips, get_redis

logger = structlog.get_logger(__name__)


async def load_ip_reputation_into_cache(db: AsyncSession) -> int:
    """
    Called at application startup.
    Loads all active malicious IPs from PostgreSQL into a Redis SET
    for O(1) runtime lookups.
    """
    stmt = select(IPReputation.ip_address).where(IPReputation.is_active.is_(True))
    result = await db.execute(stmt)
    ips = {row[0] for row in result.all()}

    if ips:
        await seed_malicious_ips(ips)
        logger.info("ip_reputation_seeded", count=len(ips))
    else:
        logger.info("ip_reputation_empty", count=0)

    return len(ips)


async def add_malicious_ip(
    db: AsyncSession,
    ip_address: str,
    threat_type: str,
    source: str,
    confidence: float = 1.0,
) -> None:
    """Add a new IP to both PostgreSQL and the Redis cache."""
    entry = IPReputation(
        ip_address=ip_address,
        threat_type=threat_type,
        confidence_score=confidence,
        source=source,
    )
    db.add(entry)
    await db.flush()

    # Immediate cache update
    redis = await get_redis()
    await redis.sadd("threat_intel:malicious_ips", ip_address)

    logger.info("malicious_ip_added", ip=ip_address, threat_type=threat_type)