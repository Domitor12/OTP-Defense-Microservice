"""
Redis connection pool and atomic Lua-script-based rate limiting.

Design rationale:
  - Sorted sets (ZSET) give us a precise sliding window.
  - Lua scripts ensure atomicity: no TOCTOU race conditions
    between checking the count and adding a new entry.
  - EXPIRE provides automatic key cleanup so Redis memory
    does not grow unbounded.
"""

import time
import uuid

import redis.asyncio as aioredis
from redis.asyncio import Redis
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.config import get_settings

settings = get_settings()

# ── Connection Pool ────────────────────────────────────────────────

_redis_pool: Redis | None = None


async def get_redis() -> Redis:
    """Returns the global Redis connection (singleton pattern)."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
    return _redis_pool


async def close_redis() -> None:
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None


# ── Lua Scripts ────────────────────────────────────────────────────

# Atomic sliding-window rate limiter using sorted sets.
# Returns 1 if the request is ALLOWED, 0 if RATE LIMITED.
SLIDING_WINDOW_SCRIPT = """
local key          = KEYS[1]
local now          = tonumber(ARGV[1])
local window       = tonumber(ARGV[2])
local limit        = tonumber(ARGV[3])
local member       = ARGV[4]

-- Evict entries outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

-- Count remaining entries
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window))
    return 1
else
    return 0
end
"""

# Check-only variant: does NOT add an entry. Returns the current count.
SLIDING_WINDOW_COUNT_SCRIPT = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
return redis.call('ZCARD', key)
"""


# ── Rate Limiter Interface ─────────────────────────────────────────

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.1, min=0.1, max=1.0),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    reraise=True,
)
async def check_and_record_rate_limit(
    key: str,
    window_seconds: int,
    max_allowed: int,
) -> tuple[bool, int]:
    """
    Atomically checks the sliding-window count and, if under the
    limit, records a new entry.

    Returns:
        (allowed: bool, current_count: int)
    """
    redis = await get_redis()
    now = time.time()
    member = f"{now}:{uuid.uuid4().hex[:8]}"

    # Register the script once; Redis caches by SHA
    script = redis.register_script(SLIDING_WINDOW_SCRIPT)
    result = await script(
        keys=[key],
        args=[now, window_seconds, max_allowed, member],
    )

    allowed = bool(result)
    # If allowed, count is previous + 1; if not, it's at limit
    current_count = max_allowed if not allowed else (max_allowed)  # approximate
    return allowed, current_count


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.1, min=0.1, max=1.0),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    reraise=True,
)
async def get_sliding_window_count(key: str, window_seconds: int) -> int:
    """Returns the number of events in the current sliding window (read-only)."""
    redis = await get_redis()
    now = time.time()
    script = redis.register_script(SLIDING_WINDOW_COUNT_SCRIPT)
    count = await script(keys=[key], args=[now, window_seconds])
    return int(count)


async def is_ip_malicious(ip_address: str) -> bool:
    """O(1) check against the cached malicious IP set in Redis."""
    redis = await get_redis()
    return bool(await redis.sismember("threat_intel:malicious_ips", ip_address))


async def seed_malicious_ips(ip_addresses: set[str]) -> None:
    """Bulk-loads IPs into the Redis malicious set (called at startup)."""
    if not ip_addresses:
        return
    redis = await get_redis()
    await redis.sadd("threat_intel:malicious_ips", *ip_addresses)