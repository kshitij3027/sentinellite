"""Redis-backed queues + pub/sub. The ingest queue feeds the worker pipeline;
SSE streams (R10) ride on pub/sub channels."""

from __future__ import annotations

import json

import redis.asyncio as aioredis

from sentinel.config import settings

INGEST_QUEUE = "sentinel:ingest"

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def enqueue_alert(tenant_id: str, alert_id: str) -> None:
    await get_redis().lpush(INGEST_QUEUE, json.dumps({"tenant_id": tenant_id, "alert_id": alert_id}))


async def dequeue_alert(timeout: int = 5) -> dict | None:
    res = await get_redis().brpop(INGEST_QUEUE, timeout=timeout)
    if not res:
        return None
    _key, payload = res
    return json.loads(payload)


async def queue_depth() -> int:
    return int(await get_redis().llen(INGEST_QUEUE))


# --- debounced investigation scheduling ---
# A sorted set of "tenant|inv_id" -> ready_at epoch. Re-marking pushes ready_at
# out, so an investigation only runs after a quiet period (debounce).
DIRTY_INV = "sentinel:inv_dirty"


async def mark_investigation_dirty(tenant_id: str, inv_id: str, debounce_s: float) -> None:
    import time

    await get_redis().zadd(DIRTY_INV, {f"{tenant_id}|{inv_id}": time.time() + debounce_s})


async def pop_ready_investigations() -> list[tuple[str, str]]:
    import time

    r = get_redis()
    members = await r.zrangebyscore(DIRTY_INV, "-inf", time.time())
    out: list[tuple[str, str]] = []
    for m in members:
        if await r.zrem(DIRTY_INV, m):  # claim atomically
            tenant, inv_id = m.split("|", 1)
            out.append((tenant, inv_id))
    return out


# --- pub/sub for live agent traces (SSE) ---

def trace_channel(investigation_id: str) -> str:
    return f"sentinel:trace:{investigation_id}"


async def publish_trace(investigation_id: str, event: dict) -> None:
    await get_redis().publish(trace_channel(investigation_id), json.dumps(event, default=str))
