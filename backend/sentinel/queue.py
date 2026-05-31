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


# --- pub/sub for live agent traces (SSE) ---

def trace_channel(investigation_id: str) -> str:
    return f"sentinel:trace:{investigation_id}"


async def publish_trace(investigation_id: str, event: dict) -> None:
    await get_redis().publish(trace_channel(investigation_id), json.dumps(event, default=str))
