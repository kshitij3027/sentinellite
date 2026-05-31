"""Immutable audit log with a SHA-256 hash chain (R9).

Each event's hash covers (prev_hash, seq, tenant_id, content). Tampering with
any row breaks every link after it; `verify_chain` reports the first break.

The hashing/verification core is pure (no DB) so it is trivially unit-testable;
the DB layer just loads rows and delegates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.db.models import AuditEvent
from sentinel.types import new_id

GENESIS_HASH = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, seq: int, tenant_id: str, content: dict) -> str:
    material = prev_hash + _canonical({"seq": seq, "tenant_id": tenant_id, "content": content})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class ChainRow:
    seq: int
    tenant_id: str
    content: dict
    prev_hash: str
    hash: str


def verify_rows(rows: list[ChainRow]) -> dict:
    """Walk an ordered chain; return ok + the first broken index (if any)."""
    prev = GENESIS_HASH
    for i, r in enumerate(rows):
        if r.prev_hash != prev:
            return {"ok": False, "length": len(rows), "broken_index": i, "reason": "prev_hash mismatch"}
        if compute_hash(prev, r.seq, r.tenant_id, r.content) != r.hash:
            return {"ok": False, "length": len(rows), "broken_index": i, "reason": "hash mismatch"}
        prev = r.hash
    return {"ok": True, "length": len(rows), "broken_index": None, "head_hash": prev}


# --------------------------- DB-backed operations ---------------------------

async def append_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    actor: str,
    event_type: str,
    data: dict | None = None,
) -> AuditEvent:
    """Append one event to the tenant's chain. Caller controls the transaction;
    a per-tenant advisory xact-lock serializes concurrent appends."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:t))"), {"t": tenant_id}
    )
    last = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    seq = (last.seq + 1) if last else 1
    prev_hash = last.hash if last else GENESIS_HASH
    content = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "event_type": event_type,
        "data": data or {},
    }
    h = compute_hash(prev_hash, seq, tenant_id, content)
    event = AuditEvent(
        id=new_id("aud"),
        tenant_id=tenant_id,
        seq=seq,
        content=content,
        prev_hash=prev_hash,
        hash=h,
    )
    session.add(event)
    await session.flush()
    return event


async def get_chain(session: AsyncSession, tenant_id: str, limit: int = 500) -> list[AuditEvent]:
    rows = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.asc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)


async def verify_chain(session: AsyncSession, tenant_id: str) -> dict:
    events = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.asc())
        )
    ).scalars().all()
    rows = [ChainRow(e.seq, e.tenant_id, e.content, e.prev_hash, e.hash) for e in events]
    return verify_rows(rows)
