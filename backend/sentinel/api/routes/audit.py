"""GET /audit (chain) and GET /audit/verify (integrity check) — R9."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.api.deps import tenant_id
from sentinel.api.serializers import audit_event
from sentinel.audit.chain import get_chain, verify_chain
from sentinel.db.base import get_session
from sentinel.metrics import HASHCHAIN_BREAKS

router = APIRouter(tags=["audit"])


@router.get("/audit")
async def audit_list(
    limit: int = Query(default=200, le=1000),
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    events = await get_chain(session, tenant, limit=limit)
    return {"count": len(events), "events": [audit_event(e) for e in events]}


@router.get("/audit/verify")
async def audit_verify(
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    result = await verify_chain(session, tenant)
    # OB1: surface broken links as a live metric.
    breaks = 0 if result["ok"] else 1
    HASHCHAIN_BREAKS.labels(tenant=tenant).set(breaks)
    return result
