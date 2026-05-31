"""GET /alerts, GET /alerts/{id}."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.api.deps import tenant_id
from sentinel.api.serializers import alert_brief, alert_full
from sentinel.db.base import get_session
from sentinel.db.models import Alert, Investigation

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
async def list_alerts(
    status: str | None = Query(default=None),
    source: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    q = select(Alert).options(selectinload(Alert.triage)).where(Alert.tenant_id == tenant)
    if status:
        q = q.where(Alert.status == status)
    if source:
        q = q.where(Alert.source == source)
    q = q.order_by(Alert.created_at.desc()).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    return {"count": len(rows), "alerts": [alert_brief(a) for a in rows]}


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    a = (
        await session.execute(
            select(Alert)
            .options(selectinload(Alert.triage))
            .where(Alert.id == alert_id, Alert.tenant_id == tenant)
        )
    ).scalar_one_or_none()
    if a is None:
        raise HTTPException(404, f"alert '{alert_id}' not found")
    inv_id = (
        await session.execute(
            select(Investigation.id).where(Investigation.trigger_alert_id == alert_id)
        )
    ).scalar_one_or_none()
    return alert_full(a, investigation_id=inv_id)
