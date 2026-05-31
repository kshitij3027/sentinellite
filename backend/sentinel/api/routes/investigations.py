"""GET /investigations and GET /investigations/{id} (R6/R10)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.api.deps import tenant_id
from sentinel.api.serializers import (
    action_brief,
    agent_finding,
    alert_brief,
    investigation_full,
)
from sentinel.db.base import get_session
from sentinel.db.models import Action, AgentFinding, Alert, Investigation

router = APIRouter(tags=["investigations"])


@router.get("/investigations")
async def list_investigations(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    q = select(Investigation).where(Investigation.tenant_id == tenant)
    if status:
        q = q.where(Investigation.status == status)
    q = q.order_by(Investigation.created_at.desc()).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    out = []
    for inv in rows:
        d = investigation_full(inv)
        d["stage_count"] = len(inv.kill_chain or [])
        out.append(d)
    return {"count": len(out), "investigations": out}


@router.get("/investigations/{inv_id}")
async def get_investigation(
    inv_id: str,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    inv = (
        await session.execute(
            select(Investigation).where(Investigation.id == inv_id, Investigation.tenant_id == tenant)
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, f"investigation '{inv_id}' not found")

    members = (
        await session.execute(
            select(Alert).where(Alert.investigation_id == inv_id).order_by(Alert.ts.asc())
        )
    ).scalars().all()
    findings = (
        await session.execute(select(AgentFinding).where(AgentFinding.investigation_id == inv_id))
    ).scalars().all()
    actions = (
        await session.execute(select(Action).where(Action.investigation_id == inv_id))
    ).scalars().all()

    d = investigation_full(inv)
    d["alerts"] = [alert_brief(a) for a in members]
    d["findings"] = [agent_finding(f) for f in findings]
    d["actions"] = [action_brief(a) for a in actions]
    return d
