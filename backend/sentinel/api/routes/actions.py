"""Response actions + the human approval gate (R7/R8).

GET /actions, GET /actions/{id}, POST /actions/{id}/approve, /reject.
Irreversible actions require a second confirmation (?confirm=true)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.actions.executors import execute_action
from sentinel.api.deps import tenant_id
from sentinel.api.serializers import action_brief
from sentinel.audit.chain import append_event
from sentinel.db.base import get_session
from sentinel.db.models import (
    ACT_AWAITING_CONFIRM,
    ACT_EXECUTED,
    ACT_FAILED,
    ACT_REJECTED,
    ACT_STAGED,
    Action,
)
from sentinel.metrics import ACTIONS_EXECUTED, APPROVAL_LATENCY

router = APIRouter(tags=["actions"])

PENDING = (ACT_STAGED, ACT_AWAITING_CONFIRM)


async def _get(session: AsyncSession, action_id: str, tenant: str) -> Action:
    a = (
        await session.execute(
            select(Action).where(Action.id == action_id, Action.tenant_id == tenant)
        )
    ).scalar_one_or_none()
    if a is None:
        raise HTTPException(404, f"action '{action_id}' not found")
    return a


@router.get("/actions")
async def list_actions(
    status: str | None = Query(default=None),
    investigation_id: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    q = select(Action).where(Action.tenant_id == tenant)
    if status:
        q = q.where(Action.status == status)
    if investigation_id:
        q = q.where(Action.investigation_id == investigation_id)
    q = q.order_by(Action.staged_at.desc())
    rows = (await session.execute(q)).scalars().all()
    return {"count": len(rows), "actions": [action_brief(a) for a in rows]}


@router.get("/actions/{action_id}")
async def get_action(
    action_id: str,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    return action_brief(await _get(session, action_id, tenant))


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    confirm: bool = Query(default=False, description="second confirmation for irreversible actions"),
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    a = await _get(session, action_id, tenant)
    if a.status not in PENDING:
        raise HTTPException(409, f"action already '{a.status}'")

    # Two-tier blocklist: irreversible actions need confirm=true.
    if a.requires_second_confirm and not confirm:
        a.status = ACT_AWAITING_CONFIRM
        await append_event(session, tenant_id=tenant, actor="user", event_type="action.confirm_required",
                           data={"action_id": a.id, "type": a.type})
        await session.commit()
        return {
            **action_brief(a),
            "message": f"'{a.type}' is irreversible — re-approve with confirm=true to execute.",
        }

    result = await execute_action(a)
    now = datetime.now(timezone.utc)
    a.status = ACT_EXECUTED if result.get("ok") else ACT_FAILED
    a.result = result
    a.decided_at = now
    a.executed_at = now

    await append_event(session, tenant_id=tenant, actor="user", event_type="action.approved",
                       data={"action_id": a.id, "type": a.type, "confirm": confirm})
    await append_event(session, tenant_id=tenant, actor="system", event_type="action.executed",
                       data={"action_id": a.id, "type": a.type, "result": result})
    await session.commit()

    ACTIONS_EXECUTED.labels(type=a.type, dry_run=str(bool(a.dry_run)).lower(), tenant=tenant).inc()
    if a.staged_at:
        APPROVAL_LATENCY.labels(decision="approve", tenant=tenant).observe(
            max(0.0, (now - a.staged_at).total_seconds())
        )
    return action_brief(a)


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: str,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    a = await _get(session, action_id, tenant)
    if a.status not in PENDING:
        raise HTTPException(409, f"action already '{a.status}'")
    now = datetime.now(timezone.utc)
    a.status = ACT_REJECTED
    a.decided_at = now
    await append_event(session, tenant_id=tenant, actor="user", event_type="action.rejected",
                       data={"action_id": a.id, "type": a.type})
    await session.commit()
    if a.staged_at:
        APPROVAL_LATENCY.labels(decision="reject", tenant=tenant).observe(
            max(0.0, (now - a.staged_at).total_seconds())
        )
    return action_brief(a)
