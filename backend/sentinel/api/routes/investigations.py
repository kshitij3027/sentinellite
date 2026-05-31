"""GET /investigations and GET /investigations/{id} (R6/R10)."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from sentinel.api.deps import tenant_id
from sentinel.api.serializers import (
    action_brief,
    agent_finding,
    alert_brief,
    investigation_full,
)
from sentinel.db.base import get_session
from sentinel.db.models import Action, AgentFinding, Alert, Investigation
from sentinel.graph.queries import alert_subgraph
from sentinel.queue import get_redis, trace_channel

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


@router.get("/investigations/{inv_id}/graph")
async def investigation_graph(
    inv_id: str,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
) -> dict:
    """Nodes + edges for the attack-graph view (react-force-graph-2d)."""
    ids = list((
        await session.execute(
            select(Alert.id).where(Alert.investigation_id == inv_id, Alert.tenant_id == tenant)
        )
    ).scalars().all())
    if not ids:
        return {"nodes": [], "edges": []}
    try:
        return await alert_subgraph(tenant, ids)
    except Exception:
        return {"nodes": [], "edges": []}


@router.get("/investigations/{inv_id}/stream")
async def investigation_stream(inv_id: str, request: Request) -> EventSourceResponse:
    """Server-Sent Events: live agent-trace deltas for an investigation (R10)."""

    async def gen():
        pubsub = get_redis().pubsub()
        await pubsub.subscribe(trace_channel(inv_id))
        try:
            yield {"event": "hello", "data": json.dumps({"investigation_id": inv_id})}
            while not await request.is_disconnected():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    yield {"event": "trace", "data": msg["data"]}
                else:
                    yield {"event": "ping", "data": "{}"}
                await asyncio.sleep(0)
        finally:
            await pubsub.unsubscribe(trace_channel(inv_id))
            await pubsub.aclose()

    return EventSourceResponse(gen())
