"""POST /ingest/{source} — accept a native-schema alert (R1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.api.deps import tenant_id
from sentinel.db.base import get_session
from sentinel.ingest import ingest_alert
from sentinel.schemas import SOURCES

router = APIRouter(tags=["ingest"])


@router.post("/ingest/{source}")
async def ingest(
    source: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    tenant: str = Depends(tenant_id),
    x_scenario: str | None = Header(default=None, alias="X-Scenario"),
    x_replay_offset: int | None = Header(default=None, alias="X-Replay-Offset"),
) -> dict:
    if source not in SOURCES:
        raise HTTPException(404, f"unknown source '{source}'; expected one of {list(SOURCES)}")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "request body must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(400, "request body must be a JSON object")

    event_name = request.headers.get("X-GitHub-Event")  # github event name lives in the header
    try:
        alert = await ingest_alert(
            session, source, payload, event_name=event_name, tenant_id=tenant,
            scenario=x_scenario, t_offset_s=x_replay_offset,
        )
    except ValidationError as exc:
        raise HTTPException(422, detail=exc.errors())

    return {
        "alert_id": alert.id,
        "status": alert.status,
        "source": alert.source,
        "source_event_type": alert.source_event_type,
        "severity_hint": alert.severity_hint,
    }
