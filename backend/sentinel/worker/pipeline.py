"""The alert-processing pipeline: triage -> (auto-close | escalate ->
investigate -> correlate -> stage actions). Investigation wiring lands with the
investigation agents; this stage owns triage + escalation dispatch."""

from __future__ import annotations

from sqlalchemy import select

from sentinel.agents.triage import triage_alert
from sentinel.db.base import SessionLocal
from sentinel.db.models import ALERT_NEW, Alert
from sentinel.logging import get_logger

log = get_logger("pipeline")


async def process_alert(tenant_id: str, alert_id: str) -> None:
    async with SessionLocal() as session:
        alert = (
            await session.execute(
                select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            )
        ).scalar_one_or_none()
        if alert is None:
            log.warning("pipeline.alert_missing", alert_id=alert_id)
            return
        if alert.status != ALERT_NEW:
            return  # already processed (idempotent)

        triage = await triage_alert(session, alert)

    if triage.decision == "escalate":
        # Fast: attach to the incident + mark dirty. The heavy domain-agent +
        # correlator run is debounced by the worker's investigation loop (R5/R6).
        from sentinel.agents.investigation import attach_alert

        await attach_alert(tenant_id, alert_id)
