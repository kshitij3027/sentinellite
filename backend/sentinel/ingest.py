"""Ingestion service: validate → persist (Postgres) → hydrate (Neo4j) →
audit (hash chain) → enqueue (Redis) → metrics. Used by the API route and the
replay CLI alike."""

from __future__ import annotations

import hashlib

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.audit.chain import append_event
from sentinel.db.models import ALERT_NEW, Alert
from sentinel.graph.hydrate import hydrate_alert
from sentinel.logging import get_logger
from sentinel.metrics import ALERTS_INGESTED
from sentinel.queue import enqueue_alert
from sentinel.schemas import normalize
from sentinel.schemas.common import NormalizedAlert

log = get_logger("ingest")


def dedup_key(alert: NormalizedAlert) -> str:
    material = f"{alert.tenant_id}|{alert.dedup_text()}"
    return hashlib.sha256(material.encode()).hexdigest()[:32]


async def persist_normalized(
    session: AsyncSession,
    norm: NormalizedAlert,
    *,
    scenario: str | None = None,
    t_offset_s: int | None = None,
    enqueue: bool = True,
    hydrate: bool = True,
) -> Alert:
    alert = Alert(
        id=norm.id,
        tenant_id=norm.tenant_id,
        source=norm.source,
        source_event_type=norm.source_event_type,
        ts=norm.ts,
        severity_hint=norm.severity_hint,
        title=norm.title,
        actor_identity=norm.actor_identity,
        source_ip=norm.source_ip,
        asset=norm.asset,
        process=norm.process,
        package=norm.package,
        repository=norm.repository,
        cloud_resource=norm.cloud_resource,
        status=ALERT_NEW,
        dedup_key=dedup_key(norm),
        raw=norm.raw,
        scenario=scenario,
        t_offset_s=t_offset_s,
    )
    session.add(alert)
    await append_event(
        session,
        tenant_id=norm.tenant_id,
        actor="system",
        event_type="alert.ingested",
        data={
            "alert_id": norm.id,
            "source": norm.source,
            "event_type": norm.source_event_type,
            "severity_hint": norm.severity_hint,
        },
    )
    await session.commit()

    if hydrate:
        try:
            await hydrate_alert(norm)
        except Exception as exc:  # graph is a separate store; never lose the alert
            log.error("graph.hydrate_failed", alert_id=norm.id, error=str(exc))

    if enqueue:
        await enqueue_alert(norm.tenant_id, norm.id)

    ALERTS_INGESTED.labels(source=norm.source, tenant=norm.tenant_id).inc()
    log.info("alert.ingested", alert_id=norm.id, source=norm.source,
             event_type=norm.source_event_type, severity_hint=norm.severity_hint)
    return alert


async def ingest_alert(
    session: AsyncSession,
    source: str,
    payload: dict,
    event_name: str | None = None,
    tenant_id: str = "default",
    scenario: str | None = None,
    t_offset_s: int | None = None,
) -> Alert:
    norm = normalize(source, payload, event_name)
    norm.tenant_id = tenant_id
    return await persist_normalized(session, norm, scenario=scenario, t_offset_s=t_offset_s)
