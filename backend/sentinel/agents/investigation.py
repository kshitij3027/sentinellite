"""Parallel multi-agent investigation (R5). When an alert escalates it is
attached to an incident investigation; three specialized agents — Identity,
Endpoint, SupplyChain — run concurrently via asyncio.gather, each querying the
graph for its domain and returning findings + IOCs."""

from __future__ import annotations

import asyncio
import time

from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.agents.llm import run_agent
from sentinel.audit.chain import append_event
from sentinel.config import settings
from sentinel.db.base import SessionLocal
from sentinel.db.models import (
    INV_RUNNING,
    AgentFinding,
    Alert,
    Investigation,
)
from sentinel.graph.queries import correlated_alerts
from sentinel.logging import get_logger
from sentinel.metrics import AGENT_RUNS
from sentinel.mitre import classify
from sentinel.queue import mark_investigation_dirty, publish_trace
from sentinel.types import new_id

log = get_logger("investigation")


class DomainOut(BaseModel):
    summary: str = Field(description="2-3 sentence domain analysis")
    iocs: list[str] = Field(default_factory=list, description="indicators of compromise observed")


# ---------------------------------------------------------------- helpers

async def _load_members(session: AsyncSession, inv_id: str) -> list[Alert]:
    rows = (
        await session.execute(
            select(Alert).where(Alert.investigation_id == inv_id).order_by(Alert.ts.asc())
        )
    ).scalars().all()
    return list(rows)


def _iocs_of(alerts: list[Alert]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for a in alerts:
        for typ, val in (
            ("ip", a.source_ip),
            ("package", a.package),
            ("process", a.process),
            ("cloud_resource", a.cloud_resource),
            ("identity", a.actor_identity),
        ):
            if val and (typ, val) not in seen:
                seen.add((typ, val))
                out.append({"type": typ, "value": val})
    return out


def _facts(alerts: list[Alert]) -> dict:
    return {
        "alert_ids": [a.id for a in alerts],
        "events": [f"{a.source}:{a.source_event_type} ({a.title})" for a in alerts[:12]],
        "techniques": sorted({t for a in alerts for t in classify(a)}),
        "iocs": _iocs_of(alerts),
    }


async def _run_domain(name: str, instructions: str, alerts: list[Alert], tenant: str) -> dict:
    started = time.monotonic()
    facts = _facts(alerts)
    iocs = facts["iocs"]
    summary = ""
    tokens = 0
    if alerts:
        prompt = (
            f"You are the {name} investigation agent. Analyze these correlated alerts in your "
            f"domain and summarize what the adversary did, then list IOCs.\n"
            f"Events: {facts['events']}\nTechniques: {facts['techniques']}\nIOCs: {iocs}"
        )
        out, tokens = await run_agent(
            output_type=DomainOut, instructions=instructions, prompt=prompt,
            name=f"agent:{name}", tenant_id=tenant, max_tokens=400,
        )
        if out is not None:
            summary = out.summary
        else:
            summary = (
                f"{name} agent (heuristic): {len(alerts)} alert(s), techniques "
                f"{facts['techniques']}, {len(iocs)} IOC(s)."
            )
    else:
        summary = f"{name} agent: no domain-relevant alerts."
        AGENT_RUNS.labels(agent=f"agent:{name}", outcome="empty", tenant=tenant).inc()

    return {
        "agent": name,
        "summary": summary,
        "findings": facts,
        "iocs": iocs,
        "tokens": tokens,
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


_IDENTITY_INSTR = "You analyze identity & access telemetry (logins, role assumption, cloud creds). Flag stolen credentials, suspicious source IPs, and privilege escalation."
_ENDPOINT_INSTR = "You analyze endpoint/runtime telemetry (processes, containers, file access). Flag malicious process execution and credential theft on hosts/runners."
_SUPPLY_INSTR = "You analyze software supply-chain telemetry (repos, packages, CI). Flag compromised dependencies, malicious postinstall scripts, and vulnerable packages."


async def run_domain_agents(tenant_id: str, inv_id: str) -> list[dict]:
    async with SessionLocal() as session:
        members = await _load_members(session, inv_id)

    identity = [a for a in members if a.source in ("aws_cloudtrail", "okta_system_log") or a.actor_identity or a.source_ip]
    endpoint = [a for a in members if a.source == "falco" or a.process]
    supply = [a for a in members if a.source == "github" or a.package]

    await publish_trace(inv_id, {"type": "agents.start", "agents": ["identity", "endpoint", "supplychain"]})

    # R5: the three domain agents run CONCURRENTLY.
    results = await asyncio.gather(
        _run_domain("identity", _IDENTITY_INSTR, identity, tenant_id),
        _run_domain("endpoint", _ENDPOINT_INSTR, endpoint, tenant_id),
        _run_domain("supplychain", _SUPPLY_INSTR, supply, tenant_id),
    )

    async with SessionLocal() as session:
        # Replace prior findings so the table always holds the latest 3.
        await session.execute(delete(AgentFinding).where(AgentFinding.investigation_id == inv_id))
        for r in results:
            session.add(AgentFinding(
                id=new_id("fnd"), investigation_id=inv_id, tenant_id=tenant_id,
                agent=r["agent"], findings={"summary": r["summary"], **r["findings"]},
                iocs=r["iocs"], tokens=r["tokens"], latency_ms=r["latency_ms"],
            ))
        await session.commit()

    for r in results:
        await publish_trace(inv_id, {"type": "agent.done", "agent": r["agent"], "summary": r["summary"]})
    log.info("investigation.domain_agents_done", inv_id=inv_id,
             agents=[r["agent"] for r in results], total_tokens=sum(r["tokens"] for r in results))
    return results


# ---------------------------------------------------------------- orchestration

async def get_or_create_investigation(session: AsyncSession, alert: Alert) -> tuple[Investigation, bool]:
    """Attach to an open incident sharing this alert's scenario or a graph
    correlation; otherwise open a new investigation."""
    candidates = (
        await session.execute(
            select(Investigation)
            .where(Investigation.tenant_id == alert.tenant_id, Investigation.status == INV_RUNNING)
            .order_by(Investigation.created_at.desc())
            .limit(20)
        )
    ).scalars().all()

    # 1) same replay scenario -> same incident (keeps the demo's chain unified)
    if alert.scenario:
        for inv in candidates:
            if (inv.data_provenance or {}).get("scenario") == alert.scenario:
                return inv, False

    # 2) graph-correlated with an existing member/trigger
    if candidates:
        corr = await correlated_alerts(alert.tenant_id, alert.id)
        corr_ids = {c["id"] for c in corr}
        if corr_ids:
            for inv in candidates:
                members = (
                    await session.execute(
                        select(Alert.id).where(Alert.investigation_id == inv.id)
                    )
                ).scalars().all()
                if inv.trigger_alert_id in corr_ids or corr_ids.intersection(members):
                    return inv, False

    inv = Investigation(
        id=new_id("inv"),
        tenant_id=alert.tenant_id,
        trigger_alert_id=alert.id,
        status=INV_RUNNING,
        data_provenance={"scenario": alert.scenario, "sources": []},
    )
    session.add(inv)
    await session.flush()
    return inv, True


async def attach_alert(tenant_id: str, alert_id: str) -> str | None:
    """Fast, inline: attach an escalated alert to its incident investigation and
    mark it dirty. The heavy agent run is debounced (see run_investigation)."""
    async with SessionLocal() as session:
        alert = (
            await session.execute(
                select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            )
        ).scalar_one_or_none()
        if alert is None:
            return None
        inv, created = await get_or_create_investigation(session, alert)
        alert.investigation_id = inv.id
        await append_event(
            session, tenant_id=tenant_id, actor="agent:investigation",
            event_type="investigation.created" if created else "investigation.alert_attached",
            data={"investigation_id": inv.id, "alert_id": alert_id, "trigger": inv.trigger_alert_id},
        )
        await session.commit()
        inv_id = inv.id

    if created:
        await publish_trace(inv_id, {"type": "investigation.created", "trigger": alert_id})
    await mark_investigation_dirty(tenant_id, inv_id, settings.investigation_debounce_s)
    return inv_id


async def run_investigation(tenant_id: str, inv_id: str) -> None:
    """Heavy: parallel domain agents (R5) + correlation (R6). Findings and the
    kill-chain reflect all currently-attached alerts. Debounced by the worker."""
    await run_domain_agents(tenant_id, inv_id)
    from sentinel.agents.correlator import run_correlator

    await run_correlator(tenant_id, inv_id)


async def investigate_escalation(tenant_id: str, alert_id: str) -> str | None:
    """Synchronous attach + run (used by tests / direct calls)."""
    inv_id = await attach_alert(tenant_id, alert_id)
    if inv_id:
        await run_investigation(tenant_id, inv_id)
    return inv_id
