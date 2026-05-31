"""CorrelatorAgent (R6): merge the domain agents' work, walk the graph, and
emit a single kill-chain timeline with a MITRE ATT&CK technique ID and a
graph-path (entity) citation on each stage."""

from __future__ import annotations

import time

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.agents.llm import run_agent
from sentinel.audit.chain import append_event
from sentinel.db.base import SessionLocal
from sentinel.db.models import INV_RUNNING, Alert, Investigation, TriageResult
from sentinel.logging import get_logger
from sentinel.metrics import INVESTIGATION_LATENCY
from sentinel.mitre import CATALOG, STAGE_ORDER, classify
from sentinel.queue import publish_trace

log = get_logger("correlator")


class CorrelatorOut(BaseModel):
    headline: str = Field(description="one-line incident headline")
    summary: str = Field(description="3-5 sentence narrative of the kill chain")


def _offset(alert: Alert, first_ts) -> int:
    if alert.t_offset_s is not None:
        return alert.t_offset_s
    try:
        return max(0, int((alert.ts - first_ts).total_seconds()))
    except Exception:
        return 0


def build_kill_chain(members: list[Alert]) -> list[dict]:
    """One ordered step per distinct MITRE technique across member alerts."""
    if not members:
        return []
    first_ts = members[0].ts
    groups: dict[str, list[Alert]] = {}
    for m in members:
        tids = classify(m)
        if tids:
            groups.setdefault(tids[0], []).append(m)

    steps: list[dict] = []
    for tid, alerts in groups.items():
        tech = CATALOG[tid]
        alerts_sorted = sorted(alerts, key=lambda a: _offset(a, first_ts))
        earliest = alerts_sorted[0]
        entities: list[str] = []
        for a in alerts_sorted:
            for v in a.entities().values():
                if v not in entities:
                    entities.append(v)
        steps.append({
            "t_offset_s": _offset(earliest, first_ts),
            "stage": tech.stage,
            "mitre": tid,
            "mitre_name": tech.name,
            "evidence": [a.id for a in alerts_sorted],
            "entities": entities[:8],
            "summary": f"{tech.stage} ({tid}): {earliest.title}",
        })

    steps.sort(key=lambda s: (s["t_offset_s"],
                              STAGE_ORDER.index(s["stage"]) if s["stage"] in STAGE_ORDER else 99))
    return steps


def _aggregate_scores(triage_rows: list[TriageResult]) -> dict:
    if not triage_rows:
        return {"severity": 0, "confidence": 0, "priority": 0}
    return {
        "severity": max(t.severity for t in triage_rows),
        "confidence": max(t.confidence for t in triage_rows),
        "priority": max(t.priority for t in triage_rows),
    }


def _datasets(members: list[Alert]) -> list[str]:
    ds = set()
    for m in members:
        d = (m.raw or {}).get("_dataset") if isinstance(m.raw, dict) else None
        if d:
            ds.add(d)
    return sorted(ds)


async def run_correlator(tenant_id: str, inv_id: str) -> None:
    started = time.monotonic()
    async with SessionLocal() as session:
        inv = (
            await session.execute(select(Investigation).where(Investigation.id == inv_id))
        ).scalar_one_or_none()
        if inv is None:
            return
        members = (
            await session.execute(
                select(Alert).where(Alert.investigation_id == inv_id).order_by(Alert.ts.asc())
            )
        ).scalars().all()
        members = list(members)
        triage_rows = list((
            await session.execute(
                select(TriageResult).where(TriageResult.alert_id.in_([m.id for m in members]))
            )
        ).scalars().all()) if members else []

        steps = build_kill_chain(members)
        scores = _aggregate_scores(triage_rows)

        headline = ""
        summary = ""
        if steps:
            prompt = (
                "Correlate this kill chain into one incident. Stages (time-ordered):\n"
                + "\n".join(f"  t+{s['t_offset_s']}s {s['stage']} [{s['mitre']}] {s['summary']}" for s in steps)
                + f"\nScores: {scores}. Write a one-line headline and a 3-5 sentence narrative."
            )
            out, _tokens = await run_agent(
                output_type=CorrelatorOut,
                instructions="You are the correlation agent in an autonomous SOC. Tell the attack story across domains, in order, citing the stages.",
                prompt=prompt, name="agent:correlator", tenant_id=tenant_id, max_tokens=400,
            )
            if out is not None:
                headline, summary = out.headline, out.summary
        if not headline:
            stages = " → ".join(dict.fromkeys(s["stage"] for s in steps)) or "no stages"
            headline = f"{len(steps)}-stage incident: {stages}"
        if not summary:
            summary = f"Correlated {len(members)} alerts into {len(steps)} kill-chain stages."

        inv.kill_chain = steps
        inv.scores = scores
        inv.summary = f"{headline} — {summary}"
        inv.data_provenance = {
            "scenario": (inv.data_provenance or {}).get("scenario"),
            "sources": sorted({m.source for m in members}),
            "datasets": _datasets(members),
        }
        inv.status = INV_RUNNING  # M3 stages actions and moves to awaiting_approval

        await append_event(
            session, tenant_id=tenant_id, actor="agent:correlator",
            event_type="investigation.correlated",
            data={"investigation_id": inv_id, "stages": len(steps),
                  "techniques": [s["mitre"] for s in steps], "scores": scores},
        )
        await session.commit()
        created_at = inv.created_at

    INVESTIGATION_LATENCY.labels(tenant=tenant_id).observe(time.monotonic() - started)
    await publish_trace(inv_id, {"type": "correlated", "headline": headline,
                                 "kill_chain": steps, "scores": scores})
    log.info("investigation.correlated", inv_id=inv_id, stages=len(steps),
             techniques=[s["mitre"] for s in steps], scores=scores)
