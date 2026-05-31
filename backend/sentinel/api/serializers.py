"""Plain-dict serializers for API responses (keeps routes terse)."""

from __future__ import annotations

from sentinel.db.models import Action, Alert, AuditEvent, Investigation, TriageResult


def triage_brief(t: TriageResult | None) -> dict | None:
    if t is None:
        return None
    return {
        "severity": t.severity,
        "confidence": t.confidence,
        "priority": t.priority,
        "severity_label": t.severity_label,
        "decision": t.decision,
    }


def alert_brief(a: Alert) -> dict:
    return {
        "id": a.id,
        "source": a.source,
        "source_event_type": a.source_event_type,
        "ts": a.ts.isoformat() if a.ts else None,
        "severity_hint": a.severity_hint,
        "title": a.title,
        "status": a.status,
        "actor_identity": a.actor_identity,
        "source_ip": a.source_ip,
        "scenario": a.scenario,
        "triage": triage_brief(a.triage) if "triage" in a.__dict__ else None,
    }


def alert_full(a: Alert, investigation_id: str | None = None) -> dict:
    d = alert_brief(a)
    d.update(
        {
            "tenant_id": a.tenant_id,
            "asset": a.asset,
            "process": a.process,
            "package": a.package,
            "repository": a.repository,
            "cloud_resource": a.cloud_resource,
            "raw": a.raw,
            "investigation_id": investigation_id,
        }
    )
    if a.triage is not None:
        d["triage"] = {
            **triage_brief(a.triage),  # type: ignore[dict-item]
            "reasoning": a.triage.reasoning,
            "evidence": a.triage.evidence,
            "model": a.triage.model,
        }
    return d


def audit_event(e: AuditEvent) -> dict:
    return {
        "id": e.id,
        "seq": e.seq,
        "ts": e.content.get("ts"),
        "actor": e.content.get("actor"),
        "event_type": e.content.get("event_type"),
        "data": e.content.get("data", {}),
        "prev_hash": e.prev_hash,
        "hash": e.hash,
    }


def investigation_full(inv: Investigation) -> dict:
    return {
        "id": inv.id,
        "tenant_id": inv.tenant_id,
        "trigger_alert_id": inv.trigger_alert_id,
        "status": inv.status,
        "summary": inv.summary,
        "scores": inv.scores,
        "kill_chain": inv.kill_chain,
        "data_provenance": inv.data_provenance,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
    }


def agent_finding(f) -> dict:
    return {
        "agent": f.agent,
        "summary": (f.findings or {}).get("summary", ""),
        "findings": f.findings,
        "iocs": f.iocs,
        "tokens": f.tokens,
        "latency_ms": f.latency_ms,
    }


def action_brief(a: Action) -> dict:
    return {
        "id": a.id,
        "investigation_id": a.investigation_id,
        "type": a.type,
        "params": a.params,
        "rationale": a.rationale,
        "status": a.status,
        "requires_second_confirm": a.requires_second_confirm,
        "dry_run": a.dry_run,
        "result": a.result,
    }
