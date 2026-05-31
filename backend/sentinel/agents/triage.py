"""TriageAgent (R3/R4): score each alert on Severity / Confidence / Priority
(0-100) with chain-of-thought reasoning + evidence, then auto-close or escalate.

Two-stage for speed + reliability: a deterministic indicator/noise pass always
produces a safe score and decision; the Pydantic-AI agent (Ollama) refines the
scores and writes the reasoning for anything that isn't obvious noise."""

from __future__ import annotations

import time

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.agents.llm import run_agent
from sentinel.audit.chain import append_event
from sentinel.config import settings
from sentinel.db.models import ALERT_AUTO_CLOSED, ALERT_ESCALATED, Alert, TriageResult
from sentinel.detection.indicators import Signal, evaluate
from sentinel.logging import get_logger
from sentinel.metrics import ALERTS_AUTOCLOSED, ALERTS_ESCALATED, TRIAGE_LATENCY
from sentinel.types import SEVERITY_RANK, new_id, sev_rank

log = get_logger("triage")

_BASE_SEV = {"info": 10, "low": 30, "medium": 55, "high": 78, "critical": 92}


class TriageLLMOut(BaseModel):
    reasoning: str = Field(description="2-4 sentence chain-of-thought analysis")
    severity: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    priority: int = Field(ge=0, le=100)
    evidence: list[str] = Field(default_factory=list, description="short evidence citations")


def _label_from_int(score: int) -> str:
    if score < 20:
        return "info"
    if score < 40:
        return "low"
    if score < 65:
        return "medium"
    if score < 85:
        return "high"
    return "critical"


def deterministic_scores(alert, signal: Signal) -> dict:
    base = _BASE_SEV.get(alert.severity_hint, 10)
    if signal.threat:
        severity = min(100, max(base, 60) + min(35, signal.weight // 2))
    elif signal.obvious_noise:
        severity = min(base, 30)
    else:
        severity = base

    label = _label_from_int(severity)
    if signal.threat and sev_rank(label) < SEVERITY_RANK["medium"]:
        label = "medium"
    if signal.obvious_noise and sev_rank(label) > SEVERITY_RANK["low"]:
        label = "low"

    if signal.obvious_noise:
        confidence = 95
    elif signal.threat:
        confidence = 90 if signal.weight >= 40 else 83
    else:
        confidence = 65

    priority = min(100, round(0.6 * severity + 0.4 * confidence) + (5 if signal.threat else 0))
    return {"severity": severity, "confidence": confidence, "priority": priority, "severity_label": label}


def _decision(severity_label: str, confidence: int, signal: Signal) -> str:
    if signal.threat:
        return "escalate"  # a high-fidelity indicator always escalates
    auto = (confidence / 100.0 >= settings.triage_autoclose_conf) and settings.sev_at_or_below(
        severity_label, settings.triage_autoclose_max_sev
    )
    return "auto_close" if auto else "escalate"


def _prompt(alert, signal: Signal, det: dict) -> str:
    return (
        f"Alert to triage:\n"
        f"- source: {alert.source}\n"
        f"- event: {alert.source_event_type}\n"
        f"- title: {alert.title}\n"
        f"- native severity hint: {alert.severity_hint}\n"
        f"- actor: {alert.actor_identity}\n"
        f"- source_ip: {alert.source_ip}\n"
        f"- asset: {alert.asset}\n"
        f"- process: {alert.process}\n"
        f"- package: {alert.package}\n"
        f"- cloud_resource: {alert.cloud_resource}\n"
        f"\nDetected indicators: {signal.matched or ['none']}\n"
        f"Suspected MITRE techniques: {signal.techniques or ['none']}\n"
        f"Heuristic baseline scores: {det}\n\n"
        f"Score Severity, Confidence, Priority (0-100), explain your reasoning, and cite evidence. "
        f"If high-fidelity threat indicators are present, do not under-score."
    )


_INSTRUCTIONS = (
    "You are a senior SOC triage analyst for an autonomous SOC. You receive one security alert "
    "with pre-computed threat indicators and must score it on three axes (0-100): Severity (impact), "
    "Confidence (how sure it is a true positive), and Priority (how urgently a human should look). "
    "Give concise chain-of-thought reasoning and cite concrete evidence."
)


async def triage_alert(session: AsyncSession, alert: Alert, *, use_llm: bool | None = None) -> TriageResult:
    started = time.monotonic()
    signal = evaluate(alert)
    det = deterministic_scores(alert, signal)

    # Decide whether to spend an LLM call.
    if use_llm is None:
        use_llm = settings.triage_llm_all or not signal.obvious_noise

    reasoning = ""
    evidence = list(signal.matched)
    model = "heuristic"
    tokens = 0
    scores = det

    if use_llm:
        out, tokens = await run_agent(
            output_type=TriageLLMOut,
            instructions=_INSTRUCTIONS,
            prompt=_prompt(alert, signal, det),
            name="triage",
            tenant_id=alert.tenant_id,
            max_tokens=600,
        )
        if out is not None:
            # Reconcile: never let the model under-call a known threat.
            sev = max(out.severity, det["severity"]) if signal.threat else out.severity
            label = _label_from_int(sev)
            if signal.threat and sev_rank(label) < SEVERITY_RANK["medium"]:
                label = "medium"
            scores = {
                "severity": sev,
                "confidence": out.confidence,
                "priority": out.priority or det["priority"],
                "severity_label": label,
            }
            reasoning = out.reasoning
            evidence = list(dict.fromkeys([*out.evidence, *signal.matched]))
            model = settings.llm_model
        else:
            reasoning = _fallback_reasoning(alert, signal, det)
    else:
        reasoning = _fallback_reasoning(alert, signal, det)

    decision = _decision(scores["severity_label"], scores["confidence"], signal)

    triage = TriageResult(
        id=new_id("trg"),
        alert_id=alert.id,
        tenant_id=alert.tenant_id,
        severity=scores["severity"],
        confidence=scores["confidence"],
        priority=scores["priority"],
        severity_label=scores["severity_label"],
        decision=decision,
        reasoning=reasoning,
        evidence=evidence,
        model=model,
        tokens=tokens,
    )
    session.add(triage)
    alert.status = ALERT_AUTO_CLOSED if decision == "auto_close" else ALERT_ESCALATED

    await append_event(
        session,
        tenant_id=alert.tenant_id,
        actor="agent:triage",
        event_type="alert.triaged",
        data={
            "alert_id": alert.id,
            "decision": decision,
            "scores": {k: scores[k] for k in ("severity", "confidence", "priority")},
            "severity_label": scores["severity_label"],
            "model": model,
            "indicators": signal.matched,
        },
    )
    await session.commit()

    TRIAGE_LATENCY.labels(tenant=alert.tenant_id).observe(time.monotonic() - started)
    if decision == "auto_close":
        ALERTS_AUTOCLOSED.labels(tenant=alert.tenant_id).inc()
    else:
        ALERTS_ESCALATED.labels(tenant=alert.tenant_id).inc()
    log.info("alert.triaged", alert_id=alert.id, decision=decision, model=model,
             severity=scores["severity"], confidence=scores["confidence"])
    return triage


def _fallback_reasoning(alert, signal: Signal, det: dict) -> str:
    if signal.obvious_noise:
        return (
            f"Auto-classified as benign noise: {alert.source} {alert.source_event_type} with no "
            f"threat indicators (severity {det['severity_label']}, confidence {det['confidence']})."
        )
    if signal.matched:
        return (
            f"Heuristic escalation: matched indicators {signal.matched} mapping to MITRE "
            f"{signal.techniques}. Scored severity {det['severity']} / confidence {det['confidence']}."
        )
    return (
        f"Ambiguous {alert.source} {alert.source_event_type}; no decisive indicators. "
        f"Conservatively scored {det['severity']} severity for analyst review."
    )
