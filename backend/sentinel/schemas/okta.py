"""Okta System Log (LogEvent) validator + normalizer."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinel.schemas.common import NormalizedAlert, Source, utcnow
from sentinel.types import Severity, max_sev

_SEV_MAP: dict[str, Severity] = {"DEBUG": "info", "INFO": "info", "WARN": "medium", "ERROR": "high"}


class OktaActor(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    type: str | None = None
    alternateId: str | None = None
    displayName: str | None = None


class OktaOutcome(BaseModel):
    model_config = ConfigDict(extra="allow")
    result: str | None = None
    reason: str | None = None


class OktaLogEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    uuid: str | None = None
    published: str | None = None
    eventType: str | None = None
    severity: str | None = None
    displayMessage: str | None = None
    actor: OktaActor | None = None
    client: dict[str, Any] | None = None
    outcome: OktaOutcome | None = None
    target: list[dict[str, Any]] | None = None
    authenticationContext: dict[str, Any] | None = None
    securityContext: dict[str, Any] | None = None
    request: dict[str, Any] | None = None


def _parse_ts(value: str | None) -> datetime:
    if value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return utcnow()


def _source_ip(ev: OktaLogEvent) -> str | None:
    ip = (ev.client or {}).get("ipAddress")
    if ip:
        return ip
    chain = (ev.request or {}).get("ipChain") or []
    return chain[0].get("ip") if chain else None


def _severity(ev: OktaLogEvent) -> Severity:
    base = _SEV_MAP.get((ev.severity or "INFO").upper(), "info")
    if ev.outcome and (ev.outcome.result or "").upper() == "FAILURE":
        base = max_sev(base, "medium")
    if (ev.securityContext or {}).get("isProxy") is True:
        base = max_sev(base, "medium")
    return base  # type: ignore[return-value]


def to_normalized(payload: dict[str, Any], event_name: str | None = None) -> NormalizedAlert:
    ev = OktaLogEvent.model_validate(payload)
    actor = (ev.actor.alternateId if ev.actor else None) or (
        ev.actor.displayName if ev.actor else None
    )
    target_app = None
    for t in ev.target or []:
        if t.get("type") == "AppInstance":
            target_app = t.get("displayName") or t.get("alternateId")
            break

    geo = (ev.client or {}).get("geographicalContext") or {}
    loc = ", ".join(p for p in [geo.get("city"), geo.get("country")] if p)
    result = (ev.outcome.result if ev.outcome else None) or ""
    title = f"Okta {ev.eventType or 'event'} {result}".strip()
    if loc:
        title += f" from {loc}"

    return NormalizedAlert(
        tenant_id="default",
        source=Source.okta_system_log,
        source_event_type=ev.eventType or "okta.event",
        ts=_parse_ts(ev.published),
        severity_hint=_severity(ev),
        title=title,
        actor_identity=actor,
        source_ip=_source_ip(ev),
        cloud_resource=target_app,
        raw=payload,
    )
