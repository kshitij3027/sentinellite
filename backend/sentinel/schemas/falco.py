"""Falco JSON alert validator + normalizer."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinel.schemas.common import NormalizedAlert, Source, utcnow
from sentinel.types import Severity

_PRIORITY_MAP: dict[str, Severity] = {
    "DEBUG": "low",
    "INFORMATIONAL": "low",
    "NOTICE": "low",
    "WARNING": "medium",
    "ERROR": "high",
    "CRITICAL": "critical",
    "ALERT": "critical",
    "EMERGENCY": "critical",
}


class FalcoAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    time: str | None = None
    rule: str | None = None
    priority: str | None = None
    source: str | None = None
    output: str | None = None
    output_fields: dict[str, Any] | None = None
    tags: list[str] | None = None
    hostname: str | None = None


def _parse_ts(value: str | None) -> datetime:
    if value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return utcnow()


def to_normalized(payload: dict[str, Any], event_name: str | None = None) -> NormalizedAlert:
    ev = FalcoAlert.model_validate(payload)
    fields = ev.output_fields or {}

    asset = (
        fields.get("k8s.pod.name")
        or fields.get("container.name")
        or (fields.get("container.id") if fields.get("container.id") != "host" else None)
        or ev.hostname
    )
    image = fields.get("container.image.repository")
    cid = fields.get("container.id")
    cloud_resource = f"{image}@{cid}" if image and cid else image

    return NormalizedAlert(
        tenant_id="default",
        source=Source.falco,
        source_event_type=ev.rule or "falco.rule",
        ts=_parse_ts(ev.time),
        severity_hint=_PRIORITY_MAP.get((ev.priority or "NOTICE").upper(), "medium"),
        title=f"Falco: {ev.rule or 'rule'}",
        actor_identity=fields.get("user.name"),
        asset=asset,
        process=fields.get("proc.cmdline") or fields.get("proc.name"),
        cloud_resource=cloud_resource,
        raw=payload,
    )
