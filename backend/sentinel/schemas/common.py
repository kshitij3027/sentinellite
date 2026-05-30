"""The normalized internal Alert. All four native sources map into this one
shape (R1). The graph hydrator (R2) and triage agent (R3) consume only this."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.types import Severity, new_id


class Source(str, Enum):
    """Path values for POST /ingest/{source} — match the PRD exactly (R1)."""

    github = "github"
    aws_cloudtrail = "aws_cloudtrail"
    okta_system_log = "okta_system_log"
    falco = "falco"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NormalizedAlert(BaseModel):
    """Source-agnostic alert. `raw` always preserves the untouched original."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: new_id("alt"))
    tenant_id: str = "default"
    source: Source
    source_event_type: str
    ts: datetime
    severity_hint: Severity = "info"
    title: str = ""

    # entity slots (None when the source has no such concept)
    actor_identity: str | None = None
    source_ip: str | None = None
    asset: str | None = None
    process: str | None = None
    package: str | None = None  # "name@version"
    repository: str | None = None  # "owner/repo"
    cloud_resource: str | None = None  # ARN / resource id

    raw: dict[str, Any] = Field(default_factory=dict)

    def dedup_text(self) -> str:
        """Stable text used for semantic dedup embeddings (pgvector) later."""
        parts = [
            str(self.source),
            self.source_event_type,
            self.actor_identity or "",
            self.source_ip or "",
            self.asset or "",
            self.process or "",
            self.package or "",
            self.repository or "",
            self.cloud_resource or "",
        ]
        return " | ".join(p for p in parts if p)

    def entities(self) -> dict[str, str]:
        """Non-null entity slots, used by the graph hydrator."""
        slots = {
            "actor_identity": self.actor_identity,
            "source_ip": self.source_ip,
            "asset": self.asset,
            "process": self.process,
            "package": self.package,
            "repository": self.repository,
            "cloud_resource": self.cloud_resource,
        }
        return {k: v for k, v in slots.items() if v}
