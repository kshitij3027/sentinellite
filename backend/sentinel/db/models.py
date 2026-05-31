"""ORM models. Every row carries tenant_id (MT1). JSONB preserves rich payloads."""

from __future__ import annotations

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinel.db.base import Base

EMBED_DIM = 768  # nomic-embed-text / all-minilm style; nullable until populated

# --- alert lifecycle states ---
ALERT_NEW = "new"
ALERT_AUTO_CLOSED = "auto_closed"
ALERT_ESCALATED = "escalated"
ALERT_TRIAGED = "triaged"

# --- investigation states ---
INV_RUNNING = "running"
INV_AWAITING_APPROVAL = "awaiting_approval"
INV_APPROVED = "approved"
INV_REJECTED = "rejected"
INV_CLOSED = "closed"

# --- action states ---
ACT_STAGED = "staged"
ACT_AWAITING_CONFIRM = "awaiting_confirm"
ACT_APPROVED = "approved"
ACT_REJECTED = "rejected"
ACT_EXECUTED = "executed"
ACT_FAILED = "failed"
ACT_EXPIRED = "expired"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    source: Mapped[str] = mapped_column(String(32))
    source_event_type: Mapped[str] = mapped_column(String(128))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity_hint: Mapped[str] = mapped_column(String(16), default="info")
    title: Mapped[str] = mapped_column(Text, default="")

    actor_identity: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset: Mapped[str | None] = mapped_column(Text, nullable=True)
    process: Mapped[str | None] = mapped_column(Text, nullable=True)
    package: Mapped[str | None] = mapped_column(Text, nullable=True)
    repository: Mapped[str | None] = mapped_column(Text, nullable=True)
    cloud_resource: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(16), default=ALERT_NEW, index=True)
    investigation_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM), nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)  # replay provenance
    t_offset_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    triage: Mapped["TriageResult | None"] = relationship(back_populates="alert", uselist=False)

    __table_args__ = (Index("ix_alerts_tenant_status", "tenant_id", "status"),)

    def entities(self) -> dict[str, str]:
        """Non-null entity slots (mirrors NormalizedAlert.entities)."""
        slots = {
            "actor_identity": self.actor_identity, "source_ip": self.source_ip,
            "asset": self.asset, "process": self.process, "package": self.package,
            "repository": self.repository, "cloud_resource": self.cloud_resource,
        }
        return {k: v for k, v in slots.items() if v}


class TriageResult(Base):
    __tablename__ = "triage_results"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")

    severity: Mapped[int] = mapped_column(Integer)  # 0-100
    confidence: Mapped[int] = mapped_column(Integer)  # 0-100
    priority: Mapped[int] = mapped_column(Integer)  # 0-100
    severity_label: Mapped[str] = mapped_column(String(16))  # info..critical
    decision: Mapped[str] = mapped_column(String(16))  # auto_close | escalate
    reasoning: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    model: Mapped[str] = mapped_column(String(64), default="")
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert: Mapped["Alert"] = relationship(back_populates="triage")


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    trigger_alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default=INV_RUNNING, index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    scores: Mapped[dict] = mapped_column(JSONB, default=dict)  # {severity,confidence,priority}
    kill_chain: Mapped[list] = mapped_column(JSONB, default=list)
    data_provenance: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    findings: Mapped[list["AgentFinding"]] = relationship(back_populates="investigation")
    actions: Mapped[list["Action"]] = relationship(back_populates="investigation")


class AgentFinding(Base):
    __tablename__ = "agent_findings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    agent: Mapped[str] = mapped_column(String(32))  # identity|endpoint|supplychain|correlator
    findings: Mapped[dict] = mapped_column(JSONB, default=dict)
    iocs: Mapped[list] = mapped_column(JSONB, default=list)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    investigation: Mapped["Investigation"] = relationship(back_populates="findings")


class Action(Base):
    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    type: Mapped[str] = mapped_column(String(48))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    rationale: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default=ACT_STAGED, index=True)
    requires_second_confirm: Mapped[bool] = mapped_column(default=False)
    dry_run: Mapped[bool] = mapped_column(default=True)
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    staged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="actions")


class AuditEvent(Base):
    """Append-only SHA-256 hash chain (R9). `content` is the hashed JSONB blob;
    created_at is a non-hashed convenience column."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    seq: Mapped[int] = mapped_column(BigInteger)
    content: Mapped[dict] = mapped_column(JSONB)  # {ts, actor, event_type, data}
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("uq_audit_tenant_seq", "tenant_id", "seq", unique=True),)
