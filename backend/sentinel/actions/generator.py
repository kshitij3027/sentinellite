"""Generate recommended response actions for an investigation (R7) with
pre-filled parameters and a rationale, and expire stale approvals."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from sentinel.actions.registry import REGISTRY, is_irreversible
from sentinel.audit.chain import append_event
from sentinel.config import settings
from sentinel.db.base import SessionLocal
from sentinel.db.models import (
    ACT_AWAITING_CONFIRM,
    ACT_EXPIRED,
    ACT_STAGED,
    INV_AWAITING_APPROVAL,
    INV_RUNNING,
    Action,
    Alert,
    Investigation,
)
from sentinel.detection.indicators import is_suspicious_ip
from sentinel.logging import get_logger
from sentinel.metrics import ACTIONS_STAGED
from sentinel.mitre import classify
from sentinel.queue import publish_trace
from sentinel.types import new_id

log = get_logger("actions")


def _cidr24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return f"{ip}/32"


_PKG_RE = re.compile(r"([A-Za-z0-9_.\-]+)@(\d+\.\d+\.\d+)")


def _package_of(alert: Alert) -> str | None:
    if alert.package:
        return alert.package
    m = _PKG_RE.search(str(alert.raw))  # e.g. "lodash@4.17.15" in a commit message
    return f"{m.group(1)}@{m.group(2)}" if m else None


def _aws_user(alert: Alert) -> str:
    raw = alert.raw if isinstance(alert.raw, dict) else {}
    rp = raw.get("requestParameters") or {}
    if rp.get("userName"):
        return rp["userName"]
    arn = alert.actor_identity or ""
    return arn.split("/")[-1] if "/" in arn else (arn or "unknown")


def recommend_actions(members: list[Alert]) -> list[tuple[str, dict, str]]:
    """Deterministic IOC -> action mapping. Returns (type, params, rationale)."""
    recs: list[tuple[str, dict, str]] = []
    seen: set[tuple] = set()

    def add(typ: str, params: dict, rationale: str) -> None:
        key = (typ, tuple(sorted(params.items())))
        if key not in seen:
            seen.add(key)
            recs.append((typ, params, rationale))

    for m in members:
        techs = classify(m)
        ev = m.source_event_type.split(":")[-1]

        if "T1195.002" in techs:
            pkg = _package_of(m)
            if pkg:
                name, _, ver = pkg.partition("@")
                add("quarantine_package", {"name": name, "version": ver or "unknown"},
                    f"Compromised dependency {pkg} executed a malicious postinstall in CI (evidence {m.id}).")

        if is_suspicious_ip(m.source_ip):
            add("block_ip", {"cidr": _cidr24(m.source_ip)},
                f"Malicious activity from Tor exit {m.source_ip} (evidence {m.id}).")

        if m.source == "aws_cloudtrail" and ev in ("AssumeRole", "CreateAccessKey"):
            add("revoke_aws_keys", {"user": _aws_user(m)},
                f"Stolen AWS credentials used for {ev} from {m.source_ip} (evidence {m.id}).")

        if m.source == "okta_system_log" and m.actor_identity and "credential" in (m.source_event_type or "").lower():
            add("revoke_session", {"user": m.actor_identity},
                f"Suspicious Okta activity for {m.actor_identity} (evidence {m.id}).")

        if m.source == "falco" and "T1059.004" in techs and m.asset:
            add("isolate_workload", {"workload": m.asset},
                f"Malicious shell executed on {m.asset}; isolate to stop lateral movement (evidence {m.id}).")

    return recs


async def generate_actions(tenant_id: str, inv_id: str) -> int:
    async with SessionLocal() as session:
        inv = (await session.execute(
            select(Investigation).where(Investigation.id == inv_id)
        )).scalar_one_or_none()
        if inv is None:
            return 0
        members = list((await session.execute(
            select(Alert).where(Alert.investigation_id == inv_id).order_by(Alert.ts.asc())
        )).scalars().all())

        recs = recommend_actions(members)

        # Replace only still-staged actions; never disturb decided/executed ones.
        await session.execute(
            delete(Action).where(Action.investigation_id == inv_id, Action.status == ACT_STAGED)
        )
        for typ, params, rationale in recs:
            if typ not in REGISTRY:
                continue
            session.add(Action(
                id=new_id("act"), investigation_id=inv_id, tenant_id=tenant_id,
                type=typ, params=params, rationale=rationale, status=ACT_STAGED,
                requires_second_confirm=is_irreversible(typ), dry_run=settings.action_dry_run,
            ))
            ACTIONS_STAGED.labels(type=typ, tenant=tenant_id).inc()

        inv.status = INV_AWAITING_APPROVAL if recs else INV_RUNNING
        await append_event(
            session, tenant_id=tenant_id, actor="agent:responder", event_type="actions.staged",
            data={"investigation_id": inv_id, "count": len(recs), "types": [r[0] for r in recs]},
        )
        await session.commit()

    await publish_trace(inv_id, {"type": "actions.staged", "count": len(recs)})
    log.info("actions.staged", inv_id=inv_id, count=len(recs), types=[r[0] for r in recs])
    return len(recs)


async def expire_stale_actions() -> int:
    """Auto-reject approvals left pending past APPROVAL_TIMEOUT_MIN."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.approval_timeout_min)
    async with SessionLocal() as session:
        stale = list((await session.execute(
            select(Action).where(
                Action.status.in_([ACT_STAGED, ACT_AWAITING_CONFIRM]),
                Action.staged_at < cutoff,
            )
        )).scalars().all())
        for a in stale:
            a.status = ACT_EXPIRED
            a.decided_at = datetime.now(timezone.utc)
            await append_event(
                session, tenant_id=a.tenant_id, actor="system", event_type="action.expired",
                data={"action_id": a.id, "type": a.type},
            )
        if stale:
            await session.commit()
    return len(stale)
