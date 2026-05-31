"""DetectionTunerAgent (DE2): review recent alerts, find escalated true-positives
NOT yet covered by a Sigma rule (detection gaps), and propose candidate rules.

The proposals are written to rules/candidates/ as a Git-diffable YAML. Opening a
PR against the rules repo is gated behind a GitHub PAT (opt-in)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml
from sqlalchemy import select

from sentinel.config import settings
from sentinel.db.base import SessionLocal
from sentinel.db.models import ALERT_ESCALATED, Alert
from sentinel.detection.indicators import evaluate
from sentinel.detection.rules import get_engine
from sentinel.logging import get_logger
from sentinel.mitre import classify

log = get_logger("tuner")


async def propose_rules(tenant_id: str, limit: int = 300) -> list[dict]:
    engine = get_engine()
    async with SessionLocal() as session:
        rows = list((await session.execute(
            select(Alert).where(Alert.tenant_id == tenant_id, Alert.status == ALERT_ESCALATED).limit(limit)
        )).scalars().all())

    gaps: Counter = Counter()
    sample: dict = {}
    for a in rows:
        if engine.match(a):  # already covered by an existing rule
            continue
        if evaluate(a).threat:  # escalated true-positive with no rule -> a gap
            key = (a.source, (a.source_event_type or "").split(":")[-1])
            gaps[key] += 1
            sample.setdefault(key, a)

    proposals: list[dict] = []
    for (source, ev), count in gaps.most_common(5):
        a = sample[(source, ev)]
        techs = classify(a)
        proposals.append({
            "id": f"auto-{source}-{ev}".lower().replace("_", "-").replace(":", "-"),
            "title": f"Auto-proposed: {ev} on {source} (covers {count} escalated alert(s))",
            "severity": "medium",
            "source": source,
            "mitre": techs[0] if techs else None,
            "indicator": f"auto_{ev.lower()}",
            "condition": {"event_in": [ev]} if ev else {"min_severity_hint": "high"},
        })
    return proposals


def write_candidates(proposals: list[dict]) -> Path | None:
    if not proposals:
        return None
    out_dir = Path(settings.rules_dir) / "candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "proposed.yml"
    body = [{k: v for k, v in p.items()} for p in proposals]
    dest.write_text("# Auto-proposed by the DetectionTunerAgent (DE2). Review before merging.\n"
                    + yaml.safe_dump(body, sort_keys=False))
    log.info("tuner.candidates_written", path=str(dest), count=len(proposals))
    return dest
