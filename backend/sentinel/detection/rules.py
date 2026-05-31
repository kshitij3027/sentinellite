"""Sigma-style YAML detection rules (DE1) with hot-reload on file change.

A rule matches a normalized alert when ALL of its condition clauses hold. Matched
rules contribute an indicator label, a MITRE technique, and a severity/weight to
the triage Signal — augmenting the hardcoded indicators."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel.config import settings
from sentinel.logging import get_logger
from sentinel.types import SEVERITY_RANK

log = get_logger("rules")

_SEV_WEIGHT = {"info": 5, "low": 10, "medium": 30, "high": 40, "critical": 50}


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    source: str | None = None
    mitre: str | None = None
    indicator: str = ""
    condition: dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> int:
        return _SEV_WEIGHT.get(self.severity, 30)

    @property
    def is_threat(self) -> bool:
        return SEVERITY_RANK.get(self.severity, 0) >= SEVERITY_RANK["medium"]

    def _field(self, alert, name: str) -> str:
        if name == "raw":
            return str(getattr(alert, "raw", "")).lower()
        return str(getattr(alert, name, "") or "").lower()

    def matches(self, alert) -> bool:
        c = self.condition
        if self.source and alert.source != self.source:
            return False
        ev = (alert.source_event_type or "").split(":")[-1]
        if "event_in" in c and ev not in c["event_in"]:
            return False
        if "event_regex" in c and not re.search(c["event_regex"], alert.source_event_type or ""):
            return False
        for fld, sub in (c.get("contains") or {}).items():
            if str(sub).lower() not in self._field(alert, fld):
                return False
        if "any_contains" in c:
            spec = c["any_contains"]
            blob = " ".join(self._field(alert, f) for f in spec.get("fields", ["raw"]))
            if not any(str(v).lower() in blob for v in spec.get("values", [])):
                return False
        if c.get("ip_suspicious"):
            from sentinel.detection.indicators import is_suspicious_ip
            if not is_suspicious_ip(alert.source_ip):
                return False
        if "min_severity_hint" in c:
            if SEVERITY_RANK.get(alert.severity_hint, 0) < SEVERITY_RANK.get(c["min_severity_hint"], 0):
                return False
        return True


def _parse(doc: Any) -> list[Rule]:
    items = doc if isinstance(doc, list) else [doc]
    rules = []
    for it in items:
        if not isinstance(it, dict) or "id" not in it:
            continue
        rules.append(Rule(
            id=it["id"], title=it.get("title", it["id"]), severity=it.get("severity", "medium"),
            source=it.get("source"), mitre=it.get("mitre"),
            indicator=it.get("indicator", f"rule:{it['id']}"), condition=it.get("condition", {}),
        ))
    return rules


class RuleEngine:
    """Loads rules from RULES_DIR and hot-reloads when any .yml mtime changes."""

    def __init__(self, rules_dir: str | None = None):
        self.dir = Path(rules_dir or settings.rules_dir)
        self.rules: list[Rule] = []
        self._sig: float = -1.0
        self.reload()

    def _mtime_sig(self) -> float:
        if not self.dir.exists():
            return 0.0
        return sum(p.stat().st_mtime for p in self.dir.glob("*.y*ml"))

    def reload(self) -> int:
        rules: list[Rule] = []
        if self.dir.exists():
            for p in sorted(self.dir.glob("*.y*ml")):
                try:
                    rules.extend(_parse(yaml.safe_load(p.read_text())))
                except Exception as exc:
                    log.warning("rules.parse_failed", file=str(p), error=str(exc))
        self.rules = rules
        self._sig = self._mtime_sig()
        log.info("rules.loaded", count=len(rules), dir=str(self.dir))
        return len(rules)

    def _maybe_reload(self) -> None:
        if self._mtime_sig() != self._sig:  # hot-reload on change
            self.reload()

    def match(self, alert) -> list[Rule]:
        self._maybe_reload()
        return [r for r in self.rules if r.matches(alert)]


_engine: RuleEngine | None = None


def get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
