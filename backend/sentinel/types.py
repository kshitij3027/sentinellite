"""Shared primitive types used across config, schemas, agents, and DB models."""

from __future__ import annotations

import secrets
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITY_RANK.get(sev, 99)


def max_sev(a: str, b: str) -> str:
    return a if sev_rank(a) >= sev_rank(b) else b


def new_id(prefix: str) -> str:
    """Short, human-readable, prefixed id, e.g. alt_3f9a1c2b."""
    return f"{prefix}_{secrets.token_hex(4)}"
