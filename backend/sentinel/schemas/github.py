"""GitHub webhook validator + normalizer. The event name comes from the
`X-GitHub-Event` header (NOT the body), so the ingest route passes it in."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinel.schemas.common import NormalizedAlert, Source, utcnow
from sentinel.types import Severity


class GHUser(BaseModel):
    model_config = ConfigDict(extra="allow")
    login: str | None = None
    id: int | None = None
    type: str | None = None
    site_admin: bool | None = None


class GHRepo(BaseModel):
    model_config = ConfigDict(extra="allow")
    full_name: str | None = None
    name: str | None = None
    private: bool | None = None
    default_branch: str | None = None
    visibility: str | None = None
    pushed_at: Any | None = None


class GitHubEvent(BaseModel):
    """Permissive validator covering the common + push/member/organization fields."""

    model_config = ConfigDict(extra="allow")
    action: str | None = None
    ref: str | None = None
    sender: GHUser | None = None
    repository: GHRepo | None = None
    organization: dict[str, Any] | None = None
    installation: dict[str, Any] | None = None
    pusher: dict[str, Any] | None = None
    head_commit: dict[str, Any] | None = None
    commits: list[dict[str, Any]] | None = None
    member: GHUser | None = None
    membership: dict[str, Any] | None = None
    changes: dict[str, Any] | None = None


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return utcnow()


def _severity(event: str, action: str | None, ev: GitHubEvent) -> Severity:
    perm = ((ev.changes or {}).get("permission") or {}).get("to")
    if event == "member" and action in {"added", "edited"} and perm == "admin":
        return "high"
    if event == "organization" and action in {"member_added", "member_invited"}:
        return "medium"
    if event == "member" and action == "added":
        return "low"
    if event == "push" and ev.head_commit:
        # Force pushes / pushes touching CI or credential paths get a small bump.
        files = set((ev.head_commit or {}).get("added", [])) | set(
            (ev.head_commit or {}).get("modified", [])
        )
        risky = any(
            f.endswith((".yml", ".yaml")) and "workflow" in f.lower() for f in files
        ) or any("package.json" in f or "requirements" in f or "setup.py" in f for f in files)
        return "low" if risky else "info"
    return "info"


def to_normalized(payload: dict[str, Any], event_name: str | None = None) -> NormalizedAlert:
    ev = GitHubEvent.model_validate(payload)

    # event name from header; fall back to body shape
    event = event_name or (
        "push" if (ev.commits is not None or ev.pusher) else "member" if ev.member else "unknown"
    )
    set_type = f"{event}.{ev.action}" if ev.action else event

    ts = _parse_ts((ev.head_commit or {}).get("timestamp")) if ev.head_commit else (
        _parse_ts(ev.repository.pushed_at) if ev.repository and ev.repository.pushed_at else utcnow()
    )

    actor = (ev.sender.login if ev.sender else None) or (ev.pusher or {}).get("name")
    repo = ev.repository.full_name if ev.repository else None

    title_bits = [f"GitHub {set_type}"]
    if actor:
        title_bits.append(f"by {actor}")
    if repo:
        title_bits.append(f"on {repo}")

    return NormalizedAlert(
        tenant_id="default",
        source=Source.github,
        source_event_type=set_type,
        ts=ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc),
        severity_hint=_severity(event, ev.action, ev),
        title=" ".join(title_bits),
        actor_identity=actor,
        repository=repo,
        raw=payload,
    )
