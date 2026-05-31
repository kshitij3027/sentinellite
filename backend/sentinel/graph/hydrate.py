"""Hydrate the security graph from a normalized alert (R2).

Creates the Alert node + entity nodes (Identity/Asset/Process/Package/IP/
Repository/CloudResource), an (Alert)-[:OBSERVED]->(entity) edge for each, the
domain relationships (AUTHENTICATED_AS / RAN_ON / INSTALLED / COMMUNICATED_WITH
/ ASSUMED_ROLE), and CORRELATES_WITH links to prior alerts sharing an entity."""

from __future__ import annotations

from sentinel.graph.client import NODE_KEYS, run_write
from sentinel.schemas.common import NormalizedAlert

# entity slot -> graph label
SLOT_LABEL: dict[str, str] = {
    "actor_identity": "Identity",
    "source_ip": "IP",
    "asset": "Asset",
    "process": "Process",
    "package": "Package",
    "repository": "Repository",
    "cloud_resource": "CloudResource",
}

# entities strong enough to imply two alerts are part of the same story
CORRELATION_LABELS = ("Identity", "IP", "Package", "CloudResource")


def _uid(tenant: str, value: str) -> str:
    return f"{tenant}|{value}"


def _domain_edges(alert: NormalizedAlert) -> list[tuple[str, str, str, str, str, str]]:
    """Return (src_label, src_val, REL, dst_label, dst_val) tuples."""
    edges: list[tuple[str, str, str, str, str, str]] = []
    et = alert.source_event_type
    ai, ip, asset = alert.actor_identity, alert.source_ip, alert.asset
    proc, pkg, repo, cr = alert.process, alert.package, alert.repository, alert.cloud_resource

    if ip and ai and (alert.source == "okta_system_log" or "ConsoleLogin" in et or "Login" in et):
        edges.append(("IP", ip, "AUTHENTICATED_AS", "Identity", ai, "auth"))
    if "AssumeRole" in et and ai and cr:
        edges.append(("Identity", ai, "ASSUMED_ROLE", "CloudResource", cr, "assume"))
    if alert.source == "falco" and proc and asset:
        edges.append(("Process", proc, "RAN_ON", "Asset", asset, "ran"))
    if pkg and (asset or repo):
        src_label, src_val = ("Asset", asset) if asset else ("Repository", repo)
        edges.append((src_label, src_val, "INSTALLED", "Package", pkg, "install"))  # type: ignore[arg-type]
    if ip and cr:
        edges.append(("IP", ip, "COMMUNICATED_WITH", "CloudResource", cr, "net"))
    return edges


async def hydrate_alert(alert: NormalizedAlert) -> None:
    t = alert.tenant_id
    aid = alert.id
    stmts: list[tuple[str, dict]] = []

    stmts.append((
        "MERGE (a:Alert {id:$id}) "
        "SET a.tenant_id=$t, a.source=$source, a.event_type=$et, a.ts=$ts, "
        "a.severity_hint=$sev, a.title=$title",
        {
            "id": aid, "t": t, "source": str(alert.source), "et": alert.source_event_type,
            "ts": alert.ts.isoformat(), "sev": alert.severity_hint, "title": alert.title,
        },
    ))

    for slot, value in alert.entities().items():
        label = SLOT_LABEL[slot]
        key = NODE_KEYS[label]
        stmts.append((
            f"MERGE (n:{label} {{uid:$uid}}) SET n.tenant_id=$t, n.{key}=$v "
            f"WITH n MATCH (a:Alert {{id:$aid}}) MERGE (a)-[:OBSERVED]->(n)",
            {"uid": _uid(t, value), "t": t, "v": value, "aid": aid},
        ))

    for src_label, src_val, rel, dst_label, dst_val, _tag in _domain_edges(alert):
        stmts.append((
            f"MATCH (s:{src_label} {{uid:$suid}}), (d:{dst_label} {{uid:$duid}}) "
            f"MERGE (s)-[:{rel}]->(d)",
            {"suid": _uid(t, src_val), "duid": _uid(t, dst_val)},
        ))

    # CORRELATES_WITH: link to prior alerts that share a strong entity.
    stmts.append((
        "MATCH (a:Alert {id:$aid})-[:OBSERVED]->(e)<-[:OBSERVED]-(b:Alert) "
        "WHERE b.id <> a.id AND e.tenant_id=$t AND any(l IN labels(e) WHERE l IN $labels) "
        "MERGE (a)-[:CORRELATES_WITH]->(b)",
        {"aid": aid, "t": t, "labels": list(CORRELATION_LABELS)},
    ))

    await run_write(stmts)
