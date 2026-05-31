"""Read queries over the security graph: correlation, neighborhoods, paths, and
a node/edge subgraph for the dashboard's force-graph view (R10)."""

from __future__ import annotations

from sentinel.graph.client import run_read


async def correlated_alerts(tenant_id: str, alert_id: str, limit: int = 25) -> list[dict]:
    """Alerts connected to this one via shared strong entities."""
    return await run_read(
        "MATCH (a:Alert {id:$id})-[:CORRELATES_WITH|OBSERVED*1..2]-(b:Alert) "
        "WHERE b.tenant_id=$t AND b.id <> $id "
        "RETURN DISTINCT b.id AS id, b.source AS source, b.event_type AS event_type, "
        "b.severity_hint AS severity_hint, b.ts AS ts ORDER BY b.ts LIMIT $limit",
        t=tenant_id, id=alert_id, limit=limit,
    )


async def entity_neighborhood(tenant_id: str, value: str, limit: int = 50) -> list[dict]:
    return await run_read(
        "MATCH (n {tenant_id:$t}) WHERE n.name=$v OR n.addr=$v OR n.arn=$v OR n.cmdline=$v "
        "MATCH (n)<-[:OBSERVED]-(a:Alert) "
        "RETURN a.id AS alert_id, a.event_type AS event_type, a.ts AS ts "
        "ORDER BY a.ts LIMIT $limit",
        t=tenant_id, v=value, limit=limit,
    )


async def alert_subgraph(tenant_id: str, alert_ids: list[str]) -> dict:
    """Nodes + edges around a set of alerts, shaped for react-force-graph-2d."""
    nodes = await run_read(
        "MATCH (a:Alert)-[:OBSERVED]->(n) WHERE a.id IN $ids "
        "RETURN DISTINCT elementId(n) AS id, labels(n)[0] AS label, "
        "coalesce(n.name,n.addr,n.arn,n.cmdline) AS value",
        ids=alert_ids,
    )
    alert_nodes = await run_read(
        "MATCH (a:Alert) WHERE a.id IN $ids "
        "RETURN a.id AS id, 'Alert' AS label, a.event_type AS value, a.severity_hint AS severity",
        ids=alert_ids,
    )
    edges = await run_read(
        "MATCH (a:Alert)-[r]->(n) WHERE a.id IN $ids "
        "RETURN a.id AS source, elementId(n) AS target, type(r) AS rel",
        ids=alert_ids,
    )
    inter = await run_read(
        "MATCH (s)-[r]->(d) WHERE NOT s:Alert AND NOT d:Alert AND s.tenant_id=$t "
        "AND any(a IN $ids WHERE (a)<-[]-() OR true) "
        "RETURN elementId(s) AS source, elementId(d) AS target, type(r) AS rel LIMIT 200",
        t=tenant_id, ids=alert_ids,
    )
    return {"nodes": alert_nodes + nodes, "edges": edges + inter}


async def graph_stats(tenant_id: str) -> dict:
    rows = await run_read(
        "MATCH (n {tenant_id:$t}) RETURN labels(n)[0] AS label, count(*) AS n", t=tenant_id
    )
    return {r["label"]: r["n"] for r in rows if r["label"]}
