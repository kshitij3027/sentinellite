"""End-to-end data-plane tests (R1/R2/R9) against live Postgres + Neo4j + Redis.

Marked `integration`; run via `make test` (datastores up), skipped by
`make test-unit`. Uses a fresh random tenant so the audit chain starts empty
and the tamper test is deterministic."""

from __future__ import annotations

import asyncio
import secrets

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import app
from sentinel.config import settings
from tests import samples

pytestmark = pytest.mark.integration

TENANT = f"itest_{secrets.token_hex(3)}"
H = {"X-Tenant-Id": TENANT}


@pytest.fixture(scope="module")
def api():
    # Context manager runs lifespan -> init_db + graph schema, on one portal loop.
    with TestClient(app) as c:
        yield c


def _corrupt_first_audit_row(tenant: str) -> None:
    import asyncpg

    dsn = settings.postgres_dsn.replace("+asyncpg", "")

    async def go():
        conn = await asyncpg.connect(dsn=dsn)
        await conn.execute(
            "UPDATE audit_events SET content = jsonb_set(content, '{actor}', '\"tampered\"') "
            "WHERE tenant_id=$1 AND seq=1",
            tenant,
        )
        await conn.close()

    asyncio.run(go())


def _count_alert_nodes(tenant: str) -> int:
    from neo4j import AsyncGraphDatabase

    async def go():
        drv = AsyncGraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
        )
        try:
            async with drv.session() as s:
                res = await s.run("MATCH (a:Alert {tenant_id:$t}) RETURN count(a) AS n", t=tenant)
                rec = await res.single()
                return rec["n"]
        finally:
            await drv.close()

    return asyncio.run(go())


def test_ingest_cloudtrail_createaccesskey_is_high(api):
    r = api.post("/ingest/aws_cloudtrail", json=samples.CLOUDTRAIL_CREATEACCESSKEY, headers=H)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source_event_type"] == "iam:CreateAccessKey"
    assert body["severity_hint"] == "high"
    assert body["alert_id"].startswith("alt_")


def test_ingest_github_push_with_header(api):
    r = api.post(
        "/ingest/github",
        json=samples.GITHUB_PUSH,
        headers={**H, "X-GitHub-Event": "push"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["source_event_type"] == "push"


def test_ingest_okta_and_falco(api):
    assert api.post("/ingest/okta_system_log", json=samples.OKTA_LOGIN_FAILURE, headers=H).status_code == 200
    assert api.post("/ingest/falco", json=samples.FALCO_SHELL, headers=H).status_code == 200


def test_unknown_source_404(api):
    assert api.post("/ingest/splunk", json={}, headers=H).status_code == 404


def test_non_object_body_400(api):
    assert api.post("/ingest/falco", json=[1, 2, 3], headers=H).status_code == 400


def test_alerts_listed_and_detail(api):
    lst = api.get("/alerts", headers=H).json()
    assert lst["count"] >= 4
    alert_id = lst["alerts"][0]["id"]
    detail = api.get(f"/alerts/{alert_id}", headers=H).json()
    assert detail["id"] == alert_id
    assert detail["raw"]  # original payload preserved


def test_graph_hydrated(api):
    # 4+ alerts ingested above -> at least that many Alert nodes for this tenant.
    assert _count_alert_nodes(TENANT) >= 4


def test_audit_chain_verifies_then_tamper_breaks_it(api):
    audit = api.get("/audit", headers=H).json()
    assert audit["count"] >= 4  # one alert.ingested per alert
    assert audit["events"][0]["event_type"] == "alert.ingested"

    ok = api.get("/audit/verify", headers=H).json()
    assert ok["ok"] is True
    assert ok["broken_index"] is None

    _corrupt_first_audit_row(TENANT)

    broken = api.get("/audit/verify", headers=H).json()
    assert broken["ok"] is False
    assert broken["broken_index"] == 0
