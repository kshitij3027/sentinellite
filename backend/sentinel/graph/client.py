"""Neo4j async driver lifecycle + tiny read/write helpers."""

from __future__ import annotations

from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase

from sentinel.config import settings
from sentinel.logging import get_logger

log = get_logger("graph")

_driver: AsyncDriver | None = None

# label -> the single key property we MERGE on (community-edition friendly: a
# synthetic per-tenant `uid` so we avoid Enterprise-only composite constraints).
NODE_KEYS: dict[str, str] = {
    "Identity": "name",
    "IP": "addr",
    "Asset": "name",
    "Process": "cmdline",
    "Package": "name",
    "Repository": "name",
    "CloudResource": "arn",
}


def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
        )
    return _driver


async def close_driver() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None


async def verify_connectivity() -> bool:
    try:
        await get_driver().verify_connectivity()
        return True
    except Exception as exc:  # pragma: no cover
        log.warning("graph.connectivity_failed", error=str(exc))
        return False


async def ensure_schema() -> None:
    """Single-property uniqueness constraints (Community-safe)."""
    driver = get_driver()
    async with driver.session() as session:
        await session.run(
            "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE"
        )
        for label in NODE_KEYS:
            await session.run(
                f"CREATE CONSTRAINT {label.lower()}_uid IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.uid IS UNIQUE"
            )


async def run_write(statements: list[tuple[str, dict]]) -> None:
    driver = get_driver()
    async with driver.session() as session:
        async def _tx(tx):
            for cypher, params in statements:
                await tx.run(cypher, **params)

        await session.execute_write(_tx)


async def run_read(cypher: str, **params: Any) -> list[dict]:
    driver = get_driver()
    async with driver.session() as session:
        result = await session.run(cypher, **params)
        return [record.data() async for record in result]
