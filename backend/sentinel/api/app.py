"""FastAPI control plane. REST + SSE. Boots without hard dependencies so the
liveness probe is green immediately; /readyz pings the datastores."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from sentinel import __version__
from sentinel import metrics as _metrics  # noqa: F401  (registers Prometheus series)
from sentinel.api.routes import actions as actions_routes
from sentinel.api.routes import alerts as alerts_routes
from sentinel.api.routes import audit as audit_routes
from sentinel.api.routes import ingest as ingest_routes
from sentinel.api.routes import investigations as investigations_routes
from sentinel.config import settings
from sentinel.db.base import init_db
from sentinel.graph.client import close_driver, ensure_schema, verify_connectivity
from sentinel.logging import configure_logging, get_logger

log = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    log.info("api.startup", version=__version__, provider=settings.llm_provider,
             model=settings.llm_model, airgap=settings.airgap_mode)
    # Postgres schema (compose guarantees the DB is healthy before we start).
    last_err: Exception | None = None
    for attempt in range(10):
        try:
            await init_db()
            last_err = None
            break
        except Exception as exc:  # transient startup race
            last_err = exc
            await asyncio.sleep(1.5)
    if last_err:
        log.error("db.init_failed", error=str(last_err))
    # Neo4j schema (best-effort; graph is a secondary store).
    if await verify_connectivity():
        try:
            await ensure_schema()
        except Exception as exc:
            log.warning("graph.schema_failed", error=str(exc))
    yield
    from sentinel.db.base import engine

    await close_driver()
    await engine.dispose()
    log.info("api.shutdown")


app = FastAPI(
    title="SentinelLite",
    version=__version__,
    description="A self-hostable mini Autonomous SOC.",
    lifespan=lifespan,
)

# Dashboard runs on a different origin in dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_routes.router)
app.include_router(alerts_routes.router)
app.include_router(audit_routes.router)
app.include_router(investigations_routes.router)
app.include_router(actions_routes.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Liveness: process is up."""
    return {"status": "ok", "version": __version__}


@app.get("/readyz", tags=["meta"])
async def readyz() -> dict:
    """Readiness: can we reach Postgres, Redis, and Neo4j?"""
    from sqlalchemy import text

    from sentinel.db.base import engine
    from sentinel.queue import get_redis

    checks: dict[str, bool] = {}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception:
        checks["postgres"] = False
    try:
        await get_redis().ping()
        checks["redis"] = True
    except Exception:
        checks["redis"] = False
    checks["neo4j"] = await verify_connectivity()

    return {"ready": all(checks.values()), "checks": checks}


@app.get("/metrics", tags=["meta"])
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "name": "SentinelLite",
        "version": __version__,
        "docs": "/docs",
        "tagline": "A self-hostable mini Autonomous SOC, tested against real public attack data.",
    }
