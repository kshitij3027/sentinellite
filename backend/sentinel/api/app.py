"""FastAPI control plane. REST + SSE. Boots without hard dependencies so the
liveness probe is green immediately; /readyz pings the datastores."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from sentinel import __version__
from sentinel import metrics as _metrics  # noqa: F401  (registers Prometheus series)
from sentinel.config import settings
from sentinel.logging import configure_logging, get_logger

log = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    log.info("api.startup", version=__version__, provider=settings.llm_provider,
             model=settings.llm_model, airgap=settings.airgap_mode)
    yield
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


@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Liveness: process is up."""
    return {"status": "ok", "version": __version__}


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
