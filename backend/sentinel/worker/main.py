"""Background worker. Two concurrent loops:
  1. ingest loop  — drains the Redis queue and triages each alert (fast).
  2. investigation loop — runs debounced incident investigations (heavy: R5/R6).
Decoupling keeps triage responsive while investigations settle."""

from __future__ import annotations

import asyncio
import signal

from prometheus_client import start_http_server

from sentinel.config import settings
from sentinel.logging import configure_logging, get_logger
from sentinel.metrics import QUEUE_DEPTH
from sentinel.queue import dequeue_alert, pop_ready_investigations, queue_depth
from sentinel.worker.pipeline import process_alert

log = get_logger("worker")
METRICS_PORT = 9100


async def _ingest_loop(stop: asyncio.Event) -> None:
    # Bounded-concurrent triage: overlap LLM calls (Ollama serves NUM_PARALLEL at
    # once) so a burst of alerts doesn't serialize behind one another.
    sem = asyncio.Semaphore(settings.triage_concurrency)
    inflight: set[asyncio.Task] = set()

    async def _handle(it: dict) -> None:
        async with sem:
            try:
                await process_alert(it["tenant_id"], it["alert_id"])
            except Exception as exc:
                log.error("worker.process_failed", error=str(exc))

    while not stop.is_set():
        try:
            item = await dequeue_alert(timeout=2)
            if item:
                QUEUE_DEPTH.labels(queue="ingest").set(await queue_depth())
                task = asyncio.create_task(_handle(item))
                inflight.add(task)
                task.add_done_callback(inflight.discard)
        except Exception as exc:
            log.error("worker.ingest_failed", error=str(exc))
            await asyncio.sleep(0.5)
    if inflight:
        await asyncio.gather(*inflight, return_exceptions=True)


async def _investigation_loop(stop: asyncio.Event) -> None:
    from sentinel.actions.generator import expire_stale_actions
    from sentinel.agents.investigation import run_investigation

    while not stop.is_set():
        try:
            for tenant_id, inv_id in await pop_ready_investigations():
                await run_investigation(tenant_id, inv_id)
            await expire_stale_actions()
        except Exception as exc:
            log.error("worker.investigation_failed", error=str(exc))
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.worker_poll_dirty_s)
        except asyncio.TimeoutError:
            pass


async def run() -> None:
    configure_logging()
    # Expose the worker's metrics (triage/investigation/tokens/...) for Prometheus.
    try:
        start_http_server(METRICS_PORT)
        log.info("worker.metrics_server", port=METRICS_PORT)
    except Exception as exc:  # pragma: no cover
        log.warning("worker.metrics_server_failed", error=str(exc))
    log.info("worker.startup", provider=settings.llm_provider, model=settings.llm_model)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover
            pass

    await asyncio.gather(_ingest_loop(stop), _investigation_loop(stop))
    log.info("worker.shutdown")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
