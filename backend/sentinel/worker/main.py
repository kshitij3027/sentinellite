"""Background worker pool entrypoint. Consumes the Redis ingest queue and runs
the triage -> investigate -> correlate -> stage-actions pipeline."""

from __future__ import annotations

import asyncio
import signal

from sentinel.config import settings
from sentinel.logging import configure_logging, get_logger
from sentinel.metrics import QUEUE_DEPTH
from sentinel.queue import dequeue_alert, queue_depth
from sentinel.worker.pipeline import process_alert

log = get_logger("worker")


async def run() -> None:
    configure_logging()
    log.info("worker.startup", provider=settings.llm_provider, model=settings.llm_model)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover
            pass

    while not stop.is_set():
        try:
            item = await dequeue_alert(timeout=3)
            if item:
                QUEUE_DEPTH.labels(queue="ingest").set(await queue_depth())
                await process_alert(item["tenant_id"], item["alert_id"])
        except Exception as exc:  # never let one bad alert kill the worker
            log.error("worker.process_failed", error=str(exc))
            await asyncio.sleep(0.5)
    log.info("worker.shutdown")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
