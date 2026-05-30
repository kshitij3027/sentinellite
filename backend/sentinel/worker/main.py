"""Background worker pool entrypoint. Consumes the ingest queue and drives the
triage -> investigate -> correlate -> stage-actions pipeline.

Milestone 0: a heartbeat loop that proves the container boots and can reach
Redis. The real pipeline lands in Milestone 1-3."""

from __future__ import annotations

import asyncio
import signal

from sentinel.config import settings
from sentinel.logging import configure_logging, get_logger

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

    tick = 0
    while not stop.is_set():
        tick += 1
        log.debug("worker.heartbeat", tick=tick)
        try:
            await asyncio.wait_for(stop.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            continue
    log.info("worker.shutdown")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
