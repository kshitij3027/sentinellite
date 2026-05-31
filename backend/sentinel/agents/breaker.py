"""Per-agent circuit breaker (OB4): a stuck/erroring agent trips open so it
can't starve the investigation queue. Closed -> Open (after N fails) ->
Half-open (after reset) -> Closed on success."""

from __future__ import annotations

import time

from sentinel.config import settings
from sentinel.metrics import BREAKER_STATE

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


class CircuitBreaker:
    def __init__(self, name: str, fail_threshold: int | None = None, reset_s: float | None = None):
        self.name = name
        self.fail_threshold = fail_threshold or settings.breaker_fail_threshold
        self.reset_s = reset_s if reset_s is not None else settings.breaker_reset_s
        self.failures = 0
        self.state = CLOSED
        self.opened_at = 0.0

    def allow(self) -> bool:
        if self.state == OPEN:
            if (time.monotonic() - self.opened_at) >= self.reset_s:
                self.state = HALF_OPEN
                return True
            return False
        return True

    def record_success(self) -> None:
        self.failures = 0
        self.state = CLOSED
        BREAKER_STATE.labels(agent=self.name).set(0)

    def record_failure(self) -> None:
        self.failures += 1
        if self.state == HALF_OPEN or self.failures >= self.fail_threshold:
            self.state = OPEN
            self.opened_at = time.monotonic()
            BREAKER_STATE.labels(agent=self.name).set(1)


_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(name: str) -> CircuitBreaker:
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name)
    return _breakers[name]


def reset_all() -> None:  # test helper
    _breakers.clear()
