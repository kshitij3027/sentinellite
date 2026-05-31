"""OB4: per-agent circuit breaker transitions."""

from __future__ import annotations

import time

from sentinel.agents.breaker import CLOSED, HALF_OPEN, OPEN, CircuitBreaker


def test_breaker_opens_after_threshold():
    cb = CircuitBreaker("t", fail_threshold=2, reset_s=0.05)
    assert cb.allow() is True
    cb.record_failure()
    assert cb.state == CLOSED  # one failure, still closed
    cb.record_failure()
    assert cb.state == OPEN
    assert cb.allow() is False  # open -> blocked


def test_breaker_half_opens_then_closes_on_success():
    cb = CircuitBreaker("t2", fail_threshold=1, reset_s=0.05)
    cb.record_failure()
    assert cb.state == OPEN
    time.sleep(0.06)
    assert cb.allow() is True  # reset window elapsed -> half-open probe
    assert cb.state == HALF_OPEN
    cb.record_success()
    assert cb.state == CLOSED


def test_breaker_reopens_if_probe_fails():
    cb = CircuitBreaker("t3", fail_threshold=1, reset_s=0.05)
    cb.record_failure()
    time.sleep(0.06)
    cb.allow()  # half-open
    cb.record_failure()  # probe fails
    assert cb.state == OPEN
