"""Emit a replay scenario to the control plane over HTTP, paced by t_offset,
then wait for the resulting investigation. Synchronous (driven by the CLI)."""

from __future__ import annotations

import time
from typing import Callable

import httpx

from sentinel.replay.scenario import build_teampcp, scenario_stats

SCENARIOS = {"teampcp": build_teampcp}


def run_replay(
    scenario: str,
    *,
    api_base: str,
    tenant: str = "default",
    speed: float = 1.0,
    noise: int = 42,
    on_event: Callable[[dict, int], None] | None = None,
) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario '{scenario}'; known: {list(SCENARIOS)}")
    events = SCENARIOS[scenario](noise_count=noise)
    stats = scenario_stats(events)

    emitted = 0
    with httpx.Client(timeout=30) as client:
        prev_t = 0
        for e in events:
            delay = (e["t"] - prev_t) / max(speed, 1e-6)
            if delay > 0:
                time.sleep(delay)
            prev_t = e["t"]
            headers = {"X-Tenant-Id": tenant, "X-Scenario": scenario, "X-Replay-Offset": str(e["t"])}
            if e.get("event_name"):
                headers["X-GitHub-Event"] = e["event_name"]
            try:
                r = client.post(f"{api_base}/ingest/{e['source']}", json=e["payload"], headers=headers)
                code = r.status_code
            except Exception:
                code = 0
            emitted += 1
            if on_event:
                on_event(e, code)
    return {"scenario": scenario, "emitted": emitted, "stats": stats, "tenant": tenant}


def wait_for_investigation(api_base: str, tenant: str, *, timeout_s: float = 200.0,
                           min_stages: int = 4, expected_escalations: int = 0) -> dict | None:
    """Poll until the incident SETTLES. We require that (a) every expected
    malicious alert has actually escalated, and (b) the investigation is
    awaiting_approval with (stage_count, action_count) unchanged across two
    polls — so we never print a half-built kill chain during the natural gap
    between attack phases (the pipeline is eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    headers = {"X-Tenant-Id": tenant}
    with httpx.Client(timeout=15) as client:
        last_id = None
        prev_key = None
        stable = 0
        while time.monotonic() < deadline:
            try:
                alerts = client.get(f"{api_base}/alerts?limit=300", headers=headers).json().get("alerts", [])
                escalated = sum(1 for a in alerts if a["status"] == "escalated")
                invs = client.get(f"{api_base}/investigations", headers=headers).json().get("investigations", [])
                if invs:
                    inv = invs[0]
                    last_id = inv["id"]
                    acts = client.get(f"{api_base}/actions?investigation_id={inv['id']}",
                                      headers=headers).json().get("count", 0)
                    key = (inv.get("stage_count", 0), acts)
                    ready = (
                        inv.get("status") == "awaiting_approval"
                        and inv.get("stage_count", 0) >= min_stages
                        and escalated >= expected_escalations
                    )
                    if ready and key == prev_key:
                        stable += 1
                        # ~12s of no growth after all malicious escalated: the
                        # debounced correlator has caught up to the full chain.
                        if stable >= 4:
                            return client.get(f"{api_base}/investigations/{inv['id']}", headers=headers).json()
                    else:
                        stable = 0
                    prev_key = key
            except Exception:
                pass
            time.sleep(3)
        if last_id:
            return client.get(f"{api_base}/investigations/{last_id}", headers=headers).json()
        return None
