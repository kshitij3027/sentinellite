"""Prometheus metrics (OB1). Six headline signals plus supporting counters.

Exposed at GET /metrics on the API. The provisioned Grafana dashboard reads these."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# 1. alerts ingested
ALERTS_INGESTED = Counter(
    "sentinel_alerts_ingested_total", "Alerts ingested", ["source", "tenant"]
)
# 2. mean-time-to-triage
TRIAGE_LATENCY = Histogram(
    "sentinel_triage_latency_seconds",
    "Time from ingest to triage decision",
    ["tenant"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
)
# 3. mean-time-to-investigate
INVESTIGATION_LATENCY = Histogram(
    "sentinel_investigation_latency_seconds",
    "Time to complete a parallel investigation",
    ["tenant"],
    buckets=(0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300),
)
# 4. agent token spend per investigation
AGENT_TOKENS = Counter(
    "sentinel_agent_tokens_total", "LLM tokens consumed", ["agent", "tenant"]
)
# 5. action approval latency
APPROVAL_LATENCY = Histogram(
    "sentinel_action_approval_latency_seconds",
    "Time from action staged to approve/reject",
    ["decision", "tenant"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 900, 1800),
)
# 6. hash-chain breaks
HASHCHAIN_BREAKS = Gauge(
    "sentinel_audit_hashchain_breaks", "Broken links found by /audit/verify", ["tenant"]
)

# --- supporting ---
ALERTS_AUTOCLOSED = Counter(
    "sentinel_alerts_autoclosed_total", "Alerts auto-closed by triage", ["tenant"]
)
ALERTS_ESCALATED = Counter(
    "sentinel_alerts_escalated_total", "Alerts escalated to investigation", ["tenant"]
)
ACTIONS_STAGED = Counter(
    "sentinel_actions_staged_total", "Response actions staged", ["type", "tenant"]
)
ACTIONS_EXECUTED = Counter(
    "sentinel_actions_executed_total", "Response actions executed", ["type", "dry_run", "tenant"]
)
AGENT_RUNS = Counter(
    "sentinel_agent_runs_total", "Agent invocations", ["agent", "outcome", "tenant"]
)
BREAKER_STATE = Gauge(
    "sentinel_circuit_breaker_open", "1 if an agent circuit breaker is open", ["agent"]
)
QUEUE_DEPTH = Gauge("sentinel_queue_depth", "Pending items in a worker queue", ["queue"])
