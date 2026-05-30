<div align="center">

# 🛡️ SentinelLite

**A self-hostable, $0 mini Autonomous SOC — tested against real public attack data, not data I made up.**

</div>

> [!NOTE]
> **Status: under active construction.** This README documents the target system;
> sections fill in as milestones land. See [`tasks/todo.md`](tasks/todo.md) for the live build plan.

SentinelLite ingests a startup's dev-stack telemetry (GitHub, AWS CloudTrail, Okta,
Falco) in each vendor's **native schema**, correlates entities in a **Neo4j security
graph**, runs **specialized AI agents in parallel** to triage and investigate, and
stages **one-click response actions behind a human-approval gate** — demonstrated
against a scripted supply-chain attack replay built from **real public attack datasets**.

```bash
docker compose up
sentinel datasets fetch          # public datasets, checksum-verified (a curated subset ships in-repo)
sentinel attack replay teampcp   # watch a supply-chain kill chain reconstruct live, < 3 min
```

## The zero-cost promise

> SentinelLite runs end-to-end via `docker compose up` with zero accounts, zero API
> keys, and zero payment, using **Ollama** as the local LLM backend and public attack
> datasets (flaws.cloud, Splunk Attack Data, GitHub Advisory DB) as the demo corpus.
> Hosted LLM providers, live cloud integrations, and threat-intel enrichments are
> opt-in and gated behind environment variables.

## Architecture (at a glance)

```
              ┌────────────┐   native-schema alerts   ┌──────────────────────┐
  CLI replay  │  /ingest/  │ ───────────────────────► │  Detection rules      │
  & live      │  {source}  │                          │  (Sigma-style YAML)   │
  integrations└────────────┘                          └─────────┬────────────┘
                                                                │
   Neo4j security graph  ◄───── hydrate entities ───────────────┤
   (Identity/Asset/Process/Package/IP/...)                      ▼
                                                       ┌──────────────────┐
                                                       │  TriageAgent      │  Severity / Confidence / Priority
                                                       └────────┬─────────┘  + chain-of-thought + evidence
                                            auto-close  ◄────────┤
                                                        escalate ▼
                                   ┌────────── asyncio.gather ───────────┐
                                   │ IdentityAgent EndpointAgent          │
                                   │              SupplyChainAgent         │
                                   └──────────────────┬───────────────────┘
                                                      ▼
                                            ┌──────────────────┐
                                            │ CorrelatorAgent   │  kill-chain timeline + MITRE ATT&CK IDs
                                            └────────┬─────────┘
                                                     ▼
                              Staged response actions  ──►  Human approval gate  ──►  dry-run executors
                                                     │
                                                     ▼
                                      Immutable audit log (SHA-256 hash chain)
```

Everything is observable: Prometheus metrics, a provisioned Grafana dashboard,
`structlog` JSON, and Server-Sent Events streaming live agent traces to a Next.js dashboard.

## Why I built this

I haven't worked in a SOC. I built a small one to learn how an autonomous-SOC vendor's
claims actually hold up — and I tested it against **real attack data**, not data I made up.

This project is a homage to the graph-first, six-stage autonomous-SOC architecture
pioneered by companies like Alaris; it is a **single-tenant educational reimplementation**,
not a competitor.

_Role map, demo screencap, and the kill-chain walkthrough land here as the build completes._

## License

[MIT](LICENSE)
