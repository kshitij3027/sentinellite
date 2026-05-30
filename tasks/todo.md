# SentinelLite — Build Plan

> A self-hostable mini Autonomous SOC. Ingests dev-stack telemetry (GitHub, AWS
> CloudTrail, Okta, Falco), correlates entities in a Neo4j security graph, runs
> parallel AI agents (Ollama) to triage + investigate, and stages one-click
> response actions behind a human approval gate — demoed against real public
> attack datasets.

**Hard constraints (from the goal):**
- Everything (dev + test) runs in Docker. Nothing installed/run on host but Docker.
- Local git repo here + remote on GitHub; commit & push every increment.
- Use subagents liberally to keep main context clean.
- Only touch files inside this working folder.
- Stop & ask only if a website login/permission is needed.

**Key decisions made:**
- Default demo model = `qwen2.5:1.5b-instruct` (fast on CPU-only Docker on Mac).
  `qwen2.5:7b-instruct` stays one env-var away (`LLM_MODEL`).
- Graph DB = Neo4j 5 Community (per spec).
- Agent runtime = Pydantic AI (no LangGraph for MVP).
- Multi-tenant schema from day one (`tenant_id` everywhere), single-tenant behavior.
- Triage = detection rules (Sigma-style) do cheap filtering; LLM does reasoning/scoring.
- Repo is **private** initially (flip to public when demo-ready).

---

## Milestone 0 — Foundation & scaffolding  ✅ DONE
- [x] Assess env (git/docker/gh/resources)
- [x] `.gitignore`
- [x] `tasks/todo.md` + `tasks/lessons.md`
- [x] README skeleton + LICENSE (MIT)
- [x] Monorepo layout: `backend/`, `datasets/`, `rules/`, `deploy/` (dashboard/ in M5, verification/ in M8)
- [x] `git init` + first commit
- [x] `gh repo create` **public** + push → https://github.com/kshitij3027/sentinellite
- [x] `.env.example` with all configurable params
- [x] `docker-compose.yml` (8 services) + healthchecks + dependency ordering
- [x] `Makefile` (up/down/test/fetch/replay/smoketest-fresh)
- [x] Backend skeleton (config/logging/metrics/api/worker/cli) + 6 smoke tests passing
- [x] **Validated: full stack boots healthy in Docker; model pulled; all endpoints green**

## Milestone 1 — Backend data plane (R1, R2, R9)
- [ ] FastAPI app skeleton + structured logging (structlog) + settings
- [ ] Pydantic source schemas: github, aws_cloudtrail, okta_system_log, falco
- [ ] Postgres models (alerts, investigations, actions, audit_events) + pgvector
- [ ] Alembic-style migrations / init SQL
- [ ] Neo4j graph hydration (nodes + edges per R2)
- [ ] `POST /ingest/{source}` endpoints
- [ ] Audit log w/ SHA-256 hash chain + `GET /audit/verify`
- [ ] Backend tests in Docker (pytest) — schemas, ingestion, hash chain

## Milestone 2 — Agents & triage (R3, R4, R5, R6)
- [ ] Ollama client + LLM provider abstraction (ollama/openrouter/openai/anthropic)
- [ ] TriageAgent: Severity/Confidence/Priority + CoT + evidence (persisted)
- [ ] Auto-close vs escalate (configurable thresholds)
- [ ] Parallel investigation: Identity / Endpoint / SupplyChain via asyncio.gather
- [ ] CorrelatorAgent: merge findings, walk graph, kill-chain timeline w/ MITRE IDs
- [ ] Circuit breaker per agent (OB4)
- [ ] Tests (mock LLM for determinism)

## Milestone 3 — Response actions & approval gate (R7, R8)
- [ ] Action generation w/ pre-filled params
- [ ] Typed executors (dry-run by default; per-executor live flag)
- [ ] Two-tier blocklist (irreversible actions need 2nd confirm)
- [ ] `POST /actions/{id}/approve|reject` + approval timeout
- [ ] Tests

## Milestone 4 — CLI & datasets (R11, R12)
- [ ] `sentinel` CLI (typer)
- [ ] `sentinel datasets fetch` w/ checksum verification
- [ ] Curated ~50MB subset bundled in repo (offline demo)
- [ ] `sentinel attack replay teampcp` (real dataset-backed sequence, ~3 min)
- [ ] Provenance metadata on every replay

## Milestone 5 — Dashboard (R10)
- [ ] Next.js 15 + tailwind + shadcn/ui + react-query
- [ ] Alert Queue view (Severity/Confidence/Priority)
- [ ] Investigation Detail: attack graph (react-force-graph-2d) + agent timeline (SSE)
- [ ] Pending Actions view (approve/reject + reasoning)
- [ ] Audit Log view w/ hash-chain status badge

## Milestone 6 — Observability (OB1–OB4)
- [ ] Prometheus metrics (6 panels worth)
- [ ] Provisioned Grafana OSS dashboard (JSON)
- [ ] structlog JSON (done in M1) + optional LangSmith flag

## Milestone 7 — Extended (as time allows)
- [ ] DE1–DE3 detection rules + 20 starter detections + DetectionTunerAgent
- [ ] TI1–TI3 threat-intel enrichment (OSV.dev tier-0 default)
- [ ] MT1–MT2 multi-tenancy + air-gap mode
- [ ] LI1–LI4 live integrations (opt-in stubs)
- [ ] Stretch: B2 okta-breach replay, B3 eval harness, B4 PDF report, B6 flaws-real

## Milestone 8 — End-to-end verification
- [ ] `verification/stories.yaml` (1–2 multi-step journeys)
- [ ] `docker compose up` → fetch → replay end-to-end < 3 min (SC1)
- [ ] `make smoketest-fresh` (SC2)
- [ ] `/ui-review` all stories pass
- [ ] README "Why I built this" + role mapping + zero-cost claim

---

## Review
_(filled in as milestones complete)_
