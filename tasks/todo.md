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

## Milestone 1 — Backend data plane (R1, R2, R9)  ✅ DONE
- [x] FastAPI app skeleton + structured logging (structlog) + settings
- [x] Pydantic source schemas: github, aws_cloudtrail, okta_system_log, falco
- [x] Postgres models (alerts, triage, investigations, findings, actions, audit) + pgvector col
- [x] Schema bootstrap via metadata.create_all + pgvector extension (no Alembic for MVP)
- [x] Neo4j graph hydration (8 node labels + 5 domain rels + OBSERVED + CORRELATES_WITH)
- [x] `POST /ingest/{source}` + `GET /alerts`, `/alerts/{id}`, `/audit`, `/audit/verify`, `/readyz`
- [x] Audit log w/ SHA-256 hash chain (advisory-lock serialized) + tamper detection
- [x] 35 tests pass in Docker (schemas, hash chain unit + integration: ingest/graph/audit/tamper)

## Milestone 2 — Agents & triage (R3, R4, R5, R6)  ✅ DONE
- [x] LLM provider abstraction (ollama default) — NativeOutput for reliable small-model JSON
- [x] TriageAgent: Severity/Confidence/Priority + CoT + evidence (persisted); two-stage
      (deterministic noise filter + LLM for interesting alerts) for SC1 budget
- [x] Auto-close vs escalate per R4 (confidence>=0.9 AND severity<=low), configurable
- [x] Parallel investigation: Identity/Endpoint/SupplyChain via asyncio.gather (R5)
- [x] CorrelatorAgent: kill-chain timeline w/ verified MITRE IDs + graph-path citation (R6)
- [x] Circuit breaker per agent (OB4) + debounced investigation scheduling (decoupled worker)
- [x] mitre.py catalog + classifier; detection/indicators.py threat+noise heuristics
- [x] 49 tests green; live e2e: 7-stage kill chain, rich domain findings, scores 100/100/92

## Milestone 3 — Response actions & approval gate (R7, R8)  ✅ DONE
- [x] Action generation w/ pre-filled params + rationale (IOC->action mapping, deduped)
- [x] Typed executors (dry-run by default; live deliberately unconfigured in MVP)
- [x] Two-tier blocklist (revoke_aws_keys/delete_iam_user need confirm=true)
- [x] `POST /actions/{id}/approve|reject` (+ ?confirm), GET /actions[/id], approval-timeout sweep
- [x] Wired into investigation (post-correlate -> awaiting_approval); 57 tests green

## Milestone 4 — CLI & datasets (R11, R12)  ✅ DONE
- [x] `sentinel` CLI (typer + rich): version, datasets verify/fetch, attack replay
- [x] `sentinel datasets fetch` w/ sha256 checksum verification; AIRGAP-aware
- [x] Curated real-dataset subset bundled (~780KB: Splunk attack_data, GHSA lodash, invictus)
- [x] `sentinel attack replay teampcp` — dataset-backed 8-stage chain over ~3 min
- [x] Provenance metadata (real datasets cited) on the investigation
- [x] **Validated live: 8-stage MITRE kill chain, 84% noise auto-closed, 5 staged actions,
      audit ok — SC1/SC3/SC4/SC5/SC6 all demonstrated. 62 tests green.**

## Milestone 5 — Dashboard (R10)
- [ ] Next.js 15 + tailwind + shadcn/ui + react-query
- [ ] Alert Queue view (Severity/Confidence/Priority)
- [ ] Investigation Detail: attack graph (react-force-graph-2d) + agent timeline (SSE)
- [ ] Pending Actions view (approve/reject + reasoning)
- [ ] Audit Log view w/ hash-chain status badge

## Milestone 6 — Observability (OB1–OB4)  ✅ DONE
- [x] Prometheus metrics (all 6 headline signals + supporting), scraped from BOTH
      api:8000 and worker:9100 (worker exposes its own /metrics)
- [x] Provisioned Grafana OSS dashboard — 9 panels, anonymous access, live data verified
- [x] structlog JSON (M1) + circuit breaker (OB4, M2); hash-chain-breaks gauge wired
- [x] Verified: both scrape targets up; 42 auto-closed/8 escalated/4281 tokens in Prometheus

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
