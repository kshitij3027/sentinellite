# Air-gap mode (MT2)

SentinelLite runs **fully offline** with no external network calls — the single
strongest hook for a sovereignty / government-defense deployment story.

## What `AIRGAP_MODE=true` enforces

When `AIRGAP_MODE=true`, the system makes **zero outbound network calls**:

| Subsystem | Normal | Air-gapped |
|---|---|---|
| LLM inference | configurable provider | **forced to local Ollama** (`build_model()` ignores any hosted provider) |
| Threat-intel (OSV.dev) | queried for package CVEs | **skipped** (`enrich_packages` returns nothing) |
| Dataset fetch | downloads public corpora | **skipped** (`datasets fetch` verifies the bundled curated subset only) |
| Tier-1 enrichers (VirusTotal, URLhaus) | opt-in | never called |
| Datastores (Postgres, Neo4j, Redis) | in-cluster | in-cluster (already local) |

Everything the demo needs — the model, the attack datasets, the security graph,
the agents — is already inside the Docker network or bundled in the repo.

## Runbook

1. **Before going dark**, pre-pull the model into the Ollama volume (this is the
   only thing that needs the internet, and only once):
   ```bash
   docker compose up -d ollama
   docker compose run --rm ollama-init      # pulls $LLM_MODEL into the ollamadata volume
   ```
   The curated attack datasets are already committed under `datasets/curated/`,
   so no dataset download is required.

2. **Enable air-gap mode** in `.env`:
   ```ini
   AIRGAP_MODE=true
   LLM_PROVIDER=ollama
   ```

3. **Bring up the stack and replay** — entirely offline:
   ```bash
   docker compose up -d
   docker compose run --rm api sentinel datasets verify   # confirms the bundled subset is intact
   make replay                                            # full kill-chain reconstruction, no internet
   ```

4. **Verify isolation** (optional): run the stack on a Docker network with no
   egress, or pull the host's network — the replay still produces the complete
   8-stage kill chain, staged actions, and a verified audit chain.

## Notes

- Hosted LLM providers, live cloud integrations (AWS/Okta/GitHub/Falco), and
  Tier-1 threat intel are all opt-in and gated behind environment variables; none
  are required, and all are suppressed under `AIRGAP_MODE`.
- Multi-tenancy (MT1) is independent of air-gap: every node and row already
  carries `tenant_id`, so a single air-gapped deployment can still isolate tenants.
