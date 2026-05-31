#!/usr/bin/env bash
# SC2: prove the system runs end-to-end on a FRESH slate with NO API keys and
# NO accounts. Wipes all volumes (incl. the Ollama model), rebuilds, brings the
# stack up with default (zero-cost) config, fetches/verifies datasets, replays
# the teampcp attack, and asserts a complete kill chain + staged actions + a
# verified audit chain.
set -euo pipefail
cd "$(dirname "$0")/.."

TENANT="smoketest"
API="http://localhost:8000"

echo "==> [1/6] Fresh slate: docker compose down -v (wipes volumes incl. model)"
docker compose down -v --remove-orphans

echo "==> [2/6] Bring up the full stack with default zero-cost config (no .env keys)"
# Intentionally do NOT source any API keys — defaults must suffice (the zero-cost promise).
docker compose up -d --build

echo "==> [3/6] Wait for readiness (first run pulls the Ollama model, be patient)..."
ready=""
for _ in $(seq 1 200); do
  if curl -sf "$API/readyz" 2>/dev/null | grep -q '"ready":true'; then ready=1; echo "    api ready."; break; fi
  sleep 3
done
[ -n "$ready" ] || { echo "FAIL: api never became ready"; docker compose logs --tail=40 api worker; exit 1; }

echo "==> [4/6] Verify the bundled curated datasets (checksums)"
docker compose run --rm --no-deps api sentinel datasets verify

echo "==> [5/6] Replay the teampcp supply-chain attack (tenant=$TENANT)"
docker compose run --rm --no-deps api sentinel attack replay teampcp --tenant "$TENANT" --speed 6 --no-wait
echo "    waiting for the worker to triage + investigate..."

echo "==> [6/6] Assert outcomes (kill chain >= 4 stages, >= 3 actions, audit ok)"
docker compose run --rm --no-deps api python - "$TENANT" <<'PY'
import sys, time, httpx
tenant = sys.argv[1]
H = {"X-Tenant-Id": tenant}
B = "http://api:8000"
# The pipeline is eventually consistent (debounced investigation), so poll until
# the incident SETTLES: all malicious alerts escalated, kill chain >= 4 stages,
# and >= 3 response actions staged. (The AWS-stage actions land last.)
deadline = time.time() + 300
inv, acts, escalated, auto_closed = None, 0, 0, 0
while time.time() < deadline:
    try:
        alerts = httpx.get(f"{B}/alerts?limit=300", headers=H, timeout=15).json()["alerts"]
        escalated = sum(1 for a in alerts if a["status"] == "escalated")
        auto_closed = sum(1 for a in alerts if a["status"] == "auto_closed")
        invs = httpx.get(f"{B}/investigations", headers=H, timeout=15).json()["investigations"]
        if invs:
            cand = invs[0]
            a = httpx.get(f"{B}/actions?investigation_id={cand['id']}", headers=H, timeout=15).json()["count"]
            if cand["stage_count"] >= 4 and cand["status"] == "awaiting_approval" and escalated >= 8 and a >= 3:
                inv, acts = cand, a
                break
    except Exception:
        pass
    time.sleep(4)
assert inv, "FAIL: incident did not settle (need stages>=4, escalated>=8, actions>=3) in time"
ver = httpx.get(f"{B}/audit/verify", headers=H, timeout=15).json()
assert acts >= 3, f"FAIL: expected >=3 staged actions, got {acts}"
assert ver.get("ok"), f"FAIL: audit chain not ok: {ver}"
print(f"\nSMOKETEST PASS  inv={inv['id']}  stages={inv['stage_count']}  "
      f"actions={acts}  auto_closed={auto_closed}/{auto_closed + escalated}  audit_ok={ver['ok']}")
PY

echo ""
echo "✅ smoketest-fresh PASSED — zero accounts, zero API keys, end to end."
