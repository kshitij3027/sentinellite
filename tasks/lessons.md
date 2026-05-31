# Lessons

Patterns learned from corrections and mistakes. Reviewed at session start.

## Environment / infra
- The working folder lives inside a parent git repo rooted at `/Users/kshitij`
  (home dir). Always run git from this folder so ops hit the local nested `.git`,
  never the parent. Never `git add` paths outside this folder.
- Ollama in Docker on macOS is **CPU-only** (no Metal/GPU). Keep the default
  model small (`qwen2.5:1.5b-instruct`) and minimize LLM calls on the hot path.

## Agents / LLM (pydantic-ai 1.104 + Ollama)
- Small models (qwen2.5:1.5b) FAIL pydantic-ai's default tool-call structured
  output ("Exceeded maximum output retries"). Use `NativeOutput(Schema)` — it
  maps to Ollama's grammar-constrained JSON schema and is reliable even at 1.5b
  (~6s/call on CPU). `PromptedOutput` also works as a fallback.
- Use `OpenAIChatModel` (not deprecated `OpenAIModel`) with
  `OpenAIProvider(base_url=OLLAMA_HOST+'/v1', api_key='ollama')`.
- Result: `await agent.run(p)` → `r.output`; token usage via `r.usage()`.
- Budget: don't LLM every alert. Deterministic noise-filter auto-closes obvious
  benign events; the Pydantic-AI triage agent runs only on interesting ones.
  Keeps SC1 (<3 min) achievable and mirrors real SOC rule-then-analyst flow.

## Pipeline correctness must not depend on the LLM keeping up (M4)
- On CPU Ollama, concurrent LLM calls (triage + 3 domain agents + correlator)
  contend and TIME OUT, making investigation runs slow so the kill chain lags
  behind attached alerts. Fix: persist the DETERMINISTIC kill chain + staged
  actions FIRST and fast; run LLM narratives best-effort with short timeouts
  (investigation_agent_timeout_s). The headline output is always correct; the
  LLM only enriches the prose.
- Incident grouping: match OPEN investigations in status (running OR
  awaiting_approval) — else alerts arriving after the first action-staging
  fragment into new investigations. [[]]
- Noise filter: low/info, non-suspicious-IP, no-threat-indicator alerts are
  auto-closable even if they nominally map to a MITRE technique (benign
  AssumeRole reads) — don't gate noise on `classify()` being empty.

## (add new lessons below as corrections happen)
