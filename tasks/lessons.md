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

## (add new lessons below as corrections happen)
