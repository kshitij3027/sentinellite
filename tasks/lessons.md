# Lessons

Patterns learned from corrections and mistakes. Reviewed at session start.

## Environment / infra
- The working folder lives inside a parent git repo rooted at `/Users/kshitij`
  (home dir). Always run git from this folder so ops hit the local nested `.git`,
  never the parent. Never `git add` paths outside this folder.
- Ollama in Docker on macOS is **CPU-only** (no Metal/GPU). Keep the default
  model small (`qwen2.5:1.5b-instruct`) and minimize LLM calls on the hot path.

## (add new lessons below as corrections happen)
