"""LLM access for agents. Pydantic-AI agents with NativeOutput (Ollama
grammar-constrained JSON — reliable even on small local models). Provider is
configurable; AIRGAP_MODE forces the local Ollama backend and blocks any
external endpoint."""

from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import TypeVar

from pydantic import BaseModel
from pydantic_ai import Agent, NativeOutput
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from sentinel.agents.breaker import get_breaker
from sentinel.config import settings
from sentinel.logging import get_logger
from sentinel.metrics import AGENT_RUNS, AGENT_TOKENS

log = get_logger("llm")

T = TypeVar("T", bound=BaseModel)


@lru_cache(maxsize=8)
def build_model():
    """Return a pydantic-ai model for the configured provider."""
    provider = settings.llm_provider
    # Air-gap (MT2): never reach an external API — local Ollama only.
    if settings.airgap_mode or provider == "ollama":
        base = settings.ollama_host.rstrip("/") + "/v1"
        return OpenAIChatModel(settings.llm_model, provider=OpenAIProvider(base_url=base, api_key="ollama"))
    if provider == "openrouter":
        return OpenAIChatModel(
            settings.llm_model,
            provider=OpenAIProvider(
                base_url="https://openrouter.ai/api/v1", api_key=settings.openrouter_api_key or ""
            ),
        )
    if provider == "openai":
        return OpenAIChatModel(settings.llm_model, provider=OpenAIProvider(api_key=settings.openai_api_key or ""))
    if provider == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(settings.llm_model, provider=AnthropicProvider(api_key=settings.anthropic_api_key or ""))
    raise ValueError(f"unknown LLM_PROVIDER: {provider}")


@lru_cache(maxsize=32)
def build_agent(output_type: type[T], instructions: str, name: str, max_tokens: int = 0) -> Agent:
    return Agent(
        build_model(),
        output_type=NativeOutput(output_type),
        instructions=instructions,
        model_settings={"temperature": 0.0, "max_tokens": max_tokens or settings.llm_max_tokens},
        retries=2,
        name=name,
    )


def _tokens(result) -> int:
    try:
        u = result.usage  # property in pydantic-ai 1.x (was a method in 0.x)
        if callable(u):
            u = u()
        return int(getattr(u, "total_tokens", 0) or 0)
    except Exception:
        return 0


async def run_agent(
    *,
    output_type: type[T],
    instructions: str,
    prompt: str,
    name: str,
    tenant_id: str = "default",
    max_tokens: int = 0,
    timeout: float | None = None,
) -> tuple[T | None, int]:
    """Run an agent with circuit-breaker + timeout. Returns (output|None, tokens).
    None means the caller should fall back to its deterministic path."""
    breaker = get_breaker(name)
    if not breaker.allow():
        log.warning("agent.breaker_open", agent=name)
        AGENT_RUNS.labels(agent=name, outcome="skipped_open", tenant=tenant_id).inc()
        return None, 0

    agent = build_agent(output_type, instructions, name, max_tokens)
    try:
        result = await asyncio.wait_for(
            agent.run(prompt), timeout=timeout or settings.agent_timeout_s
        )
        breaker.record_success()
        tokens = _tokens(result)
        if tokens:
            AGENT_TOKENS.labels(agent=name, tenant=tenant_id).inc(tokens)
        AGENT_RUNS.labels(agent=name, outcome="ok", tenant=tenant_id).inc()
        return result.output, tokens
    except (TimeoutError, asyncio.TimeoutError):
        breaker.record_failure()
        log.warning("agent.timeout", agent=name)
        AGENT_RUNS.labels(agent=name, outcome="timeout", tenant=tenant_id).inc()
        return None, 0
    except Exception as exc:
        breaker.record_failure()
        log.warning("agent.error", agent=name, error=str(exc)[:200])
        AGENT_RUNS.labels(agent=name, outcome="error", tenant=tenant_id).inc()
        return None, 0
