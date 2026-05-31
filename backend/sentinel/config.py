"""Central configuration. Every tunable from the PRD's parameter table lives here.

All values are environment-overridable. Defaults are chosen so the system runs
end-to-end with zero accounts / zero API keys (the zero-cost promise)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel.types import SEVERITY_RANK, Severity


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # --- LLM / agents ---
    llm_provider: Literal["ollama", "openrouter", "openai", "anthropic"] = "ollama"
    llm_model: str = "qwen2.5:1.5b-instruct"
    ollama_host: str = "http://ollama:11434"
    openrouter_api_key: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # --- triage thresholds (R4) ---
    triage_autoclose_conf: float = 0.90
    triage_autoclose_max_sev: Severity = "low"

    # --- triage LLM policy ---
    triage_llm_all: bool = False  # False: LLM only for non-noise alerts (fast). True: every alert.
    llm_max_tokens: int = 700

    # --- investigation (R5/R6) ---
    investigation_parallelism: int = 3
    investigation_budget_tokens: int = 30_000
    investigation_debounce_s: float = 6.0  # quiet period before running a (re)investigation
    worker_poll_dirty_s: float = 2.0
    agent_timeout_s: float = 45.0
    # circuit breaker (OB4)
    breaker_fail_threshold: int = 3
    breaker_reset_s: float = 30.0

    # --- actions / approval (R7/R8) ---
    action_dry_run: bool = True
    approval_timeout_min: int = 30

    # --- multi-tenancy (MT1) ---
    tenant_id: str = "default"

    # --- air-gap (MT2) ---
    airgap_mode: bool = False

    # --- paths ---
    rules_dir: str = "/app/rules"
    replay_data_dir: str = "/app/datasets"

    # --- source mode ---
    alert_source_mode: Literal["replay", "live"] = "replay"

    # --- datastores ---
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "change-me-please"
    postgres_dsn: str = "postgresql+asyncpg://sentinel:sentinel@postgres/sentinel"
    redis_url: str = "redis://redis:6379/0"

    # --- observability ---
    enable_langsmith: bool = False
    langsmith_api_key: str | None = None
    log_level: str = "INFO"
    log_json: bool = True

    # --- threat intel (TI1) ---
    virustotal_api_key: str | None = None
    urlhaus_auth_key: str | None = None

    # --- bonus / live integrations (all opt-in) ---
    slack_webhook_url: str | None = None
    aws_live_enabled: bool = False
    github_pat: str | None = None
    okta_domain: str | None = None
    okta_api_token: str | None = None
    falco_live_enabled: bool = False

    # --- internal API base (CLI -> control plane) ---
    api_base_url: str = "http://api:8000"

    def sev_at_or_below(self, sev: str, ceiling: str) -> bool:
        return SEVERITY_RANK.get(sev, 99) <= SEVERITY_RANK.get(ceiling, 0)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
