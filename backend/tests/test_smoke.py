"""Milestone 0 smoke tests: the package imports, the API boots, metrics are
exposed, and the CLI runs — all without any datastore."""

from __future__ import annotations

from typer.testing import CliRunner

from sentinel import __version__
from sentinel.cli.main import app as cli_app
from sentinel.config import settings


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["name"] == "SentinelLite"


def test_metrics_exposes_sentinel_series(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "sentinel_alerts_ingested_total" in r.text


def test_settings_defaults_are_zero_cost():
    # The zero-cost promise: defaults need no accounts/keys.
    assert settings.llm_provider == "ollama"
    assert settings.action_dry_run is True
    assert settings.airgap_mode is False
    assert settings.openai_api_key is None


def test_severity_helper():
    assert settings.sev_at_or_below("low", "low") is True
    assert settings.sev_at_or_below("high", "low") is False


def test_cli_version():
    result = CliRunner().invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
