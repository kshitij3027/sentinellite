"""Shared pytest fixtures. Integration tests (needing live datastores) are
marked with @pytest.mark.integration; `make test-unit` skips them."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import app


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "integration: needs live datastores (postgres/neo4j/redis/ollama)")


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
