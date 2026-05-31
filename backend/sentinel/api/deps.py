"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Header


def tenant_id(x_tenant_id: str = Header(default="default", alias="X-Tenant-Id")) -> str:
    """Multi-tenancy (MT1): the tenant scope for this request."""
    return x_tenant_id or "default"
