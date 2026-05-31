"""Threat-intel enrichment via OSV.dev (TI1, Tier-0: fully anonymous, no key).
Used by the SupplyChain agent to confirm a compromised dependency's CVE. Honors
AIRGAP_MODE (MT2) — no external calls when air-gapped."""

from __future__ import annotations

import re

import httpx

from sentinel.config import settings
from sentinel.logging import get_logger

log = get_logger("osv")

OSV_QUERY = "https://api.osv.dev/v1/query"
_PKG_RE = re.compile(r"([A-Za-z0-9_.\-]+)@(\d+\.\d+\.\d+)")


async def query_osv(name: str, version: str | None = None, ecosystem: str = "npm") -> list[dict]:
    if settings.airgap_mode:
        return []
    body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(OSV_QUERY, json=body)
            r.raise_for_status()
            vulns = r.json().get("vulns", [])
        return [{"id": v.get("id"), "summary": v.get("summary", ""), "aliases": v.get("aliases", [])}
                for v in vulns][:5]
    except Exception as exc:
        log.warning("osv.query_failed", name=name, error=str(exc)[:120])
        return []


def _package_from(alert) -> tuple[str, str] | None:
    if alert.package and "@" in alert.package:
        n, _, v = alert.package.partition("@")
        return n, v
    m = _PKG_RE.search(str(alert.raw))
    return (m.group(1), m.group(2)) if m else None


async def enrich_packages(alerts: list) -> list[dict]:
    """Return CVE/GHSA IOCs for any compromised packages referenced by the alerts."""
    seen: set[str] = set()
    iocs: list[dict] = []
    for a in alerts:
        pkg = _package_from(a)
        if not pkg or pkg[0] in seen:
            continue
        seen.add(pkg[0])
        for vuln in await query_osv(pkg[0], pkg[1]):
            iocs.append({"type": "cve", "value": vuln["id"], "summary": vuln["summary"],
                         "aliases": vuln["aliases"], "package": f"{pkg[0]}@{pkg[1]}"})
    return iocs
