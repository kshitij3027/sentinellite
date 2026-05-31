"""MITRE ATT&CK technique catalog + a deterministic classifier mapping a
normalized alert to technique IDs. IDs/names verified at attack.mitre.org.

`stage` is the narrative kill-chain label shown in the timeline (R6); it tracks
the PRD's sample output. Tactic-accuracy note: T1530 is officially under the
Collection tactic — we display it as the data-theft / "Exfiltration" stage for
narrative clarity while keeping the correct technique ID."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    stage: str  # narrative kill-chain stage


CATALOG: dict[str, Technique] = {
    "T1195.002": Technique("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access"),
    "T1059.004": Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1552.001": Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1567.002": Technique("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    "T1078.004": Technique("T1078.004", "Valid Accounts: Cloud Accounts", "Lateral Movement"),
    "T1087.004": Technique("T1087.004", "Account Discovery: Cloud Account", "Discovery"),
    "T1098.001": Technique("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence"),
    "T1530": Technique("T1530", "Data from Cloud Storage", "Exfiltration"),
}

# kill-chain ordering for sorting timeline stages with equal timestamps
STAGE_ORDER = [
    "Initial Access", "Execution", "Credential Access", "Discovery",
    "Lateral Movement", "Persistence", "Collection", "Exfiltration",
]

_RECON_EVENTS = {"ListUsers", "ListRoles", "GetCallerIdentity", "ListAccessKeys", "ListBuckets"}
_SENSITIVE_HINTS = ("pii", "customer", "secret", "credential", "backup", "prod-data")


def classify(alert) -> list[str]:
    """Return MITRE technique IDs implied by this alert (primary first)."""
    et = alert.source_event_type or ""
    src = alert.source
    proc = (alert.process or "").lower()
    pkg = alert.package
    out: list[str] = []

    if src == "github":
        raw_blob = str(alert.raw).lower()
        if pkg or any(k in et.lower() for k in ("package", "advisory", "dependabot", "vuln")) or \
           any(k in raw_blob for k in ("postinstall", "ghsa-", "package.json", "lockfile")):
            out.append("T1195.002")
    elif src == "falco":
        name = et.lower()
        if "credential" in name or ".aws/credentials" in proc or "akia" in proc or "/etc/shadow" in proc:
            out.append("T1552.001")
        if "shell" in name or "terminal" in name or proc.startswith(("sh ", "bash", "sh -c")):
            out.append("T1059.004")
        if any(k in name for k in ("outbound", "netcat", "exfil", "remote")) or "nc " in proc:
            out.append("T1567.002")
    elif src == "aws_cloudtrail":
        ev = et.split(":")[-1]
        if ev == "CreateAccessKey":
            out.append("T1098.001")
        elif ev == "AssumeRole":
            out.append("T1078.004")
        elif ev in _RECON_EVENTS:
            out.append("T1087.004")
        elif ev == "GetObject":
            cr = (alert.cloud_resource or "").lower()
            if any(h in cr for h in _SENSITIVE_HINTS):
                out.append("T1530")
    return out


def primary_technique(alert) -> Technique | None:
    ids = classify(alert)
    return CATALOG.get(ids[0]) if ids else None
