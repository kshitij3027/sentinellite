"""Deterministic threat-indicator + noise evaluation. This is the fast, reliable
layer the triage agent leans on: it guarantees true-positive supply-chain alerts
escalate (SC3) and that obvious benign telemetry auto-closes without an LLM call.

The full Sigma rule engine (DE1-DE3) augments this in a later milestone."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.logging import get_logger
from sentinel.mitre import classify

log = get_logger("indicators")

# Known-bad source IPs. 185.220.101.0/24 is a real, well-known Tor exit block.
TOR_EXIT_PREFIXES = ("185.220.101.", "185.220.100.", "171.25.193.")
KNOWN_BAD_IPS: set[str] = set()

# Indicator labels that, if present, force escalation (high-fidelity threat).
THREAT_INDICATORS = {
    "tor_exit_ip", "supply_chain_compromise", "credential_theft", "shell_in_ci",
    "persistence_key", "role_assumption", "recon_from_bad_ip", "sensitive_bucket_exfil",
    "falco_critical",
}

_SENSITIVE_HINTS = ("pii", "customer", "secret", "credential", "backup", "prod-data")
_RECON = {"ListUsers", "ListRoles", "GetCallerIdentity", "ListAccessKeys"}


@dataclass
class Signal:
    matched: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    weight: int = 0  # 0-100 contribution toward severity/priority
    threat_flag: bool = False  # set by a matched medium+ detection rule
    rules: list[str] = field(default_factory=list)  # matched rule ids

    @property
    def threat(self) -> bool:
        return self.threat_flag or any(m in THREAT_INDICATORS for m in self.matched)

    @property
    def obvious_noise(self) -> bool:
        return not self.threat and "benign_pattern" in self.matched


def is_suspicious_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return ip in KNOWN_BAD_IPS or ip.startswith(TOR_EXIT_PREFIXES)


def evaluate(alert) -> Signal:
    sig = Signal(techniques=classify(alert))
    et = alert.source_event_type or ""
    src = alert.source
    proc = (alert.process or "").lower()
    cr = (alert.cloud_resource or "").lower()
    suspicious_ip = is_suspicious_ip(alert.source_ip)

    if suspicious_ip:
        sig.matched.append("tor_exit_ip")
        sig.weight += 45

    if src == "github" and ("T1195.002" in sig.techniques):
        sig.matched.append("supply_chain_compromise")
        sig.weight += 40
    elif src == "falco":
        if "T1552.001" in sig.techniques:
            sig.matched.append("credential_theft")
            sig.weight += 45
        if "T1059.004" in sig.techniques:
            sig.matched.append("shell_in_ci")
            sig.weight += 30
        if "T1567.002" in sig.techniques:
            sig.matched.append("credential_theft")
            sig.weight += 25
        if alert.severity_hint == "critical":
            sig.matched.append("falco_critical")
            sig.weight += 20
    elif src == "aws_cloudtrail":
        ev = et.split(":")[-1]
        if ev == "CreateAccessKey":
            sig.matched.append("persistence_key")
            sig.weight += 40
        elif ev == "AssumeRole" and suspicious_ip:
            sig.matched.append("role_assumption")
            sig.weight += 35
        elif ev in _RECON and suspicious_ip:
            sig.matched.append("recon_from_bad_ip")
            sig.weight += 30
        elif ev == "GetObject" and any(h in cr for h in _SENSITIVE_HINTS):
            sig.matched.append("sensitive_bucket_exfil")
            sig.weight += 40

    # Sigma-style detection rules (DE1/DE3) augment the signal.
    try:
        from sentinel.detection.rules import get_engine

        for rule in get_engine().match(alert):
            sig.rules.append(rule.id)
            if rule.indicator and rule.indicator not in sig.matched:
                sig.matched.append(rule.indicator)
            if rule.mitre and rule.mitre not in sig.techniques:
                sig.techniques.append(rule.mitre)
            sig.weight += rule.weight
            if rule.is_threat:
                sig.threat_flag = True
    except Exception as exc:  # rules are augmentation; never block triage
        log.warning("rules.match_failed", error=str(exc))

    # Obvious-noise classification (only when no threat indicator matched and the
    # source IP isn't suspicious). Low/info telemetry is auto-closable noise even
    # if it nominally maps to a technique (e.g. a benign AssumeRole read).
    if not sig.threat and not suspicious_ip:
        ev = et.split(":")[-1]
        ro = bool(alert.raw.get("readOnly")) if isinstance(alert.raw, dict) else False
        if alert.severity_hint in ("info", "low"):
            sig.matched.append("benign_pattern")
        elif src == "aws_cloudtrail" and (ro or ev.startswith(("Describe", "List", "Get"))):
            sig.matched.append("benign_pattern")

    return sig
