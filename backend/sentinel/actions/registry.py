"""Response-action type registry + the two-tier blocklist (R7).

Irreversible/destructive action types always require a SECOND confirmation
before they execute (borrowed from the Codagent danger-list pattern)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionType:
    type: str
    title: str
    irreversible: bool  # True -> two-tier confirm required
    params: tuple[str, ...]


REGISTRY: dict[str, ActionType] = {
    "quarantine_package": ActionType("quarantine_package", "Quarantine compromised package", False, ("name", "version")),
    "block_ip": ActionType("block_ip", "Block source IP / CIDR at the edge", False, ("cidr",)),
    "revoke_session": ActionType("revoke_session", "Revoke active user session", False, ("user",)),
    "disable_oauth_app": ActionType("disable_oauth_app", "Disable OAuth application", False, ("app_id",)),
    "isolate_workload": ActionType("isolate_workload", "Network-isolate the workload/runner", False, ("workload",)),
    # Irreversible — deleting/rotating credentials cannot be undone.
    "revoke_aws_keys": ActionType("revoke_aws_keys", "Revoke & delete AWS access keys", True, ("user",)),
    "delete_iam_user": ActionType("delete_iam_user", "Delete IAM user", True, ("user",)),
}

IRREVERSIBLE: frozenset[str] = frozenset(t for t, a in REGISTRY.items() if a.irreversible)


def is_known(action_type: str) -> bool:
    return action_type in REGISTRY


def is_irreversible(action_type: str) -> bool:
    return action_type in IRREVERSIBLE
