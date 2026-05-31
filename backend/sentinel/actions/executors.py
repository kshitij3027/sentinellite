"""Typed action executors (R8). Dry-run by default: log the call and return a
fake success. A single env flag (ACTION_DRY_RUN, per-action override) flips an
executor to live mode — which is intentionally unconfigured in the MVP so the
demo can never touch a real account."""

from __future__ import annotations

from sentinel.config import settings
from sentinel.logging import get_logger

log = get_logger("executor")

# What a *live* executor would do, stated for the dry-run log line.
_LIVE_INTENT = {
    "quarantine_package": "remove the package from the registry/lockfile and pin a safe version",
    "block_ip": "add a deny rule for the CIDR at the firewall/WAF",
    "revoke_session": "terminate the user's active sessions (Okta/IdP)",
    "disable_oauth_app": "disable the OAuth application grant",
    "isolate_workload": "apply a deny-all network policy to the workload",
    "revoke_aws_keys": "deactivate and delete the IAM access keys",
    "delete_iam_user": "delete the IAM user",
}


async def execute_action(action) -> dict:
    """Execute one action. `action` is an ORM Action. Returns a result dict."""
    dry = action.dry_run if action.dry_run is not None else settings.action_dry_run
    intent = _LIVE_INTENT.get(action.type, "perform the response")
    if dry:
        log.info("action.dry_run", type=action.type, params=action.params, intent=intent)
        return {
            "ok": True,
            "dry_run": True,
            "message": f"[DRY-RUN] would {intent} :: {action.type}({action.params})",
        }
    # Live mode is deliberately not wired to any real account in the MVP.
    log.warning("action.live_not_configured", type=action.type)
    return {
        "ok": False,
        "dry_run": False,
        "message": f"live executor for '{action.type}' is not configured (set sandbox creds to enable)",
    }
