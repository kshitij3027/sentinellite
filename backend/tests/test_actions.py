"""R7/R8 deterministic core: action recommendation, the irreversible blocklist,
and dry-run executors (no DB/LLM)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinel.actions.executors import execute_action
from sentinel.actions.generator import _aws_user, _cidr24, recommend_actions
from sentinel.actions.registry import IRREVERSIBLE, REGISTRY, is_irreversible
from sentinel.db.models import Action, Alert

T0 = datetime(2026, 5, 30, 14, 0, 0, tzinfo=timezone.utc)


def _alert(off, source, et, **kw) -> Alert:
    return Alert(id=f"alt_{off}", tenant_id="t", source=source, source_event_type=et,
                 ts=T0 + timedelta(seconds=off), severity_hint="high", raw=kw.pop("raw", {}), **kw)


def test_registry_and_blocklist():
    for t in ("quarantine_package", "block_ip", "revoke_session", "revoke_aws_keys"):
        assert t in REGISTRY
    assert "revoke_aws_keys" in IRREVERSIBLE
    assert "delete_iam_user" in IRREVERSIBLE
    assert not is_irreversible("block_ip")
    assert is_irreversible("revoke_aws_keys")


def test_cidr_and_user_helpers():
    assert _cidr24("185.220.101.45") == "185.220.101.0/24"
    a = _alert(0, "aws_cloudtrail", "iam:CreateAccessKey", raw={"requestParameters": {"userName": "svc-legacy"}})
    assert _aws_user(a) == "svc-legacy"
    a2 = _alert(0, "aws_cloudtrail", "sts:AssumeRole", actor_identity="arn:aws:iam::1:user/ci-svc")
    assert _aws_user(a2) == "ci-svc"


def test_recommend_actions_for_teampcp():
    members = [
        _alert(28, "github", "push", package="lodash@4.17.15", repository="teampcp/api"),
        _alert(70, "aws_cloudtrail", "sts:AssumeRole", actor_identity="arn:aws:iam::1:user/ci-svc", source_ip="185.220.101.45", cloud_resource="arn:aws:iam::1:role/prod"),
        _alert(104, "aws_cloudtrail", "iam:CreateAccessKey", source_ip="185.220.101.45", raw={"requestParameters": {"userName": "svc-legacy"}}),
        _alert(33, "falco", "Terminal shell in container", process="sh -c x", asset="ci-runner-12"),
    ]
    recs = recommend_actions(members)
    types = [r[0] for r in recs]
    assert "quarantine_package" in types
    assert "block_ip" in types
    assert "revoke_aws_keys" in types
    assert len(recs) >= 3  # SC5
    # block_ip deduped to a single /24 despite two Tor-IP alerts
    assert types.count("block_ip") == 1
    # pre-filled params present
    qp = next(p for t, p, _ in recs if t == "quarantine_package")
    assert qp == {"name": "lodash", "version": "4.17.15"}


async def test_executor_dry_run():
    a = Action(id="act_x", investigation_id="i", tenant_id="t", type="block_ip",
               params={"cidr": "185.220.101.0/24"}, dry_run=True)
    res = await execute_action(a)
    assert res["ok"] is True
    assert res["dry_run"] is True
    assert "DRY-RUN" in res["message"]
