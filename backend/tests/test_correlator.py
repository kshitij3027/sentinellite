"""R6: kill-chain assembly from member alerts (pure, no LLM/DB)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinel.agents.correlator import _aggregate_scores, build_kill_chain
from sentinel.db.models import Alert, TriageResult

T0 = datetime(2026, 5, 30, 14, 0, 0, tzinfo=timezone.utc)


def _alert(off, source, et, **kw) -> Alert:
    return Alert(
        id=f"alt_{off}", tenant_id="t", source=source, source_event_type=et,
        ts=T0 + timedelta(seconds=off), t_offset_s=off, severity_hint="high", raw={}, **kw,
    )


def _teampcp_members() -> list[Alert]:
    return [
        _alert(28, "github", "push", package="lodash@4.17.15", repository="teampcp/api"),
        _alert(33, "falco", "Terminal shell in container", process="sh -c postinstall", asset="ci-runner-12"),
        _alert(38, "falco", "Find AWS Credentials", process="grep -r AKIA /root/.aws/credentials", asset="ci-runner-12"),
        _alert(70, "aws_cloudtrail", "sts:AssumeRole", actor_identity="arn:aws:iam::1:user/svc", source_ip="185.220.101.45", cloud_resource="arn:aws:iam::1:role/prod"),
        _alert(104, "aws_cloudtrail", "iam:CreateAccessKey", actor_identity="arn:aws:iam::1:user/svc", source_ip="185.220.101.45", cloud_resource="svc-legacy"),
        _alert(128, "aws_cloudtrail", "s3:GetObject", source_ip="185.220.101.45", cloud_resource="arn:aws:s3:::teampcp-customer-pii/dump"),
    ]


def test_kill_chain_has_required_stages():
    steps = build_kill_chain(_teampcp_members())
    techniques = [s["mitre"] for s in steps]
    # SC4: >=4 stages, each with a valid MITRE id + a graph (entity) citation.
    assert len(steps) >= 4
    for required in ("T1195.002", "T1059.004", "T1552.001", "T1078.004", "T1098.001", "T1530"):
        assert required in techniques
    assert all(s["mitre_name"] and s["stage"] for s in steps)
    assert all(s["evidence"] for s in steps)


def test_kill_chain_is_time_ordered():
    steps = build_kill_chain(_teampcp_members())
    offsets = [s["t_offset_s"] for s in steps]
    assert offsets == sorted(offsets)
    assert steps[0]["stage"] == "Initial Access"  # T1195.002 at t+28 first


def test_kill_chain_empty():
    assert build_kill_chain([]) == []


def test_aggregate_scores_takes_max():
    rows = [
        TriageResult(id="t1", alert_id="a", tenant_id="t", severity=40, confidence=80, priority=50, severity_label="medium", decision="escalate"),
        TriageResult(id="t2", alert_id="b", tenant_id="t", severity=95, confidence=90, priority=92, severity_label="critical", decision="escalate"),
    ]
    assert _aggregate_scores(rows) == {"severity": 95, "confidence": 90, "priority": 92}
    assert _aggregate_scores([]) == {"severity": 0, "confidence": 0, "priority": 0}
